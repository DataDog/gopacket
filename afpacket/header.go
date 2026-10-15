// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux

package afpacket

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Our model of handling all TPacket versions is a little hacky, to say the
// least.  We use the header interface to handle interactions with the
// tpacket1/tpacket2 packet header AND the tpacket3 block header.  The big
// difference is that tpacket3's block header implements the next() call to get
// the next packet within the block, while v1/v2 just always return false.

type header interface {
	// getStatus returns the TPacket status of the current header.
	getStatus() uint64
	// clearStatus clears the status of the current header, releasing its
	// underlying data back to the kernel for future use with new packets.
	// Using the header after calling clearStatus is an error.  clearStatus
	// should only be called after next() returns false.
	clearStatus()
	// getTime returns the timestamp for the current packet pointed to by
	// the header.
	getTime() time.Time
	// getData returns the packet data pointed to by the current header.
	getData(opts *options) ([]byte, error)
	// getLength returns the total length of the packet.
	getLength() int
	// getIfaceIndex returns the index of the network interface
	// where the packet was seen. The index can later be translated to a name.
	getIfaceIndex() int
	// getPktType returns the packet type
	getPktType() uint8
	// getVLAN returns the VLAN of a packet if it was provided out-of-band
	getVLAN() int
	// next moves this header to point to the next packet it contains,
	// returning true on success (in which case getTime and getData will
	// return values for the new packet) or false if there are no more
	// packets (in which case clearStatus should be called).
	next() bool
}

const tpacketAlignment = uint(unix.TPACKET_ALIGNMENT)

func tpAlign(x int) int {
	return int((uint(x) + tpacketAlignment - 1) &^ (tpacketAlignment - 1))
}

func insertVlanHeader(data []byte, vlanTCI int, opts *options) []byte {
	if vlanTCI <= 0 || !opts.addVLANHeader {
		return data
	}
	eth := make([]byte, 0, len(data)+VLAN_HLEN)
	eth = append(eth, data[0:ETH_ALEN*2]...)
	// unix.ETH_P_8021Q = 0x8100
	eth = append(eth, []byte{0x81, 0, byte((vlanTCI >> 8) & 0xff), byte(vlanTCI & 0xff)}...)
	return append(eth, data[ETH_ALEN*2:]...)
}

func (h *TPacketHdr) getVLAN() int {
	return -1
}
func (h *TPacketHdr) getStatus() uint64 {
	return atomic.LoadUint64(&h.Status)
}
func (h *TPacketHdr) clearStatus() {
	atomic.StoreUint64(&h.Status, unix.TP_STATUS_KERNEL)
}
func (h *TPacketHdr) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Usec)*1000)
}
func (h *TPacketHdr) getData(opts *options) ([]byte, error) {
	if uint32(h.Mac)+h.Snaplen > opts.frameSize {
		return nil, fmt.Errorf("%w: offset %d + caplen %d > frame len %d", ErrCorruptedPacket, h.Mac, h.Snaplen, opts.frameSize)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(h))+uintptr(h.Mac))), int(h.Snaplen)), nil
}
func (h *TPacketHdr) getLength() int {
	return int(h.Len)
}
func (h *TPacketHdr) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(SizeOfTPacketHdr))))
	return int(ll.Ifindex)
}
func (h *TPacketHdr) getPktType() uint8 {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(SizeOfTPacketHdr))))
	return ll.Pkttype
}
func (h *TPacketHdr) next() bool {
	return false
}

func (h *TPacket2Hdr) getVLAN() int {
	if h.getStatus()&unix.TP_STATUS_VLAN_VALID != 0 {
		return int(h.Vlan_tci & 0xfff)
	}
	return -1
}
func (h *TPacket2Hdr) getStatus() uint64 {
	return uint64(atomic.LoadUint32(&h.Status))
}
func (h *TPacket2Hdr) clearStatus() {
	atomic.StoreUint32(&h.Status, unix.TP_STATUS_KERNEL)
}
func (h *TPacket2Hdr) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Nsec))
}
func (h *TPacket2Hdr) getData(opts *options) ([]byte, error) {
	if uint32(h.Mac)+h.Snaplen > opts.frameSize {
		return nil, fmt.Errorf("%w: offset %d + caplen %d > frame len %d", ErrCorruptedPacket, h.Mac, h.Snaplen, opts.frameSize)
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(h))+uintptr(h.Mac))), int(h.Snaplen))
	return insertVlanHeader(data, h.getVLAN(), opts), nil
}
func (h *TPacket2Hdr) getLength() int {
	return int(h.Len)
}
func (h *TPacket2Hdr) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(SizeOfTPacket2Hdr))))
	return int(ll.Ifindex)
}
func (h *TPacket2Hdr) getPktType() uint8 {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(SizeOfTPacket2Hdr))))
	return ll.Pkttype
}
func (h *TPacket2Hdr) next() bool {
	return false
}

type v3wrapper struct {
	block     *TPacketBlockDesc
	blockhdr  *TPacketHdrV1
	packet    *TPacket3Hdr
	blockSize uint32
	used      uint32
}

// initV3Wrapper only locates the block. It must not read anything from the
// block other than its status: the rest of the block header is owned by the
// kernel until block_status has TP_STATUS_USER set. Call firstPacket() once the
// block has been handed over.
func initV3Wrapper(block unsafe.Pointer, blockSize uint32) (w v3wrapper) {
	w.block = (*TPacketBlockDesc)(block)
	w.blockhdr = (*TPacketHdrV1)(unsafe.Pointer(&w.block.Hdr[0]))
	w.blockSize = blockSize
	return
}

// firstPacket points the wrapper at the first packet of a block owned by
// userspace. The block header is fully written once block_status has
// TP_STATUS_USER, so tp_offset_to_first_pkt is safe to read here.
func (w *v3wrapper) firstPacket() {
	offset := w.blockhdr.Offset_to_first_pkt
	if uint64(offset)+SizeOfTPacket3Hdr > uint64(w.blockSize) {
		// The offset is corrupted and points outside the block. Fall back to
		// the block start so every read through w.packet stays in bounds;
		// getData rejects the resulting garbage as a corrupted packet.
		offset = 0
	}
	w.packet = (*TPacket3Hdr)(unsafe.Pointer(uintptr(unsafe.Pointer(w.block)) + uintptr(offset)))
	w.used = 0
}

func (w *v3wrapper) getVLAN() int {
	if w.packet.Status&unix.TP_STATUS_VLAN_VALID != 0 {
		return int(w.packet.Hv1.Vlan_tci & 0xfff)
	}
	return -1
}

func (w *v3wrapper) getStatus() uint64 {
	return uint64(atomic.LoadUint32(&w.blockhdr.Block_status))
}
func (w *v3wrapper) clearStatus() {
	atomic.StoreUint32(&w.blockhdr.Block_status, unix.TP_STATUS_KERNEL)
}
func (w *v3wrapper) getTime() time.Time {
	return time.Unix(int64(w.packet.Sec), int64(w.packet.Nsec))
}
func (w *v3wrapper) getData(opts *options) ([]byte, error) {
	// TPacket3 packs packets sequentially into blocks and tp_snaplen is the
	// real captured length: the kernel does not truncate packets to the frame
	// size, so the packet must be bounded against its block, not frameSize.
	pktOffset := uint64(uintptr(unsafe.Pointer(w.packet)) - uintptr(unsafe.Pointer(w.block)))
	if pktOffset+SizeOfTPacket3Hdr > uint64(w.blockSize) ||
		pktOffset+uint64(w.packet.Mac)+uint64(w.packet.Snaplen) > uint64(w.blockSize) {
		return nil, fmt.Errorf("%w: offset %d + caplen %d > block len %d", ErrCorruptedPacket, pktOffset+uint64(w.packet.Mac), w.packet.Snaplen, w.blockSize)
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(w.packet))+uintptr(w.packet.Mac))), int(w.packet.Snaplen))
	return insertVlanHeader(data, w.getVLAN(), opts), nil
}
func (w *v3wrapper) getLength() int {
	return int(w.packet.Len)
}
func (w *v3wrapper) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(w.packet)) + uintptr(tpAlign(SizeOfTPacket3Hdr))))
	return int(ll.Ifindex)
}
func (w *v3wrapper) getPktType() uint8 {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(w.packet)) + uintptr(tpAlign(SizeOfTPacket3Hdr))))
	return ll.Pkttype
}
func (w *v3wrapper) next() bool {
	w.used++
	if w.used >= w.blockhdr.Num_pkts {
		return false
	}

	// Bound the walk to the current block so a corrupted tp_next_offset can
	// never take the reader outside the ring.
	nextOffset := uint64(uintptr(unsafe.Pointer(w.packet))-uintptr(unsafe.Pointer(w.block))) + uint64(w.packet.Next_offset)
	if nextOffset+SizeOfTPacket3Hdr > uint64(w.blockSize) {
		return false
	}
	w.packet = (*TPacket3Hdr)(unsafe.Pointer(uintptr(unsafe.Pointer(w.block)) + uintptr(nextOffset)))
	return true
}
