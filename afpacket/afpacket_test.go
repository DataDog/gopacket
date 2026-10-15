// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux

package afpacket

import (
	"bytes"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestParseOptions(t *testing.T) {
	wanted1 := defaultOpts
	wanted1.frameSize = 1 << 10
	wanted1.framesPerBlock = wanted1.blockSize / wanted1.frameSize
	for i, test := range []struct {
		opts []Option
		want options
		err  bool
	}{
		{opts: []Option{OptBlockSize(2)}, err: true},
		{opts: []Option{OptFrameSize(333)}, err: true},
		{opts: []Option{OptTPacketVersion(-3)}, err: true},
		{opts: []Option{OptTPacketVersion(5)}, err: true},
		{opts: []Option{OptBlockTimeout(1 * time.Nanosecond)}, err: true},
		{opts: []Option{OptSocketType(0)}, err: true},
		{opts: []Option{OptFrameSize(1 << 10)}, want: wanted1},
	} {
		got, err := parseOptions(test.opts...)
		t.Logf("got: %#v\nerr: %v", got, err)
		if test.err && err == nil || !test.err && err != nil {
			t.Errorf("%d error mismatch, want error? %v.  error: %v", i, test.err, err)
		}
		if !test.err && !reflect.DeepEqual(test.want, got) {
			t.Errorf("%d opts mismatch, want\n%#v", i, test.want)
		}
	}
}

// buildV3Block returns a synthetic TPacket3 block with its block header
// fields filled in and a first packet header placed at firstOffset. If the
// first-packet offset would fall outside the block, no packet header is
// written (that is the corrupted-header case under test).
func buildV3Block(blockSize, firstOffset uint32) (block []byte, bh *TPacketHdrV1, pkt *TPacket3Hdr) {
	block = make([]byte, blockSize)
	bd := (*TPacketBlockDesc)(unsafe.Pointer(&block[0]))
	bh = (*TPacketHdrV1)(unsafe.Pointer(&bd.Hdr[0]))
	bh.Num_pkts = 1
	bh.Offset_to_first_pkt = firstOffset
	if uint64(firstOffset)+SizeOfTPacket3Hdr <= uint64(blockSize) {
		pkt = (*TPacket3Hdr)(unsafe.Pointer(&block[firstOffset]))
	}
	return
}

// TPacket3 packs packets sequentially into blocks and does not truncate them
// to the frame size: a packet whose data extends past frameSize but stays
// within the block is valid and must be returned (regression test for the
// bounds check that compared Mac+Snaplen against frameSize).
func TestV3GetDataPacketLargerThanFrameSize(t *testing.T) {
	const (
		frameSize   = uint32(256)
		blockSize   = uint32(4096)
		firstOffset = uint32(64)
	)
	opts := defaultOpts
	opts.frameSize = frameSize
	opts.blockSize = blockSize

	block, _, pkt := buildV3Block(blockSize, firstOffset)
	pkt.Mac = 128
	pkt.Snaplen = 1000 // > frameSize, but well within the block
	w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)

	data, err := w.getData(&opts)
	if err != nil {
		t.Fatalf("unexpected error reading V3 packet larger than frame size: %v", err)
	}
	if len(data) != 1000 {
		t.Fatalf("expected 1000 bytes of packet data, got %d", len(data))
	}
}

func TestV3GetDataRejectsOutOfBlockData(t *testing.T) {
	const (
		blockSize   = uint32(4096)
		firstOffset = uint32(64)
	)
	opts := defaultOpts
	opts.frameSize = 256
	opts.blockSize = blockSize

	for _, test := range []struct {
		mac     uint16
		snaplen uint32
	}{
		{mac: 128, snaplen: 4000},  // data runs past the end of the block
		{mac: 60000, snaplen: 100}, // mac offset alone points past the block
	} {
		block, _, pkt := buildV3Block(blockSize, firstOffset)
		pkt.Mac = test.mac
		pkt.Snaplen = test.snaplen
		w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)

		if _, err := w.getData(&opts); !errors.Is(err, ErrCorruptedPacket) {
			t.Fatalf("mac=%d snaplen=%d: expected ErrCorruptedPacket, got %v", test.mac, test.snaplen, err)
		}
	}
}

// A corrupted tp_offset_to_first_pkt pointing outside the block must not
// take the reader out of bounds; initV3Wrapper clamps it to the block start
// and getData rejects the garbage read there.
func TestV3WrapperClampsInvalidFirstPacketOffset(t *testing.T) {
	const blockSize = uint32(4096)
	// Fill the block with garbage so the clamped header reads bogus values.
	block := make([]byte, blockSize)
	for i := range block {
		block[i] = 0xff
	}
	bd := (*TPacketBlockDesc)(unsafe.Pointer(&block[0]))
	bh := (*TPacketHdrV1)(unsafe.Pointer(&bd.Hdr[0]))
	bh.Offset_to_first_pkt = 0xffffff00 // far outside the block

	w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)
	if _, err := w.getData(&defaultOpts); !errors.Is(err, ErrCorruptedPacket) {
		t.Fatalf("expected ErrCorruptedPacket, got %v", err)
	}
}

// The packet walk must stop at the end of the block: a corrupted
// tp_next_offset must not advance the reader outside the ring (the crash the
// original sanity check was written to prevent).
func TestV3NextStaysWithinBlock(t *testing.T) {
	const (
		blockSize   = uint32(4096)
		firstOffset = uint32(64)
	)
	block := make([]byte, blockSize)
	bd := (*TPacketBlockDesc)(unsafe.Pointer(&block[0]))
	bh := (*TPacketHdrV1)(unsafe.Pointer(&bd.Hdr[0]))
	bh.Num_pkts = 3
	bh.Offset_to_first_pkt = firstOffset
	p1 := (*TPacket3Hdr)(unsafe.Pointer(&block[firstOffset]))
	p1.Next_offset = 1024 // second packet lands at offset 1088
	p2 := (*TPacket3Hdr)(unsafe.Pointer(&block[firstOffset+1024]))
	p2.Next_offset = 8192 // would leave the block: the walk must stop
	p2.Mac = 128
	p2.Snaplen = 16

	w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)
	if !w.next() {
		t.Fatal("expected next() to advance to the second packet")
	}
	if _, err := w.getData(&defaultOpts); err != nil {
		t.Fatalf("unexpected error reading second packet: %v", err)
	}
	if w.next() {
		t.Fatal("expected next() to refuse advancing past the block")
	}
}

// publishV3Block fills a zeroed block the way the kernel opens a TPACKET_V3
// block: it writes the block header, the first packet header and the packet
// data, and only then atomically publishes the block to userspace by setting
// block_status to TP_STATUS_USER. Everything written before the status store
// is guaranteed visible to a reader that observes TP_STATUS_USER.
func publishV3Block(block []byte, blockSize, firstOffset uint32, payload []byte) (*TPacketHdrV1, *TPacket3Hdr) {
	bd := (*TPacketBlockDesc)(unsafe.Pointer(&block[0]))
	bh := (*TPacketHdrV1)(unsafe.Pointer(&bd.Hdr[0]))
	bh.Num_pkts = 1
	bh.Offset_to_first_pkt = firstOffset
	bh.Blk_len = blockSize
	bh.Seq_num = 1

	// tp_mac = TPACKET_ALIGN(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll)
	macOffset := uint32(tpAlign(SizeOfTPacket3Hdr) + 20)
	pkt := (*TPacket3Hdr)(unsafe.Pointer(&block[firstOffset]))
	pkt.Snaplen = uint32(len(payload))
	pkt.Len = uint32(len(payload))
	pkt.Status = unix.TP_STATUS_USER
	pkt.Mac = uint16(macOffset)
	copy(block[firstOffset+macOffset:], payload)

	// The kernel publishes the block only after everything above is written.
	atomic.StoreUint32(&bh.Block_status, unix.TP_STATUS_USER)
	return bh, pkt
}

// TestV3RaceHeaderReadBeforeHandover simulates the TPACKET_V3 handover race
// (see ~/dd/experimental/users/usama.saqib/afpacket-v3-race-repro/report.md):
// the reader initializes the v3 wrapper — reading tp_offset_to_first_pkt —
// while the block header is still zero, the kernel then writes the block
// header and first packet and publishes the block (TP_STATUS_USER), and only
// then does the reader proceed to read packet data through the wrapper.
//
// This is the exact ordering ZeroCopyReadPacketData produces: getTPacketHeader()
// runs before pollForFirstPacket() blocks. Once the block has been handed over,
// the reader must return the packet the kernel actually wrote; a wrapper that
// read tp_offset_to_first_pkt before the handover instead reads the block
// header itself as a packet header, returning garbage (or a bogus
// ErrCorruptedPacket) for a perfectly valid block.
//
// When the fix defers reading tp_offset_to_first_pkt until after
// pollForFirstPacket() succeeds (the reader must re-derive the first-packet
// pointer from the now-valid block header at that point), this test should
// pass with no other change.
func TestV3RaceHeaderReadBeforeHandover(t *testing.T) {
	const (
		blockSize   = uint32(4096)
		firstOffset = uint32(48) // typical: block header is 48 bytes
	)
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	// A fresh ring: the block header is all zeros until the kernel opens it.
	block := make([]byte, blockSize)

	// Reader step 1: ZeroCopyReadPacketData -> getTPacketHeader ->
	// initV3Wrapper, which reads tp_offset_to_first_pkt. The kernel has not
	// written this block yet, so the field reads as 0.
	w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)

	// Kernel steps: open the block (header, first packet, data), then publish
	// it to userspace, exactly as prb_open_block/prb_close_block would.
	publishV3Block(block, blockSize, firstOffset, payload)

	// Reader step 2: pollForFirstPacket sees TP_STATUS_USER and the reader
	// proceeds to read packet data through the wrapper it built in step 1.
	if w.getStatus()&unix.TP_STATUS_USER == 0 {
		t.Fatal("block was not published to userspace")
	}

	data, err := w.getData(&defaultOpts)
	if err != nil {
		t.Fatalf("valid published block rejected as corrupted: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("reader returned stale block-header data (len %d, bytes % x) instead of the published packet (len %d)", len(data), data, len(payload))
	}
	if got := w.getLength(); got != len(payload) {
		t.Fatalf("packet length: got %d, want %d", got, len(payload))
	}
}

// TestV3WrapperReadsBlockAfterHandover is the control case for the race test
// above: the same block contents, but the wrapper is initialized after the
// kernel published the block, which is what the kernel contract requires
// (docs.kernel.org packet_mmap, "AF_PACKET TPACKET_V3 example": the block
// header is only read once block_status is TP_STATUS_USER). It must pass on
// any implementation, and proves the synthetic block built by publishV3Block
// is valid — isolating the race test failure to the premature header read,
// not to bad test data.
func TestV3WrapperReadsBlockAfterHandover(t *testing.T) {
	const (
		blockSize   = uint32(4096)
		firstOffset = uint32(48)
	)
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	block := make([]byte, blockSize)
	publishV3Block(block, blockSize, firstOffset, payload)

	w := initV3Wrapper(unsafe.Pointer(&block[0]), blockSize)
	if w.getStatus()&unix.TP_STATUS_USER == 0 {
		t.Fatal("block was not published to userspace")
	}

	data, err := w.getData(&defaultOpts)
	if err != nil {
		t.Fatalf("unexpected error reading published block: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("reader returned wrong data (len %d), want len %d", len(data), len(payload))
	}
	if got := w.getLength(); got != len(payload) {
		t.Fatalf("packet length: got %d, want %d", got, len(payload))
	}
}
