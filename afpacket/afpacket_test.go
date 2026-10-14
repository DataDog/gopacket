// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux

package afpacket

import (
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"
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
