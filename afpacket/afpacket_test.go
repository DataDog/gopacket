// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux

package afpacket

import (
	"reflect"
	"testing"
	"time"
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
