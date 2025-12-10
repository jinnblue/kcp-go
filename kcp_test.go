// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

import (
	"container/heap"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/lossyconn"
)

const repeat = 16

func TestLossyConn1(t *testing.T) {
	t.Log("testing loss rate 10%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
	}

	server, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn2(t *testing.T) {
	t.Log("testing loss rate 20%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.2, 100)
	if err != nil {
		t.Fatal(err)
	}

	server, err := lossyconn.NewLossyConn(0.2, 100)
	if err != nil {
		t.Fatal(err)
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn3(t *testing.T) {
	t.Log("testing loss rate 30%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 1")
	client, err := lossyconn.NewLossyConn(0.3, 100)
	if err != nil {
		t.Fatal(err)
	}

	server, err := lossyconn.NewLossyConn(0.3, 100)
	if err != nil {
		t.Fatal(err)
	}
	testlink(t, client, server, 1, 10, 2, 1)
}

func TestLossyConn4(t *testing.T) {
	t.Log("testing loss rate 10%, rtt 200ms")
	t.Log("testing link with nodelay parameters:1 10 2 0")
	client, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
	}

	server, err := lossyconn.NewLossyConn(0.1, 100)
	if err != nil {
		t.Fatal(err)
	}
	testlink(t, client, server, 1, 10, 2, 0)
}

func testlink(t *testing.T, client *lossyconn.LossyConn, server *lossyconn.LossyConn, nodelay, interval, resend, nc int) {
	t.Log("testing with nodelay parameters:", nodelay, interval, resend, nc)
	listener, _ := ServeConn(nil, 0, 0, server)
	listener.SetDSCP(46)
	listener.SetReadBuffer(16 * 1024 * 1024)
	listener.SetWriteBuffer(16 * 1024 * 1024)

	echoServer := func(l *Listener) {
		for {
			conn, err := l.AcceptKCP()
			if err != nil {
				return
			}
			go func() {
				conn.SetWriteDelay(true)
				conn.SetNoDelay(nodelay, interval, resend, nc)
				conn.SetMtu(1200)
				conn.SetWindowSize(256, 256)
				conn.SetACKNoDelay(true)
				buf := make([]byte, 65536)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}
	go echoServer(listener)

	sess, _ := NewConn2(server.LocalAddr(), nil, 0, 0, client)
	sess.Connect()
	echoTester := func(s *UDPSession, raddr net.Addr) {
		s.SetNoDelay(nodelay, interval, resend, nc)
		buf := make([]byte, 64)
		var rtt time.Duration
		for i := 0; i < repeat; i++ {
			start := time.Now()
			s.Write(buf)
			io.ReadFull(s, buf)
			rtt += time.Since(start)
		}

		t.Log("client:", client)
		t.Log("server:", server)
		t.Log("avg rtt:", rtt/repeat)
		t.Logf("total time: %v for %v round trip:", rtt, repeat)
	}

	echoTester(sess, server.LocalAddr())
}

func BenchmarkFlush(b *testing.B) {
	kcp := NewKCP(1, func(buf []byte, size int) {})
	kcp.snd_buf = NewRingBuffer[segment](1024)
	for range kcp.snd_buf.MaxLen() {
		kcp.snd_buf.Push(segment{xmit: 1, resendts: currentMs() + 10000})
	}
	b.ResetTimer()
	b.ReportAllocs()
	var mu sync.Mutex
	for i := 0; i < b.N; i++ {
		mu.Lock()
		kcp.flush(IKCP_FLUSH_FULL)
		mu.Unlock()
	}
}

// segmentHeap is a min-heap of segments, used for receiving segments in order
type segmentHeap struct {
	segments []segment
	marks    map[uint32]struct{} // to avoid duplicates
}

func newSegmentHeap() *segmentHeap {
	h := &segmentHeap{
		marks: make(map[uint32]struct{}),
	}
	heap.Init(h)
	return h
}

func (h *segmentHeap) Len() int { return len(h.segments) }

func (h *segmentHeap) Less(i, j int) bool {
	return h.segments[i].sn < h.segments[j].sn
}

func (h *segmentHeap) Swap(i, j int) { h.segments[i], h.segments[j] = h.segments[j], h.segments[i] }
func (h *segmentHeap) Push(x any) {
	seg := x.(segment)
	h.segments = append(h.segments, seg)
	h.marks[seg.sn] = struct{}{}
}

func (h *segmentHeap) Pop() any {
	n := len(h.segments)
	x := h.segments[n-1]
	h.segments = h.segments[0 : n-1]
	delete(h.marks, x.sn)
	return x
}

func (h *segmentHeap) Has(sn uint32) bool {
	_, exists := h.marks[sn]
	return exists
}

// TestSegmentHeap tests the segmentHeap data structure
func TestSegmentHeap(t *testing.T) {
	h := newSegmentHeap()
	segments := []segment{
		{sn: 1, frg: 0},
		{sn: 2, frg: 1},
		{sn: 3, frg: 0},
		{sn: 4, frg: 2},
		{sn: 5, frg: 1},
		{sn: 6, frg: 0},
	}

	for _, seg := range segments {
		heap.Push(h, seg)
		t.Logf("pushed segment with seq %d", seg.sn)
	}

	if h.Len() != len(segments) {
		t.Errorf("expected length %d, got %d", len(segments), h.Len())
	}

	for i := 0; i < len(segments); i++ {
		if !h.Has(segments[i].sn) {
			t.Errorf("expected segment %d not in heap", segments[i].sn)
		}
		seg := heap.Pop(h).(segment)
		if seg.sn != segments[i].sn {
			t.Errorf("expected seq %d, got %d", segments[i].sn, seg.sn)
		}
	}
}

// TestMinHeap tests the minheap data structure
func TestMinHeap(t *testing.T) {
	h := newMinheap(0)
	segments := []segment{
		{sn: 1, frg: 0},
		{sn: 2, frg: 1},
		{sn: 3, frg: 0},
		{sn: 4, frg: 2},
		{sn: 5, frg: 1},
		{sn: 6, frg: 0},
	}

	for _, seg := range segments {
		if !h.Has(seg.sn) {
			h.Push(seg)
		}
		t.Logf("pushed segment with seq %d", seg.sn)
	}

	if h.Len() != len(segments) {
		t.Errorf("expected length %d, got %d", len(segments), h.Len())
	}

	for i := 0; i < len(segments); i++ {
		if !h.Has(segments[i].sn) {
			t.Errorf("expected segment %d not in heap", segments[i].sn)
		}
		seg := h.Pop()
		if seg.sn != segments[i].sn {
			t.Errorf("expected seq %d, got %d", segments[i].sn, seg.sn)
		}
	}
}

func genSegments(wnd int) []segment {
	segs := make([]segment, 0, wnd)
	for i := range wnd {
		segs = append(segs, segment{sn: uint32(i)})
	}
	return segs
}

func BenchmarkSegmentHeap(b *testing.B) {
	wnd := 1024
	orders := genSegments(wnd)

	shuffles := make([]segment, wnd)
	copy(shuffles, orders)
	rand.Shuffle(len(shuffles), func(i, j int) { shuffles[i], shuffles[j] = shuffles[j], shuffles[i] })

	var seg segment
	h := newSegmentHeap()
	for range b.N {
		for i := range wnd {
			if !h.Has(shuffles[i].sn) {
				heap.Push(h, shuffles[i])
			}
		}
		i := 0
		for h.Len() > 0 {
			seg = heap.Pop(h).(segment)
			if seg.sn != orders[i].sn {
				b.Errorf("expected seq %d, got %d", orders[i].sn, seg.sn)
			}
			i++
		}
	}
	b.Log(seg.sn)
}

func BenchmarkMinheap(b *testing.B) {
	wnd := 1024
	orders := genSegments(wnd)

	shuffles := make([]segment, wnd)
	copy(shuffles, orders)
	rand.Shuffle(len(shuffles), func(i, j int) { shuffles[i], shuffles[j] = shuffles[j], shuffles[i] })

	var seg segment
	h := newMinheap(0)
	for range b.N {
		for i := range wnd {
			if !h.Has(shuffles[i].sn) {
				h.Push(shuffles[i])
			}
		}
		i := 0
		for h.Len() > 0 {
			seg = h.Pop()
			if seg.sn != orders[i].sn {
				b.Errorf("expected seq %d, got %d", orders[i].sn, seg.sn)
			}
			i++
		}
	}
	b.Log(seg.sn)
}

// BenchmarkDebugLog test DebugLog cost time with build tags debug on/off
// trace log on:
//
//	go test -benchmem -run=^$ -bench ^BenchmarkDebugLog$ -tags debug
//
// trace log off:
//
//	go test -benchmem -run=^$ -bench ^BenchmarkDebugLog$
func BenchmarkDebugLog(b *testing.B) {
	kcp := &KCP{
		conv:    123,
		snd_wnd: 456,
	}
	kcp.log = slog.Debug

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// In release mode, this line of code will be completely 'erased' by the compiler,
		// as if it doesn't exist at all, and even the parameter's interface conversion will not occur.
		kcp.debugLog(IKCP_LOG_OUT_WASK, "conv", kcp.conv, "wnd", kcp.snd_wnd)
	}
}
