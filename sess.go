// The MIT License (MIT)
//
// # Copyright (c) 2015 xtaci
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

// [THE GENERALIZED DATA PIPELINE FOR KCP-GO]
//
// Outgoing Data Pipeline:                        Incoming Data Pipeline:
// Stream          (Input Data)                   Packet Network  (Network Interface Card)
//   |                                               |
//   v                                               v
// KCP Output      (Reliable Transport Layer)     Reader/Listener (Reception Queue)
//   |                                               |
//   v                                               v
// FEC Encoding    (Forward Error Correction)     Decryption      (Data Security)
//   |                                               |
//   v                                               v
// CRC32 Checksum  (Error Detection)              CRC32 Checksum  (Error Detection)
//   |                                               |
//   v                                               v
// Encryption      (Data Security)                FEC Decoding    (Forward Error Correction)
//   |                                               |
//   v                                               v
// TxQueue         (Transmission Queue)           KCP Input       (Reliable Transport Layer)
//   |                                               |
//   v                                               v
// Packet Network  (Network Transmission)         Stream          (Input Data)

package kcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
)

// header mirror + crypt + fec + kcp. mirror include channel + cookie + cmd.
// |   1B    |   4B   |   20B   | 8B  | 24B | 1B  |
// | channel | cookie | encrypt | fec | kcp | cmd |
const (
	// 1-bytes channel
	mirrorChanSize = 1

	// 4-bytes cookie
	mirrorCookieSize = 4

	// overall mirror header size
	mirrorHeadSize = mirrorChanSize + mirrorCookieSize

	// 1-bytes cmd
	mirrorCmdSize = 1

	// overall mirror packet size
	mirrorPacketSize = mirrorHeadSize + mirrorCmdSize

	// times of disconnect packet
	disconnectTimes = 5

	// 16-bytes nonce for each packet
	nonceSize = 16

	// 4-bytes packet checksum
	crcSize = 4

	// overall crypto header size
	cryptHeaderSize = nonceSize + crcSize

	// maximum packet size
	mtuLimit = 1500
	// minimum packet size
	mtuMinLimit = 50

	// accept backlog
	acceptBacklog = 128

	// dev backlog
	devBacklog = 2048

	// max latency for consecutive FEC encoding, in millisecond
	maxFECEncodeLatency = 500

	// max batch size
	maxBatchSize = 64
)

const (
	// offset of channel in mirror header
	channelOffset = 0
	// offset of cookie in mirror header
	cookieOffset = 1

	// offset of cmd in data
	cmdOffset = 0
)

const (
	// mirror channel
	channelReliable   = 1
	channelUnreliable = 2

	// mirror cmd
	cmdKcpOriginal          = 0
	cmdReliableHello        = 1
	cmdReliablePing         = 2
	cmdReliableData         = 3
	cmdUnreliableData       = 4
	cmdUnreliableDisconnect = 5

	// mirror session state
	stateConnected     = 0
	stateAuthenticated = 1
	stateDisconnected  = 2
)

var (
	errInvalidOperation = errors.New("invalid operation")
	errTimeout          = timeoutError{}
	errNotOwner         = errors.New("not the owner of this connection")
	errDeadLink         = errors.New("dead link")
	errInvalidState     = errors.New("invalid state")
)

// timeoutError implements net.Error
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type (
	// UDPSession defines a KCP session implemented by UDP
	UDPSession struct {
		conn    net.PacketConn // the underlying packet connection
		ownConn bool           // true if we created conn internally, false if provided by caller
		kcp     *KCP           // KCP ARQ protocol
		l       *Listener      // pointing to the Listener object if it's been accepted by a Listener
		block   BlockCrypt     // block encryption object

		state  atomic.Uint32 // session state
		cookie atomic.Uint32 // cookie for verification

		// kcp receiving is based on packets
		// recvbufs  turns packets into stream
		recvbufs [][]byte
		bufptr   []byte
		bufidx   int

		// FEC codec
		fecDecoder *fecDecoder
		fecEncoder *fecEncoder

		// settings
		remote     net.Addr     // remote peer address
		rd         atomic.Value // read deadline
		wd         atomic.Value // write deadline
		headerSize int          // the header size additional to a KCP frame
		ackNoDelay bool         // send ack immediately for each incoming packet(testing purpose)
		writeDelay bool         // delay kcp.flush() for Write() for bulk transfer
		dup        int          // duplicate udp packets(testing purpose)

		// notifications
		connectOnce  sync.Once
		die          chan struct{} // notify current session has Closed
		closed       atomic.Int32
		chReadEvent  chan struct{} // notify Read() can be called without blocking
		chWriteEvent chan struct{} // notify Write() can be called without blocking

		// socket error handling
		socketReadError      atomic.Value
		socketWriteError     atomic.Value
		chSocketReadError    chan struct{}
		chSocketWriteError   chan struct{}
		socketReadErrorOnce  sync.Once
		socketWriteErrorOnce sync.Once

		// packets waiting to be sent on wire
		chPostProcessing chan []byte

		// platform-dependent optimizations
		platform platform

		// rate limiter (bytes per second)
		rateLimiter atomic.Value

		handler UDPSessionHandler

		udpRecvQueue *RingBuffer[datagram]

		mu sync.Mutex
	}

	setReadBuffer interface {
		SetReadBuffer(bytes int) error
	}

	setWriteBuffer interface {
		SetWriteBuffer(bytes int) error
	}

	setDSCP interface {
		SetDSCP(int) error
	}
)

type UDPSessionHandler interface {
	OnConnected(sess *UDPSession)
	OnDisconnected(sess *UDPSession, ct ClosedType)
	OnPing(sess *UDPSession, rtt int32)
}

// newUDPSession create a new udp session for client or server
func newUDPSession(conv uint32, dataShards, parityShards int, l *Listener, conn net.PacketConn, ownConn bool, remote net.Addr, block BlockCrypt) *UDPSession {
	sess := new(UDPSession)
	sess.die = make(chan struct{})
	sess.chReadEvent = make(chan struct{}, 1)
	sess.chWriteEvent = make(chan struct{}, 1)
	sess.chSocketReadError = make(chan struct{})
	sess.chSocketWriteError = make(chan struct{})
	sess.chPostProcessing = make(chan []byte, devBacklog)
	sess.remote = remote
	sess.conn = conn
	sess.ownConn = ownConn
	sess.l = l
	sess.block = block
	sess.recvbufs = make([][]byte, 0, IKCP_FRG_MAX)
	sess.udpRecvQueue = NewRingBuffer[datagram](disconnectTimes)

	sess.initPlatform()

	// calculate additional header size introduced by encryption
	switch block := sess.block.(type) {
	case nil:
	case *aeadCrypt:
		sess.headerSize = block.NonceSize()
	default:
		sess.headerSize = cryptHeaderSize
	}

	// FEC codec initialization
	sess.fecDecoder = newFECDecoder(dataShards, parityShards)
	sess.fecEncoder = newFECEncoder(dataShards, parityShards, sess.headerSize)

	// calculate additional header size introduced by FEC
	if sess.fecEncoder != nil {
		sess.headerSize += fecHeaderSizePlus2
	}
	sess.headerSize += mirrorHeadSize

	sess.kcp = NewKCP(conv, func(buf []byte, size int) {
		// A basic check for the minimum packet size
		if size >= IKCP_OVERHEAD {
			// make a copy
			bts := defaultBufferPool.Get()[:size+sess.headerSize]
			// set channel and cookie
			bts[channelOffset] = channelReliable
			binary.LittleEndian.PutUint32(bts[cookieOffset:mirrorHeadSize], sess.cookie.Load())
			// copy the data to a new buffer, and reserve header space
			copy(bts[sess.headerSize:], buf)

			// delivery to post processing (non-blocking to avoid deadlock under lock)
			select {
			case sess.chPostProcessing <- bts:
			case <-sess.die:
				return
			default:
				// drop and recycle to avoid blocking; KCP will retransmit if needed
				defaultBufferPool.Put(bts)
			}
		}
	})

	// create post-processing goroutine
	go sess.postProcess()

	// start per-session updater
	SystemTimedSched().Put(sess.update, time.Now())

	if sess.l == nil { // it's a client connection
		go sess.readLoop()
		atomic.AddUint64(&DefaultSnmp.ActiveOpens, 1)
	} else {
		atomic.AddUint64(&DefaultSnmp.PassiveOpens, 1)
	}

	currestab := atomic.AddUint64(&DefaultSnmp.CurrEstab, 1)
	maxconn := atomic.LoadUint64(&DefaultSnmp.MaxConn)
	if currestab > maxconn {
		atomic.CompareAndSwapUint64(&DefaultSnmp.MaxConn, maxconn, currestab)
	}

	return sess
}

func (s *UDPSession) Connect(data ...byte) (err error) {
	var need bool
	s.connectOnce.Do(func() {
		need = true
	})

	if !need {
		return nil
	}

	s.mu.Lock()
	if s.l != nil {
		s.mu.Unlock()
		return nil
	}
	s.sendHello(data)
	s.mu.Unlock()

	// wait for server hello response
	_, err = s.Read(nil)
	return err
}

func (s *UDPSession) readFromBuf(b []byte, data []byte) (n int) {
	for len(data) > 0 {
		x := copy(b, data)
		b = b[x:]
		n += x
		if x < len(data) {
			s.bufptr = data[x:]
			return n
		}
		defaultBufferPool.Put(s.recvbufs[s.bufidx])
		s.bufidx++
		if s.bufidx < len(s.recvbufs) {
			data = s.recvbufs[s.bufidx]
			s.recvbufs[s.bufidx] = nil
		} else {
			return n
		}
	}
	return n
}

// PeekUdpMessageSize checks the size of next message in the udp recv queue
func (s *UDPSession) PeekUdpMessageSize() (size int) {
	d, ok := s.udpRecvQueue.Peek()
	if !ok {
		return -1
	}
	return len(d.data)
}

func (s *UDPSession) shiftRecvUdp(buffers [][]byte) (n int) {
	d, ok := s.udpRecvQueue.Pop()
	if !ok {
		return 0
	}

	n += len(d.data)
	buffers[0] = d.data
	d.data = nil
	return n
}

// Read implements net.Conn
func (s *UDPSession) Read(b []byte) (n int, err error) {
RESET_TIMER:
	var timeout *time.Timer
	// deadline for current reading operation
	var c <-chan time.Time
	if trd, ok := s.rd.Load().(time.Time); ok && !trd.IsZero() {
		timeout = time.NewTimer(time.Until(trd))
		c = timeout.C
		defer timeout.Stop()
	}

	for {
		s.mu.Lock()
		// bufidx points to the current index of recvbufs,
		// if previous 'b' is insufficient to accommodate the data, the
		// remaining data will be stored in bufptr for next read.
		if s.bufidx < len(s.recvbufs) {
			n = s.readFromBuf(b, s.bufptr)
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		// first check if we have data in kcp
		if frg, size := s.kcp.PeekMessage(); size > 0 { // peek data size from kcp
			s.bufidx = 0
			s.recvbufs = s.recvbufs[:frg]
			s.kcp.ShiftRecv(s.recvbufs) // read data to recvbufs first
			data := s.mirrorReliableInput(s.recvbufs[0])
			if len(data) > 0 {
				n = s.readFromBuf(b, data)
				s.mu.Unlock()
				atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
				return n, nil
			} else {
				s.bufidx++ // increment bufidx to skip the empty buffer
				defaultBufferPool.Put(s.recvbufs[0])
				if b == nil {
					if s.kcp.PeekSize() > 0 {
						s.notifyReadEvent()
					}
					s.mu.Unlock()
					return 0, nil
				}
			}
		}

		// second check if we have any data in udp
		if size := s.PeekUdpMessageSize(); size > 0 {
			s.bufidx = 0
			s.recvbufs = s.recvbufs[:1]
			s.shiftRecvUdp(s.recvbufs)
			data := s.mirrorUnreliableInput(s.recvbufs[0])
			if len(data) > 0 {
				n = s.readFromBuf(b, data)
				s.mu.Unlock()
				atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
				return n, nil
			} else {
				s.bufidx++ // increment bufidx to skip the empty buffer
				defaultBufferPool.Put(s.recvbufs[0])
				if b == nil {
					if s.kcp.PeekSize() > 0 {
						s.notifyReadEvent()
					}
					s.mu.Unlock()
					return 0, nil
				}
			}
		}

		s.mu.Unlock()

		// if it runs here, that means we have to block the call, and wait until the next data packet arrives.
		select {
		case <-s.chReadEvent:
			if timeout != nil {
				timeout.Stop()
				goto RESET_TIMER
			}
		case <-c:
			return 0, errors.WithStack(errTimeout)
		case <-s.chSocketReadError:
			return 0, s.socketReadError.Load().(error)
		case <-s.die:
			if err = s.closeError(); errors.Is(err, net.ErrClosed) {
				err = io.EOF
			}
			return 0, err
		}
	}
}

// Write implements net.Conn
func (s *UDPSession) Write(b []byte) (n int, err error) { return s.WriteBuffers([][]byte{b}) }

// WriteBuffers write a vector of byte slices to the underlying connection
func (s *UDPSession) WriteBuffers(v [][]byte) (n int, err error) {
RESET_TIMER:
	var timeout *time.Timer
	var c <-chan time.Time
	if twd, ok := s.wd.Load().(time.Time); ok && !twd.IsZero() {
		timeout = time.NewTimer(time.Until(twd))
		c = timeout.C
		defer timeout.Stop()
	}

	for {
		// check for connection close and socket error
		select {
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.die:
			return 0, s.closeError()
		default:
			if s.state.Load() == stateConnected {
				<-s.chWriteEvent
				if timeout != nil {
					timeout.Stop()
				}
				goto RESET_TIMER
			}
		}

		s.mu.Lock()
		// make sure write do not overflow the max sliding window on both side
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			// transmit all data sequentially, make sure every packet size is within 'mss'
			for _, b := range v {
				s.kcp.Send(cmdReliableData, b)
				n += len(b)
			}
			s.kcp.debugLog(IKCP_LOG_WRITE, "conv", s.kcp.conv, "cookie", s.cookie.Load(), "datalen", n)

			waitsnd = s.kcp.WaitSnd()
			if waitsnd >= int(s.kcp.snd_wnd) || !s.writeDelay {
				// put the packets on wire immediately if the inflight window is full
				// or if we've specified write no delay(NO merging of outgoing bytes)
				// we don't have to wait until the periodical update() procedure uncorks.
				s.kcp.flush(IKCP_FLUSH_FULL)
			}
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}

		s.mu.Unlock()

		// if it runs here, that means we have to block the call, and wait until the
		// transmit buffer to become available again.
		select {
		case <-s.chWriteEvent:
			if timeout != nil {
				timeout.Stop()
				goto RESET_TIMER
			}
		case <-c:
			return 0, errors.WithStack(errTimeout)
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.die:
			return 0, s.closeError()
		}
	}
}

func (s *UDPSession) closeError() (err error) {
	ct := ClosedType(s.closed.Load())
	switch ct {
	case ClosedByDeadLink:
		return errDeadLink
	case ClosedByErrState:
		return errInvalidState
	default:
		return net.ErrClosed
	}
}

func (s *UDPSession) isClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

type ClosedType int32

const (
	ClosedByLocal ClosedType = iota + 1
	ClosedByErrState
	ClosedByDeadLink
	ClosedByRemote
)

func (s *UDPSession) Close() error {
	return s.closeWithType(ClosedByLocal, true)
}

// Close closes the connection.
func (s *UDPSession) closeWithType(ct ClosedType, needlock bool) (err error) {
	if !s.closed.CompareAndSwap(0, int32(ct)) {
		if err = s.closeError(); errors.Is(err, net.ErrClosed) {
			err = nil
		}
		return err
	}

	// try best to send all queued messages especially the data in txqueue
	s.flushKcp(IKCP_FLUSH_FULL, needlock)

	s.sendDisconnect()

	close(s.die)
	s.state.Store(stateDisconnected)
	atomic.AddUint64(&DefaultSnmp.CurrEstab, ^uint64(0))

	if s.handler != nil {
		s.handler.OnDisconnected(s, ct)
		s.handler = nil
	}

	if s.l != nil { // belongs to listener
		s.l.closeSession(s.remote)
		return nil
	}

	if s.ownConn { // client socket close
		return s.conn.Close()
	}

	return nil
}

func (s *UDPSession) flushKcp(flushType FlushType, needlock bool) {
	if needlock {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	s.kcp.flush(flushType)
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (s *UDPSession) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (s *UDPSession) RemoteAddr() net.Addr { return s.remote }

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (s *UDPSession) SetDeadline(t time.Time) error {
	s.rd.Store(t)
	s.wd.Store(t)
	s.notifyReadEvent()
	s.notifyWriteEvent()
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (s *UDPSession) SetReadDeadline(t time.Time) error {
	s.rd.Store(t)
	s.notifyReadEvent()
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (s *UDPSession) SetWriteDeadline(t time.Time) error {
	s.wd.Store(t)
	s.notifyWriteEvent()
	return nil
}

// SetWriteDelay delays write for bulk transfer until the next update interval
func (s *UDPSession) SetWriteDelay(delay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDelay = delay
}

// SetWindowSize set maximum window size
func (s *UDPSession) SetWindowSize(sndwnd, rcvwnd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.WndSize(sndwnd, rcvwnd)
}

// SetMtu sets the maximum transmission unit(not including UDP header)
func (s *UDPSession) SetMtu(mtu int) bool {
	mtu = min(mtuLimit, mtu)

	mtu -= s.headerSize
	if aead, ok := s.block.(*aeadCrypt); ok {
		mtu -= aead.Overhead()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ret := s.kcp.SetMtu(mtu) // kcp mtu is not including udp header
	return ret == 0
}

// SetACKNoDelay changes ack flush option, set true to flush ack immediately,
func (s *UDPSession) SetACKNoDelay(nodelay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ackNoDelay = nodelay
}

// (deprecated)
//
// SetDUP duplicates udp packets for kcp output.
func (s *UDPSession) SetDUP(dup int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dup = dup
}

// SetNoDelay calls nodelay() of kcp
// https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration
func (s *UDPSession) SetNoDelay(nodelay, interval, resend, nc int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.NoDelay(nodelay, interval, resend, nc)
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
//
// if the underlying connection has implemented `func SetDSCP(int) error`, SetDSCP() will invoke
// this function instead.
//
// It has no effect if it's accepted from Listener.
func (s *UDPSession) SetDSCP(dscp int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l != nil {
		return errInvalidOperation
	}

	// interface enabled
	if ts, ok := s.conn.(setDSCP); ok {
		return ts.SetDSCP(dscp)
	}

	if nc, ok := s.conn.(net.Conn); ok {
		var succeed bool
		if err := ipv4.NewConn(nc).SetTOS(dscp << 2); err == nil {
			succeed = true
		}
		if err := ipv6.NewConn(nc).SetTrafficClass(dscp); err == nil {
			succeed = true
		}

		if succeed {
			return nil
		}
	}
	return errInvalidOperation
}

// SetReadBuffer sets the socket read buffer, no effect if it's accepted from Listener
func (s *UDPSession) SetReadBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setReadBuffer); ok {
			return nc.SetReadBuffer(bytes)
		}
	}
	return errInvalidOperation
}

// SetWriteBuffer sets the socket write buffer, no effect if it's accepted from Listener
func (s *UDPSession) SetWriteBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setWriteBuffer); ok {
			return nc.SetWriteBuffer(bytes)
		}
	}
	return errInvalidOperation
}

// SetRateLimit sets the rate limit for this session in bytes per second,
// by setting to 0 will disable rate limiting.
func (s *UDPSession) SetRateLimit(bytesPerSecond uint32) {
	var limiter *rate.Limiter
	if bytesPerSecond == 0 {
		limiter = rate.NewLimiter(rate.Inf, maxBatchSize*mtuLimit)
	} else {
		limiter = rate.NewLimiter(rate.Limit(bytesPerSecond), maxBatchSize*mtuLimit)
	}

	s.rateLimiter.Store(limiter)
}

func (s *UDPSession) SetHandler(h UDPSessionHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// SetLogger configures the kcp trace logger
func (s *UDPSession) SetLogger(mask KCPLogType, logger logoutput_callback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.SetLogger(mask, logger)
}

func (s *UDPSession) RespHello() error {
	s.mu.Lock()
	s.kcp.Send(cmdReliableHello, nil)
	s.kcp.flush(IKCP_FLUSH_FULL)
	s.mu.Unlock()
	atomic.AddUint64(&DefaultSnmp.BytesSent, 1)
	return nil
}

// sendHello sends a hello packet to the remote peer
func (s *UDPSession) sendHello(data []byte) error {
	s.kcp.nocwnd = 1
	s.kcp.Send(cmdReliableHello, data)
	s.kcp.flush(IKCP_FLUSH_FULL)
	s.kcp.nocwnd = 0
	atomic.AddUint64(&DefaultSnmp.BytesSent, 1)
	return nil
}

// sendPing sends a ping packet to the remote peer
func (s *UDPSession) sendPing() error {
	s.kcp.Send(cmdReliablePing, nil)
	atomic.AddUint64(&DefaultSnmp.BytesSent, 1)
	return nil
}

// sendDisconnect sends a disconnect packet to the remote peer
func (s *UDPSession) sendDisconnect() error {
	bts := make([]byte, mirrorPacketSize)
	bts[channelOffset] = channelUnreliable
	binary.LittleEndian.PutUint32(bts[cookieOffset:mirrorHeadSize], s.cookie.Load())
	bts[mirrorHeadSize] = cmdUnreliableDisconnect
	for i := 0; i < disconnectTimes; i++ {
		s.conn.WriteTo(bts, s.RemoteAddr())
	}
	return nil
}

// Control applys a procedure to the underly socket fd.
// CAUTION: BE VERY CAREFUL TO USE THIS FUNCTION, YOU MAY BREAK THE PROTOCOL.
func (s *UDPSession) Control(f func(conn net.PacketConn) error) error {
	if !s.ownConn {
		return errNotOwner
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return f(s.conn)
}

// a goroutine to handle post processing of kcp and make the critical section smaller
// pipeline for outgoing packets (from ARQ to network)
//
//	KCP output -> FEC encoding -> CRC32 integrity -> Encryption -> TxQueue
func (s *UDPSession) postProcess() {
	txqueue := make([]ipv4.Message, 0, devBacklog)
	chDie := s.die

	ctx := context.Background()
	bytesToSend := 0
	for {
		select {
		case buf := <-s.chPostProcessing: // dequeue from post processing
			var ecc [][]byte
			// The buffer 'buf' already contains the 5-byte header (Channel + Cookie) at the beginning.
			// We need to offset the encryption and FEC operations to skip this header with mirrorHeadSize.

			// 1. FEC encoding
			if s.fecEncoder != nil {
				ecc = s.fecEncoder.encode(buf[mirrorHeadSize:], maxFECEncodeLatency)
			}

			// 2. Encryption
			switch block := s.block.(type) {
			case nil:
			case *aeadCrypt:
				nonceSize := block.NonceSize()

				nonceStart := mirrorHeadSize
				nonceEnd := nonceStart + nonceSize
				dst := buf[nonceStart:nonceEnd]
				nonce := buf[nonceStart:nonceEnd]
				plaintext := buf[nonceEnd:]

				fillRand(nonce)
				cryptData := block.Seal(dst, nonce, plaintext, nil)
				buf = append(buf[:mirrorHeadSize], cryptData...)

				for k := range ecc {
					dst := ecc[k][:nonceSize]
					nonce := ecc[k][:nonceSize]
					plaintext := ecc[k][nonceSize:]
					fillRand(nonce)
					ecc[k] = block.Seal(dst, nonce, plaintext, nil)
				}
			default:
				fillRand(buf[mirrorHeadSize : mirrorHeadSize+nonceSize])
				checksum := crc32.ChecksumIEEE(buf[mirrorHeadSize+cryptHeaderSize:])
				binary.LittleEndian.PutUint32(buf[mirrorHeadSize+nonceSize:], checksum)
				// Encrypt the body (excluding the mirror header)
				block.Encrypt(buf[mirrorHeadSize:], buf[mirrorHeadSize:])

				for k := range ecc {
					fillRand(ecc[k][:nonceSize])
					checksum := crc32.ChecksumIEEE(ecc[k][cryptHeaderSize:])
					binary.LittleEndian.PutUint32(ecc[k][nonceSize:], checksum)
					block.Encrypt(ecc[k], ecc[k])
				}
			}

			// 3. TxQueue
			var msg ipv4.Message
			msg.Addr = s.remote

			// original copy, move buf to txqueue directly
			msg.Buffers = [][]byte{buf}
			bytesToSend += len(buf)
			txqueue = append(txqueue, msg)

			// dup copies for testing if set
			for i := 0; i < s.dup; i++ {
				bts := defaultBufferPool.Get()[:len(buf)]
				copy(bts, buf)
				msg.Buffers = [][]byte{bts}
				bytesToSend += len(bts)
				txqueue = append(txqueue, msg)
			}

			// parity
			for k := range ecc {
				// Parity packets need the 5-byte header too.
				// ecc[k] contains the encrypted/encoded payload.
				// We need to prepend [ChannelReliable][Cookie].
				bts := defaultBufferPool.Get()[:mirrorHeadSize+len(ecc[k])]
				bts[channelOffset] = channelReliable
				binary.LittleEndian.PutUint32(bts[cookieOffset:mirrorHeadSize], s.cookie.Load())
				copy(bts[mirrorHeadSize:], ecc[k])

				msg.Buffers = [][]byte{bts}
				bytesToSend += len(bts)
				txqueue = append(txqueue, msg)
			}

			// transmit when chPostProcessing is empty or we've reached max batch size
			if len(s.chPostProcessing) == 0 || len(txqueue) >= maxBatchSize {
				if limiter, ok := s.rateLimiter.Load().(*rate.Limiter); ok {
					err := limiter.WaitN(ctx, bytesToSend)
					if err != nil {
						panic(err)
					}
				}
				s.tx(txqueue)
				s.kcp.debugLog(IKCP_LOG_OUTPUT, "conv", s.kcp.conv, "cookie", s.cookie.Load(), "datalen", bytesToSend)
				// recycle
				for k := range txqueue {
					defaultBufferPool.Put(txqueue[k].Buffers[0])
					txqueue[k].Buffers = nil
				}
				txqueue = txqueue[:0]
				bytesToSend = 0
			}

			// re-enable die channel
			chDie = s.die

		case <-chDie:
			// remaining packets in txqueue should be sent out
			if len(s.chPostProcessing) > 0 {
				chDie = nil // block chDie temporarily
				continue
			}
			return
		}
	}
}

// sess update to trigger protocol
func (s *UDPSession) update() {
	select {
	case <-s.die:
	default:
		s.mu.Lock()
		interval := s.kcp.flush(IKCP_FLUSH_FULL)
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			s.notifyWriteEvent()
		}
		if s.kcp.state == 0xFFFFFFFF {
			s.closeWithType(ClosedByDeadLink, false)
		}
		s.mu.Unlock()
		// self-synchronized timed scheduling
		SystemTimedSched().Put(s.update, time.Now().Add(time.Duration(interval)*time.Millisecond))
	}
}

// SetCookie sets cookie of a session
func (s *UDPSession) SetCookie(cookie uint32) {
	if cookie == 0 {
		binary.Read(rand.Reader, binary.LittleEndian, &cookie)
	}
	s.cookie.Store(cookie)
}

// GetCookie gets cookie of a session
func (s *UDPSession) GetCookie() uint32 { return s.cookie.Load() }

// GetConv gets conversation id of a session
func (s *UDPSession) GetConv() uint32 { return s.kcp.conv }

// GetRTO gets current rto of the session
func (s *UDPSession) GetRTO() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rto
}

// GetSRTT gets current srtt of the session
func (s *UDPSession) GetSRTT() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_srtt
}

// GetRTTVar gets current rtt variance of the session
func (s *UDPSession) GetSRTTVar() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rttvar
}

func (s *UDPSession) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) notifyWriteEvent() {
	select {
	case s.chWriteEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) notifyReadError(err error) {
	s.socketReadErrorOnce.Do(func() {
		s.socketReadError.Store(err)
		close(s.chSocketReadError)
	})
}

func (s *UDPSession) notifyWriteError(err error) {
	s.socketWriteErrorOnce.Do(func() {
		s.socketWriteError.Store(err)
		close(s.chSocketWriteError)
	})
}

func (s *UDPSession) mirrorPacketInput(data []byte) {
	if len(data) < mirrorPacketSize {
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		return
	}

	// server messages always contain the security msgCookie. parse it, assign if not assigned
	msgCookie := binary.LittleEndian.Uint32(data[cookieOffset:mirrorHeadSize])
	if msgCookie == 0 {
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
	}
	cookie := s.cookie.Load()
	if cookie == 0 {
		s.cookie.Store(msgCookie)
	} else if cookie != msgCookie {
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		return
	}

	channel := data[channelOffset]
	switch channel {
	case channelReliable:
		s.rdpPacketInput(data[mirrorHeadSize:])
	case channelUnreliable:
		s.udpPacketInput(data[mirrorHeadSize:])
	default:
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
	}
}

func (s *UDPSession) mirrorReliableInput(data []byte) []byte {
	if len(data) < mirrorCmdSize {
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		return nil
	}

	cmd := data[cmdOffset]
	state := s.state.Load()
	s.kcp.debugLog(IKCP_LOG_READ, "conv", s.kcp.conv, "cookie", s.cookie.Load(), "cmd", cmd, "state", state, "datalen", len(data))
	switch state {
	case stateConnected:
		if cmd == cmdReliableHello {
			s.state.Store(stateAuthenticated)
			if s.handler != nil {
				s.handler.OnConnected(s)
			}
			if s.l != nil { // server side
				if s.handler == nil { // user not set cookie, auto generate cookie and resp hello
					s.sendHello(nil)
					s.notifyWriteEvent()
				} else { // user set cookie OnConnect hook, need handle hello data and resp hello
					return data[mirrorCmdSize:]
				}
			}
		} else if cmd == cmdReliableData {
			s.closeWithType(ClosedByErrState, false)
		}

	case stateAuthenticated:
		if cmd == cmdReliablePing {
			s.sendPing()
			if s.handler != nil {
				s.handler.OnPing(s, s.kcp.rx_srtt)
			}
			if s.l != nil {
				s.l.debugLog(LISTEN_LOG_RDP_PING, "addr", s.remote.String(), "conv", s.kcp.conv, "cookie", s.cookie.Load())
			}
		} else if cmd == cmdReliableData {
			if s.l != nil {
				s.l.debugLog(LISTEN_LOG_RDP_DATA, "addr", s.remote.String(), "conv", s.kcp.conv, "cookie", s.cookie.Load(), "datalen", len(data[mirrorCmdSize:]))
			}
			return data[mirrorCmdSize:]
		} else if cmd == cmdReliableHello {
			s.closeWithType(ClosedByErrState, false)
		}

	case stateDisconnected:
		return data[mirrorCmdSize:]
	}
	return nil
}

func (s *UDPSession) mirrorUnreliableInput(data []byte) []byte {
	cmd := data[cmdOffset]
	switch cmd {
	case cmdUnreliableData:
		return data[mirrorCmdSize:]
	case cmdUnreliableDisconnect:
		s.closeWithType(ClosedByRemote, false)
	default:
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
	}
	return nil
}

func packetDecrypt(block BlockCrypt, data []byte) []byte {
	switch block := block.(type) {
	case nil:
		return data
	case *aeadCrypt:
		nonceSize := block.NonceSize()
		if len(data) < nonceSize+block.Overhead() {
			break
		}

		nonce := data[:nonceSize]
		ciphertext := data[nonceSize:]

		plaintext, err := block.Open(ciphertext[:0], nonce, ciphertext, nil)
		if err != nil {
			atomic.AddUint64(&DefaultSnmp.InCsumErrors, 1)
			return nil
		}
		return plaintext

	default:
		// decryption and crc32 check
		if len(data) < cryptHeaderSize {
			return nil
		}

		block.Decrypt(data, data)
		crcsum := binary.LittleEndian.Uint32(data[nonceSize:])
		data = data[cryptHeaderSize:]
		checksum := crc32.ChecksumIEEE(data)
		if checksum != crcsum {
			atomic.AddUint64(&DefaultSnmp.InCsumErrors, 1)
			return nil
		}

		return data
	}

	return nil
}

// packet input pipeline:
// network -> [decryption ->] [crc32 ->] [FEC ->] [KCP input ->] stream -> application
func (s *UDPSession) rdpPacketInput(data []byte) {
	data = packetDecrypt(s.block, data)
	if len(data) < IKCP_OVERHEAD {
		return
	}
	s.kcpInput(data)
}

// kcpInput inputs a decrypted and crc32-checked packet into kcp with FEC handling
func (s *UDPSession) kcpInput(data []byte) {
	atomic.AddUint64(&DefaultSnmp.InPkts, 1)
	atomic.AddUint64(&DefaultSnmp.InBytes, uint64(len(data)))

	// 16bit kcp cmd [81-84] and frg [0-255] will not overlap with FEC type 0x00f1 0x00f2
	fecFlag := binary.LittleEndian.Uint16(data[4:])
	switch fecFlag {
	case typeData, typeParity: // packet with FEC
		if len(data) < fecHeaderSizePlus2 {
			atomic.AddUint64(&DefaultSnmp.InErrs, 1)
			return
		}

		var kcpInErrors uint64
		f := fecPacket(data)

		// lock
		s.mu.Lock()
		defer s.mu.Unlock()

		// if fecDecoder is not initialized, create one with default parameter
		// lazy initialization
		if s.fecDecoder == nil {
			s.fecDecoder = newFECDecoder(1, 1)
		}

		// FEC decoding
		recovers := s.fecDecoder.decode(f)
		if f.flag() == typeData {
			if ret := s.kcp.Input(data[fecHeaderSizePlus2:], IKCP_PACKET_REGULAR, s.ackNoDelay); ret != 0 {
				kcpInErrors++
			}
		}

		// If there're some packets recovered from FEC, feed them into kcp
		for _, r := range recovers {
			if len(r) >= 2 { // must be larger than 2bytes
				sz := binary.LittleEndian.Uint16(r)
				if int(sz) <= len(r) && sz >= 2 {
					if ret := s.kcp.Input(r[2:sz], IKCP_PACKET_FEC, s.ackNoDelay); ret != 0 {
						kcpInErrors++
					}
				}
			}
			// recycle the buffer
			defaultBufferPool.Put(r)
		}

		// to notify the readers to receive the data if there's any
		if n := s.kcp.PeekSize(); n > 0 {
			s.notifyReadEvent()
		}

		// to notify the writers if the window size allows to send more packets
		// and the remote window size is not full.
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			s.notifyWriteEvent()
		}

		if kcpInErrors > 0 {
			atomic.AddUint64(&DefaultSnmp.KCPInErrors, kcpInErrors)
		}
	default: // packet without FEC
		s.mu.Lock()
		defer s.mu.Unlock()

		if ret := s.kcp.Input(data, IKCP_PACKET_REGULAR, s.ackNoDelay); ret != 0 {
			atomic.AddUint64(&DefaultSnmp.KCPInErrors, 1)
		}

		if n := s.kcp.PeekSize(); n > 0 {
			s.notifyReadEvent()
		}

		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			s.notifyWriteEvent()
		}
		return
	}
}

// datagram defines a udp datagram
type datagram struct {
	data []byte
}

func (s *UDPSession) udpPacketInput(data []byte) {
	n := len(data)
	d := datagram{
		data: defaultBufferPool.Get()[:n],
	}
	copy(d.data, data)

	s.mu.Lock()
	s.udpRecvQueue.Push(d)
	s.mu.Unlock()

	s.notifyReadEvent()

	atomic.AddUint64(&DefaultSnmp.InUdpPkts, 1)
	atomic.AddUint64(&DefaultSnmp.InBytes, uint64(n))
}

// kcpHardReset reset kcp state, Used for resetting and rebuilding the Seq for client handling
func (s *UDPSession) kcpHardReset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. reset kcp core parameters
	if s.kcp != nil {
		s.kcp.snd_una = 0
		s.kcp.snd_nxt = 0
		s.kcp.rcv_nxt = 0
		// clear queue
		s.kcp.snd_queue.Clear()
		s.kcp.snd_buf.Clear()
		s.kcp.rcv_queue.Clear()
		s.kcp.rcv_buf = newMinheap(int(s.kcp.rcv_wnd))
		// clear ack list
		s.kcp.acklist = s.kcp.acklist[:0]
	}

	// 2. wake up possible blocked Write/Read
	s.notifyReadEvent()
	s.notifyWriteEvent()
}

// skip migration packet
func (s *UDPSession) kcpSkipOne() {
	s.mu.Lock()
	s.kcp.rcv_nxt++
	s.mu.Unlock()
}

type ListenLogType uint32

const (
	LISTEN_LOG_RDP_INPUT ListenLogType = 1 << iota
	LISTEN_LOG_UDP_INPUT
	LISTEN_LOG_RDP_ORIGN
	LISTEN_LOG_RDP_HELLO
	LISTEN_LOG_RDP_PING
	LISTEN_LOG_RDP_DATA
	LISTEN_LOG_UDP_DATA
	LISTEN_LOG_UDP_DISCONNECT
	LISTEN_LOG_RDP_DROP
	LISTEN_LOG_UDP_DROP
)

const (
	LISTEN_LOG_RDP_ALL ListenLogType = LISTEN_LOG_RDP_INPUT | LISTEN_LOG_RDP_ORIGN | LISTEN_LOG_RDP_HELLO | LISTEN_LOG_RDP_PING | LISTEN_LOG_RDP_DATA | LISTEN_LOG_RDP_DROP
	LISTEN_LOG_UDP_ALL ListenLogType = LISTEN_LOG_UDP_INPUT | LISTEN_LOG_UDP_DATA | LISTEN_LOG_UDP_DISCONNECT | LISTEN_LOG_UDP_DROP
	LISTEN_LOG_ALL     ListenLogType = LISTEN_LOG_RDP_ALL | LISTEN_LOG_UDP_ALL
)

type (
	// Listener defines a server which will be waiting to accept incoming connections
	Listener struct {
		block        BlockCrypt     // block encryption
		dataShards   int            // FEC data shard
		parityShards int            // FEC parity shard
		conn         net.PacketConn // the underlying packet connection
		ownConn      bool           // true if we created conn internally, false if provided by caller

		sessions        map[string]*UDPSession // all sessions accepted by this Listener
		sessionLock     sync.RWMutex
		chAccepts       chan *UDPSession // Listen() backlog
		chSessionClosed chan net.Addr    // session close queue

		die    chan struct{} // notify the listener has closed
		closed atomic.Bool

		logmask ListenLogType // log mask

		// socket error handling
		socketReadError     atomic.Value
		chSocketReadError   chan struct{}
		socketReadErrorOnce sync.Once

		rd atomic.Value // read deadline for Accept()

		handler ListenerHandler
		log     logoutput_callback
	}
)

type ListenerHandler interface {
	OnConnect(addr net.Addr, conv uint32) (cookie uint32)
	OnDisconnect(sess *UDPSession)
}

// packet input stage
func (l *Listener) mirrorPacketInput(data []byte, addr net.Addr) {
	if len(data) < mirrorPacketSize {
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		return
	}

	l.sessionLock.RLock()
	sess := l.sessions[addr.String()]
	l.sessionLock.RUnlock()

	channel := data[channelOffset]
	msgCookie := binary.LittleEndian.Uint32(data[cookieOffset:mirrorHeadSize])
	data = data[mirrorHeadSize:]
	switch channel {
	case channelReliable:
		l.mirrorReliableInput(sess, data, addr, msgCookie)
	case channelUnreliable:
		l.mirrorUnreliableInput(sess, data, addr, msgCookie)
	default:
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
	}
}

func (l *Listener) mirrorReliableInput(sess *UDPSession, data []byte, addr net.Addr, msgCookie uint32) {
	data = packetDecrypt(l.block, data)
	if len(data) < IKCP_OVERHEAD {
		return
	}

	// cmd is after KCP Header (byte 24 of payload)
	conv, sn, cmd, convRecovered := l.parseHeader(data)
	l.debugLog(LISTEN_LOG_RDP_INPUT, "addr", addr.String(), "cookie", msgCookie,
		"conv", conv, "sn", sn, "cmd", cmd, "convRecovered", convRecovered, "datalen", len(data))

	if sess != nil { // existing connection
		if msgCookie != sess.cookie.Load() {
			l.debugLog(LISTEN_LOG_RDP_DROP, "addr", addr.String(), "cookie", msgCookie, "sess_cookie", sess.cookie.Load(), "conv", conv, "sn", sn, "cmd", cmd, "datalen", len(data))
			atomic.AddUint64(&DefaultSnmp.InErrs, 1)
			return
		}
		if !convRecovered || conv == sess.kcp.conv { // parity data or valid conversation
			sess.kcpInput(data)
		}
	}

	if sess == nil && convRecovered { // new session
		if cmd != cmdReliableHello {
			return
		}
		var cookie uint32
		if l.handler != nil {
			if cookie = l.handler.OnConnect(addr, conv); cookie == 0 {
				return
			}
		}
		l.debugLog(LISTEN_LOG_RDP_HELLO, "addr", addr.String(), "sess_cookie", cookie, "conv", conv, "sn", sn)
		if len(l.chAccepts) < cap(l.chAccepts) { // do not let the new sessions overwhelm accept queue
			sess = newUDPSession(conv, l.dataShards, l.parityShards, l, l.conn, false, addr, l.block)
			sess.SetCookie(cookie)
			sess.kcpInput(data)
			l.sessionLock.Lock()
			l.sessions[addr.String()] = sess
			l.sessionLock.Unlock()
			l.chAccepts <- sess
		}
		return
	}
}

func (l *Listener) mirrorUnreliableInput(sess *UDPSession, data []byte, addr net.Addr, msgCookie uint32) {
	cmd := data[cmdOffset]
	l.debugLog(LISTEN_LOG_UDP_INPUT, "addr", addr.String(), "cookie", msgCookie, "cmd", cmd, "datalen", len(data))

	if sess == nil {
		return
	}
	if sess.state.Load() != stateAuthenticated {
		return
	}
	if msgCookie != sess.cookie.Load() {
		l.debugLog(LISTEN_LOG_UDP_DROP, "addr", addr.String(), "cookie", msgCookie, "sess_cookie", sess.cookie.Load(), "conv", sess.kcp.conv, "cmd", cmd, "datalen", len(data))
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
		return
	}

	switch cmd {
	case cmdUnreliableData:
		l.debugLog(LISTEN_LOG_UDP_DATA, "cookie", msgCookie, "conv", sess.kcp.conv, "datalen", len(data))
		sess.udpPacketInput(data)
	case cmdUnreliableDisconnect:
		l.debugLog(LISTEN_LOG_UDP_DISCONNECT, "cookie", msgCookie, "conv", sess.kcp.conv, "datalen", len(data))
		sess.udpPacketInput(data)
	default:
		atomic.AddUint64(&DefaultSnmp.InErrs, 1)
	}
}

func (l *Listener) parseHeader(data []byte) (conv uint32, sn uint32, cmd byte, convRecovered bool) {
	cmd = cmdKcpOriginal
	convRecovered = false
	fecFlag := binary.LittleEndian.Uint16(data[4:])
	if fecFlag == typeData || fecFlag == typeParity { // 16bit kcp cmd [81-84] and frg [0-255] will not overlap with FEC type 0x00f1 0x00f2
		// packet with FEC
		if fecFlag == typeData {
			headerLen := fecHeaderSizePlus2 + IKCP_OVERHEAD
			if len(data) >= headerLen {
				conv = binary.LittleEndian.Uint32(data[fecHeaderSizePlus2:])
				sn = binary.LittleEndian.Uint32(data[fecHeaderSizePlus2+IKCP_SN_OFFSET:])
			}
			if len(data) > headerLen {
				cmd = data[fecHeaderSizePlus2+IKCP_OVERHEAD]
			}
			convRecovered = true
		}
	} else {
		// packet without FEC
		conv = binary.LittleEndian.Uint32(data)
		sn = binary.LittleEndian.Uint32(data[IKCP_SN_OFFSET:])
		if len(data) > IKCP_OVERHEAD {
			cmd = data[IKCP_OVERHEAD]
		}
		convRecovered = true
	}
	return conv, sn, cmd, convRecovered
}

func (l *Listener) notifyReadError(err error) {
	l.socketReadErrorOnce.Do(func() {
		l.socketReadError.Store(err)
		close(l.chSocketReadError)

		// propagate read error to all sessions
		l.sessionLock.RLock()
		for _, s := range l.sessions {
			s.notifyReadError(err)
		}
		l.sessionLock.RUnlock()
	})
}

// SetReadBuffer sets the socket read buffer for the Listener
func (l *Listener) SetReadBuffer(bytes int) error {
	if conn, ok := l.conn.(setReadBuffer); ok {
		return conn.SetReadBuffer(bytes)
	}
	return errInvalidOperation
}

// SetWriteBuffer sets the socket write buffer for the Listener
func (l *Listener) SetWriteBuffer(bytes int) error {
	if conn, ok := l.conn.(setWriteBuffer); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return errInvalidOperation
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
//
// if the underlying connection has implemented `func SetDSCP(int) error`, SetDSCP() will invoke
// this function instead.
func (l *Listener) SetDSCP(dscp int) error {
	// interface enabled
	if conn, ok := l.conn.(setDSCP); ok {
		return conn.SetDSCP(dscp)
	}

	conn, ok := l.conn.(net.Conn)
	if !ok {
		return errInvalidOperation
	}

	var succeed bool
	if err := ipv4.NewConn(conn).SetTOS(dscp << 2); err == nil {
		succeed = true
	}

	if err := ipv6.NewConn(conn).SetTrafficClass(dscp); err == nil {
		succeed = true
	}

	if succeed {
		return nil
	}

	return errInvalidOperation
}

// Accept implements the Accept method in the Listener interface; it waits for the next call and returns a generic Conn.
func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptKCP()
}

// AcceptKCP accepts a KCP connection
func (l *Listener) AcceptKCP() (*UDPSession, error) {
	var timeout <-chan time.Time
	if tdeadline, ok := l.rd.Load().(time.Time); ok && !tdeadline.IsZero() {
		timer := time.NewTimer(time.Until(tdeadline))
		defer timer.Stop()

		timeout = timer.C
	}

	select {
	case <-timeout:
		return nil, errors.WithStack(errTimeout)
	case c := <-l.chAccepts:
		return c, nil
	case <-l.chSocketReadError:
		return nil, l.socketReadError.Load().(error)
	case <-l.die:
		return nil, errors.WithStack(io.ErrClosedPipe)
	}
}

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (l *Listener) SetDeadline(t time.Time) error {
	l.SetReadDeadline(t)
	l.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (l *Listener) SetReadDeadline(t time.Time) error {
	l.rd.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (l *Listener) SetWriteDeadline(t time.Time) error {
	return errInvalidOperation
}

func (s *Listener) SetHandler(h ListenerHandler) {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	s.handler = h
}

func (s *Listener) SetLogger(mask ListenLogType, logger logoutput_callback) {
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	s.logmask = mask
	s.log = logger
}

// Close stops listening on the UDP address, and closes the socket
func (l *Listener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return errors.WithStack(io.ErrClosedPipe)
	}

	close(l.die)
	if l.ownConn {
		return l.conn.Close()
	}
	if l.handler != nil {
		l.handler = nil
	}
	return nil
}

// Control applys a procedure to the underly socket fd.
// CAUTION: BE VERY CAREFUL TO USE THIS FUNCTION, YOU MAY BREAK THE PROTOCOL.
func (l *Listener) Control(f func(conn net.PacketConn) error) error {
	l.sessionLock.Lock()
	defer l.sessionLock.Unlock()

	return f(l.conn)
}

// closeSession notify the listener that a session has closed
func (l *Listener) closeSession(remote net.Addr) bool {
	addr := remote.String()

	l.sessionLock.Lock()
	sess, ok := l.sessions[addr]
	if ok {
		delete(l.sessions, addr)
		l.sessionLock.Unlock() // unlock then notify handler to avoid deadlock
		if l.handler != nil {
			l.handler.OnDisconnect(sess)
		}
		return true
	}

	l.sessionLock.Unlock()
	return false
}

// Addr returns the listener's network address, The Addr returned is shared by all invocations of Addr, so do not modify it.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Listen listens for incoming KCP packets addressed to the local address laddr on the network "udp",
func Listen(laddr string) (net.Listener, error) {
	return ListenWithOptions(laddr, nil, 0, 0)
}

// ListenWithOptions listens for incoming KCP packets addressed to the local address laddr on the network "udp" with packet encryption.
//
// 'block' is the block encryption algorithm to encrypt packets.
//
// 'dataShards', 'parityShards' specify how many parity packets will be generated following the data packets.
//
// Check https://github.com/klauspost/reedsolomon for details
func ListenWithOptions(laddr string, block BlockCrypt, dataShards, parityShards int) (*Listener, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	conn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return serveConn(block, dataShards, parityShards, conn, true)
}

// ServeConn serves KCP protocol for a single packet connection.
func ServeConn(block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*Listener, error) {
	return serveConn(block, dataShards, parityShards, conn, false)
}

func serveConn(block BlockCrypt, dataShards, parityShards int, conn net.PacketConn, ownConn bool) (*Listener, error) {
	l := new(Listener)
	l.conn = conn
	l.ownConn = ownConn
	l.sessions = make(map[string]*UDPSession)
	l.chAccepts = make(chan *UDPSession, acceptBacklog)
	l.chSessionClosed = make(chan net.Addr)
	l.die = make(chan struct{})
	l.dataShards = dataShards
	l.parityShards = parityShards
	l.block = block
	l.chSocketReadError = make(chan struct{})
	go l.monitor()
	return l, nil
}

// Dial connects to the remote address "raddr" on the network "udp" without encryption and FEC
func Dial(raddr string) (net.Conn, error) {
	return DialWithOptions(raddr, nil, 0, 0)
}

// DialWithOptions connects to the remote address "raddr" on the network "udp" with packet encryption
//
// 'block' is the block encryption algorithm to encrypt packets.
//
// 'dataShards', 'parityShards' specify how many parity packets will be generated following the data packets.
//
// Check https://github.com/klauspost/reedsolomon for details
func DialWithOptions(raddr string, block BlockCrypt, dataShards, parityShards int) (*UDPSession, error) {
	// network type detection
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	network := "udp4"
	if udpaddr.IP.To4() == nil {
		network = "udp"
	}

	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	return newUDPSession(convid, dataShards, parityShards, nil, conn, true, udpaddr, block), nil
}

// NewConn4 establishes a session and talks KCP protocol over a packet connection.
func NewConn4(convid uint32, raddr net.Addr, block BlockCrypt, dataShards, parityShards int, ownConn bool, conn net.PacketConn) (*UDPSession, error) {
	return newUDPSession(convid, dataShards, parityShards, nil, conn, ownConn, raddr, block), nil
}

// NewConn3 establishes a session and talks KCP protocol over a packet connection.
func NewConn3(convid uint32, raddr net.Addr, block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*UDPSession, error) {
	return newUDPSession(convid, dataShards, parityShards, nil, conn, false, raddr, block), nil
}

// NewConn2 establishes a session and talks KCP protocol over a packet connection.
func NewConn2(raddr net.Addr, block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*UDPSession, error) {
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	return NewConn3(convid, raddr, block, dataShards, parityShards, conn)
}

// NewConn establishes a session and talks KCP protocol over a packet connection.
func NewConn(raddr string, block BlockCrypt, dataShards, parityShards int, conn net.PacketConn) (*UDPSession, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return NewConn2(udpaddr, block, dataShards, parityShards, conn)
}
