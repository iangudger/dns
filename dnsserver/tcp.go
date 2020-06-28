// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/iangudger/dns/dnsresolver"
)

const (
	// defaultTCPTimeout is the default timeout for TCP DNS connections.
	//
	// According to RFC 1035, Section 4.2.2. TCP usage, this should be two
	// minutes.
	defaultTCPTimeout = 2 * time.Minute

	// tcpInitialReadBufferSize is the default size used for TCP read
	// buffers.
	//
	// According to RFC 4035, 1280 bytes is a reasonable initial size for
	// IP over Ethernet.
	tcpInitialReadBufferSize = 1280

	// tcpInitialWriteBufferSize is the default size used for TCP write buffers.
	//
	// According to RFC 7766, section 8, the two-byte length should be
	// written in the same segment as the message.
	tcpInitialWriteBufferSize = tcpInitialReadBufferSize + 2
)

// TCPConfig contains optional configuration options for the TCP DNS server.
type TCPConfig struct {
	_ struct{} // Prevent positional initialization.

	// ClientTimeout is an optional timeout for communication with clients.
	//
	// If zero, the default value will be used.
	//
	// If negative, the timeout will be disabled.
	ClientTimeout time.Duration

	// ResolverTimeout is an optional timeout for communication with the
	// resolver.
	//
	// ResolverTimeout is only enforced if greater than zero.
	ResolverTimeout time.Duration
}

// ServeTCP listens for and responds to TCP DNS requests.
func (s *Server) ServeTCP(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		s.wg.Add(1)

		go func() {
			if err := s.handleTCP(conn); err != nil {
				s.errorf("TCP DNS server: %v", err)
			}
			conn.Close()
			s.wg.Done()
		}()
	}
}

func (s *Server) tcpDeadline() time.Time {
	d := time.Duration(atomic.LoadInt64((*int64)(&s.config.TCP.ClientTimeout)))
	if d < 0 {
		return time.Time{}
	}
	if d == 0 {
		d = defaultTCPTimeout
	}
	return time.Now().Add(d)
}

// handleTCP responds to a TCP DNS request.
//
// handleTCP does not take ownership of conn.
func (s *Server) handleTCP(conn net.Conn) error {
	srb := make([]byte, tcpInitialReadBufferSize)
	swb := make([]byte, tcpInitialWriteBufferSize)
	ctx := context.Background()
	if a := conn.RemoteAddr(); a != nil {
		ctx = context.WithValue(ctx, dnsresolver.SourceContextKey, a)
	}

	for {
		// Make a copy of the slice headers for use in this loop
		// iteration.
		readBuf := srb
		writeBuf := swb

		if err := conn.SetReadDeadline(s.tcpDeadline()); err != nil {
			return fmt.Errorf("setting read deadline: %v", err)
		}

		// Read the message length.
		if _, err := io.ReadFull(conn, readBuf[:2]); err != nil {
			return fmt.Errorf("reading request length: %v", err)
		}
		l := int(binary.BigEndian.Uint16(readBuf[:2]))

		// The message length is a uint16, so it can't be big enough to
		// cause a problem.
		if l > cap(readBuf) {
			readBuf = make([]byte, l)
		}
		readBuf = readBuf[:l]

		if _, err := io.ReadFull(conn, readBuf); err != nil {
			return fmt.Errorf("reading request data: %v", err)
		}

		ctx := ctx
		var cancel func()
		if t := s.config.TCP.ResolverTimeout; t > 0 {
			ctx, cancel = context.WithTimeout(ctx, t)
		}

		// Resolve DNS request.
		//
		// As per RFC 1035, TCP DNS messages are preceded by a 16 bit
		// size. Therefore the maximum size of a TCP DNS message is the
		// maximum 16 bit number.
		resp, err := s.pr.ResolvePacket(ctx, readBuf, math.MaxUint16, writeBuf[:2])
		if cancel != nil {
			cancel()
		}
		if err != nil {
			return fmt.Errorf("resolving request: %v", err)
		}

		respLen := len(resp) - 2
		if respLen > math.MaxUint16 {
			// This should never happen as it is a direct violation
			// of the interface contract.
			panic(fmt.Sprintf("response from ResolvePacket is of length %d, max requested %d", respLen, math.MaxUint16))
		}

		// Set length bytes.
		binary.BigEndian.PutUint16(resp[:2], uint16(respLen))

		// Write packet.
		if err := conn.SetWriteDeadline(s.tcpDeadline()); err != nil {
			return fmt.Errorf("setting write deadline: %v", err)
		}

		if _, err := conn.Write(resp); err != nil {
			return fmt.Errorf("writing response: %v", err)
		}
	}
}

// setTCPTimeout updates the TCP timeout.
func (s *Server) setTCPTimeout(t time.Duration) {
	atomic.StoreInt64((*int64)(&s.config.TCP.ClientTimeout), int64(t))
}
