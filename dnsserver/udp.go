// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/iangudger/dns/dnsresolver"
)

// udpBufferSize is the size of UDP buffers.
//
// RFC 1035 (section 2.3.4. Size limits) limits UDP DNS messages to 512 bytes.
const udpBufferSize = 512

// UDPConfig contains optional configuration options for the UDP DNS server.
type UDPConfig struct {
	_ struct{} // Prevent positional initialization.

	// DisableConcurrency, when true, causes requests to be handled in a
	// single goroutine. This is useful for fast resolvers such as static
	// resolvers or as a light weight way to rate-limit requests.
	DisableConcurrency bool

	// ResolverTimeout is an optional timeout for communication with the
	// resolver.
	//
	// ResolverTimeout is only enforced if greater than zero.
	ResolverTimeout time.Duration
}

// ServeUDP listens for and responds to UDP DNS requests.
func (s *Server) ServeUDP(c net.PacketConn) error {
	var srb []byte
	var swb []byte
	if s.config.UDP.DisableConcurrency {
		srb = make([]byte, udpBufferSize)
		swb = make([]byte, udpBufferSize)
	}
	for {
		readBuf := srb
		writeBuf := swb[:0]
		if !s.config.UDP.DisableConcurrency {
			readBuf = make([]byte, udpBufferSize)
			writeBuf = nil
		}
		n, addr, err := c.ReadFrom(readBuf)
		if err != nil {
			return err
		}
		readBuf = readBuf[:n]

		ctx := context.Background()
		if addr != nil {
			ctx = context.WithValue(ctx, dnsresolver.SourceContextKey, addr)
		}
		var cancel func()
		if t := s.config.UDP.ResolverTimeout; t > 0 {
			ctx, cancel = context.WithTimeout(ctx, t)
		}

		servReq := func() {
			if err := s.handleUDP(ctx, c, readBuf, addr, writeBuf); err != nil {
				s.errorf("UDP DNS server: handling request: %v", err)
			}
			if cancel != nil {
				cancel()
			}
		}

		if s.config.UDP.DisableConcurrency {
			servReq()
			continue
		}

		s.wg.Add(1)
		go func() {
			servReq()
			s.wg.Done()
		}()
	}
}

// handleUDP responds to a UDP DNS request.
//
// handleUDP does not take ownership of conn.
func (s *Server) handleUDP(ctx context.Context, c net.PacketConn, readBuf []byte, addr net.Addr, writeBuf []byte) error {
	// Resolve DNS request.
	resp, err := s.pr.ResolvePacket(ctx, readBuf, udpBufferSize, writeBuf)
	if err != nil {
		return fmt.Errorf("resolving packet: %v", err)
	}

	// Write packet.
	if _, err := c.WriteTo(resp, addr); err != nil {
		fmt.Errorf("writing response: %v", err)
	}
	return nil
}
