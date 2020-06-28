// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsserver provides basic UDP and TCP DNS servers.
package dnsserver

import (
	"errors"
	"sync"

	"github.com/iangudger/dns/dnsresolver"
)

// A Logger allows emitting debug information.
type Logger func(format string, v ...interface{})

// A Config holds configuration for a DNS server, including protocol specific
// configurations.
type Config struct {
	_ struct{} // Prevent positional initialization.

	// TCPConfig contains optional configuration options for the TCP DNS
	// server.
	TCP TCPConfig

	// UDPConfig contains optional configuration options for the UDP DNS
	// server.
	UDP UDPConfig

	// Errorf is optionally used to log errors.
	Errorf Logger
}

// A Server is a DNS server. It can be used with both TCP and UDP.
type Server struct {
	// config is a copy of the TCPConfig provided to New. It is
	// immutable except for TCP.Timeout, which must be accessed
	// atomically.
	//
	// Note that this field must be first to ensure that the TCP
	// timeout is 64-bit aligned so it can be accessed atomically
	// on 32-bit systems.
	config Config

	pr dnsresolver.PacketResolver

	wg sync.WaitGroup
}

var errNilResolver = errors.New("PacketResolver can't be nil")

// New creates a new DNS server, but does not start it.
func New(config Config, r dnsresolver.PacketResolver) (*Server, error) {
	if r == nil {
		return nil, errNilResolver
	}
	return &Server{config: config, pr: r}, nil
}

// Wait waits for all spawned goroutines to exit.
func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) errorf(format string, v ...interface{}) {
	if s.config.Errorf != nil {
		s.config.Errorf(format, v)
	}
}
