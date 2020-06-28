// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
	"github.com/iangudger/dns/internal/resolvers"
)

func testUDP() (net.PacketConn, net.Addr, error) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		return nil, nil, err
	}

	return pc, pc.LocalAddr(), nil
}

func TestUDP(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatal("Creating name:", err)
	}

	tests := []struct {
		name   string
		config UDPConfig
	}{
		{"concurrency", UDPConfig{DisableConcurrency: false}},
		{"no concurrency", UDPConfig{DisableConcurrency: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pc, addr, err := testUDP()
			if err != nil {
				t.Fatal("creating UDP socket:", err)
			}

			pr, err := dnsresolver.NewPacketResolver(
				dnsresolver.PacketResolverConfig{},
				resolvers.NewErroringResolver(),
			)
			if err != nil {
				pc.Close()
				t.Fatal(`dnsresolver.NewPacketResolver(...) =`, err)
			}

			srv, err := New(Config{UDP: test.config, Errorf: t.Logf}, pr)
			if err != nil {
				pc.Close()
				t.Fatal("creating UDP server:", err)
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				srv.ServeUDP(pc)
				wg.Done()
			}()
			wait := func() {
				srv.Wait()
				wg.Wait()
			}

			conn, err := net.Dial("udp", addr.String())
			if err != nil {
				pc.Close()
				wait()
				t.Fatalf("dialing server (%v): %v", addr, err)
			}
			close := func() {
				pc.Close()
				conn.Close()
			}

			req := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:               8,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
			}

			reqBuf, err := req.Pack()
			if err != nil {
				close()
				wait()
				t.Fatal("packing request:", err)
			}

			conn.SetDeadline(time.Now().Add(time.Second))

			if _, err := conn.Write(reqBuf); err != nil {
				close()
				wait()
				t.Fatal("writing request:", err)
			}

			resBuf := make([]byte, 1000)
			n, err := conn.Read(resBuf)
			close()
			wait()
			if err != nil {
				t.Fatal("reading response:", err)
			}
			resBuf = resBuf[:n]

			var res dnsmessage.Message
			if err := res.Unpack(resBuf); err != nil {
				t.Fatal("unpacking response:", err)
			}

			want := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 req.Header.ID,
					Response:           true,
					RCode:              dnsmessage.RCodeNotImplemented,
					Authoritative:      false,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
				Questions: []dnsmessage.Question{{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			}

			if !reflect.DeepEqual(res, want) {
				t.Errorf("got = %#v, want = %#v", &res, &want)
			}
		})
	}
}
