// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
	"github.com/iangudger/dns/internal/resolvers"
)

func testTCPServer(t *testing.T) (srv *Server, addr net.Addr, wait func(), close func() error, err error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return
	}
	pr, err := dnsresolver.NewPacketResolver(
		dnsresolver.PacketResolverConfig{},
		resolvers.NewErroringResolver(),
	)
	if err != nil {
		return
	}
	srv, err = New(Config{TCP: TCPConfig{
		ClientTimeout: 2 * time.Second},
		Errorf: t.Logf,
	}, pr)
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		srv.ServeTCP(lis)
		wg.Done()
	}()
	wait = func() {
		wg.Wait()
		srv.Wait()
	}
	return srv, lis.Addr(), wait, lis.Close, nil
}

func TestShutdown(t *testing.T) {
	_, _, wait, close, err := testTCPServer(t)
	if err != nil {
		t.Fatal("starting TCP DNS Server:", err)
	}

	if err := close(); err != nil {
		t.Error("closing TCP listener:", err)
	}
	wait()
}

func TestTCP(t *testing.T) {
	tests := []struct {
		name string
		msg  dnsmessage.Message
	}{
		{
			"short request",
			dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:               6,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
			},
		},
		{
			"long request",
			dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:               7,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Additionals: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("example.com."),
						Type:  dnsmessage.TypeTXT,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.TXTResource{
						TXT: []string{
							string(make([]byte, 255)),
							string(make([]byte, 255)),
							string(make([]byte, 255)),
							string(make([]byte, 255)),
							string(make([]byte, 255)),
							string(make([]byte, 255)),
						},
					},
				}},
			},
		},
	}

	_, addr, wait, close, err := testTCPServer(t)
	if err != nil {
		t.Fatal("creating test TCP server:", err)
	}
	defer func() {
		close()
		wait()
	}()

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf(`net.Dial("tcp", %q) = _, %v`, addr, err)
	}
	defer c.Close()

	buf := make([]byte, 10000)

	// Test the different types of requests on the same connection.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := test.msg.Pack()
			if err != nil {
				t.Fatal("packing request:", err)
			}

			if _, err := c.Write([]byte{byte(len(b) >> 8), byte(len(b))}); err != nil {
				t.Fatal("writing request length:", err)
			}

			if _, err := c.Write(b); err != nil {
				t.Fatal("writing request:", err)
			}

			if _, err := io.ReadFull(c, buf[:2]); err != nil {
				t.Fatal("reading response length:", err)
			}

			wantLen := int(buf[0])<<8 | int(buf[1])
			gotBuf := buf[:wantLen]
			if _, err := io.ReadFull(c, gotBuf); err != nil {
				t.Fatal("reading response:", err)
			}

			var got dnsmessage.Message
			if err := got.Unpack(gotBuf); err != nil {
				t.Fatal("unpacking response:", err)
			}

			want := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 test.msg.Header.ID,
					Response:           true,
					RCode:              dnsmessage.RCodeNotImplemented,
					Authoritative:      false,
					RecursionDesired:   true,
					RecursionAvailable: true,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("got = %#v, want = %#v", &got, &want)
			}
		})
	}
}

func TestTCPReadError(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		timeout bool
	}{
		// "no length" and "partial length" should cause the length read
		// to timeout.
		{"no length", nil, true},
		{"partial length", []byte{0}, true},

		// "no request" should cause the data read to timeout.
		{"no request", []byte{0, 5}, true},

		// "zero length request" should cause a zero length request to
		// be passed to the resolver causing a resolve error.
		{"zero length request", []byte{0, 0}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, addr, wait, close, err := testTCPServer(t)
			if err != nil {
				t.Fatal("creating test TCP server:", err)
			}
			defer func() {
				close()
				wait()
			}()

			if test.timeout {
				ts.setTCPTimeout(100 * time.Millisecond)
			}

			c, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatalf(`net.Dial("tcp", %q) = _, %v`, addr.String(), err)
			}
			defer c.Close()

			c.SetDeadline(time.Now().Add(time.Second))

			if test.data != nil {
				if _, err := c.Write(test.data); err != nil {
					t.Fatal("writing length:", err)
				}
			}

			buf := make([]byte, 10)
			if _, err := c.Read(buf); err != io.EOF {
				t.Fatalf("reading TCP DNS response: got = %v, want = %v", err, io.EOF)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		validate func(got time.Time, now time.Time) error
	}{
		{
			"default",
			0,
			func(got time.Time, now time.Time) error {
				if now.After(got) {
					return errors.New("time in the past")
				}
				if got.After(now.Add(4 * time.Minute)) {
					return errors.New("time more than 4 minutes in the future")
				}
				return nil
			},
		},
		{
			"disabled",
			-1,
			func(got time.Time, now time.Time) error {
				if !got.IsZero() {
					return errors.New("time not zero")
				}
				return nil
			},
		},
		{
			"one hour",
			time.Hour,
			func(got time.Time, now time.Time) error {
				if now.Add(30 * time.Minute).After(got) {
					return errors.New("time less than 30 minutes in the future")
				}
				if got.After(now.Add(time.Hour + 30*time.Minute)) {
					return errors.New("time more than an hour and a half in the future")
				}
				return nil

			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s Server
			s.setTCPTimeout(test.timeout)
			got := s.tcpDeadline()
			now := time.Now()
			if err := test.validate(got, now); err != nil {
				t.Errorf("got deadline %v (current time is %v): %v", got, now, err)
			}
		})
	}
}
