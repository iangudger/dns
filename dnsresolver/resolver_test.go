// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsresolver_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
	"github.com/iangudger/dns/internal/resolvers"
)

func TestResolveBadPacket(t *testing.T) {
	pr, err := dnsresolver.NewPacketResolver(
		dnsresolver.PacketResolverConfig{},
		resolvers.NewErroringResolver(),
	)
	if err != nil {
		t.Fatal("NewPacketResolver(...) = _,", err)
	}
	resp, err := pr.ResolvePacket(context.Background(), nil, 0, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "parsing DNS packet") || resp != nil {
		t.Errorf("got pr.ResolvePacket(nil, 0) = %#v, %v, want = %#v, parsing DNS packet: ...", resp, err, []byte(nil))
	}
}

func TestNewPacketResolver(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")

	tests := []struct {
		name string
		in   dnsmessage.Message
		resp dnsmessage.Message
	}{
		{
			name: "empty",
			in:   dnsmessage.Message{},
			resp: dnsmessage.Message{
				Header:      dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeFormatError},
				Questions:   []dnsmessage.Question{},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
		{
			name: "one question",
			in:   dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name}}},
			resp: dnsmessage.Message{
				Header:      dnsmessage.Header{Response: true},
				Questions:   []dnsmessage.Question{{Name: name}},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
		{
			name: "two questions",
			in:   dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name}, {Name: name}}},
			resp: dnsmessage.Message{
				Header:      dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNotImplemented},
				Questions:   []dnsmessage.Question{},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
	}

	pr, err := dnsresolver.NewPacketResolver(
		dnsresolver.PacketResolverConfig{},
		dnsresolver.ResolverFunc(func(_ context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
			return resolvers.ResolveError(question, 0, recursionDesired), true
		}),
	)
	if err != nil {
		t.Fatal("NewPacketResolver(...) = _,", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := test.in.Pack()
			if err != nil {
				t.Fatal("test.in.Pack() =", err)
			}
			resp, err := pr.ResolvePacket(context.Background(), req, 0, nil)
			if err != nil {
				t.Fatal("pr.ResolvePacket(...) = _,", err)
			}
			var got dnsmessage.Message
			if err := got.Unpack(resp); err != nil {
				t.Fatalf("got.Unpack(%v) = %v", resp, err)
			}
			if !reflect.DeepEqual(got, test.resp) {
				t.Fatalf("got from r.ResolvePacket:\n%#v\n\nwant:\n%#v", got, test.resp)
			}
		})
	}
}

func TestTruncation(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")

	testMsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:         true,
			Authoritative:    true,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			},
		},
		Authorities: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 3}},
			},
		},
	}

	tests := []struct {
		name      string
		err       error
		truncated bool
		msg       dnsmessage.Message
	}{
		{
			"full",
			nil,
			false, // truncated
			testMsg,
		},
		{
			"Additionals",
			nil,  // err
			true, // truncated
			dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:         true,
					Truncated:        true,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					},
				},
				Authorities: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}},
					},
				},
				Additionals: []dnsmessage.Resource{},
			},
		},
		{
			"Authorities",
			nil,  // err
			true, // truncated
			dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:         true,
					Truncated:        true,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					},
				},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
		{
			"Answers",
			nil,  // err
			true, // truncated
			dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:         true,
					Truncated:        true,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
		{
			"Questions",
			dnsresolver.ErrTruncatedResponseTooBig,
			false, // truncated
			dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:         true,
					Truncated:        true,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions:   []dnsmessage.Question{},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			},
		},
	}

	r, err := resolvers.NewStaticResolver(
		map[dnsmessage.Question]dnsmessage.Message{
			{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}: testMsg,
		},
		resolvers.NewErroringResolver(),
	)
	if err != nil {
		t.Fatal("NewStaticResolver(...) = _,", err)
	}

	pr, err := dnsresolver.NewPacketResolver(dnsresolver.PacketResolverConfig{}, r)
	if err != nil {
		t.Fatal("NewPacketResolver(...) = _,", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := dnsmessage.Message{
				Header: dnsmessage.Header{Authoritative: true, RecursionDesired: true},
				Questions: []dnsmessage.Question{{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
			}

			reqBuf, err := req.Pack()
			if err != nil {
				t.Fatal("req.Pack() = _,", err)
			}

			// Determine the size we should request.
			buf, err := test.msg.Pack()
			if err != nil {
				t.Fatal("test.msg.Pack() = _,", err)
			}
			maxLen := len(buf)

			resBuf, err := pr.ResolvePacket(context.Background(), reqBuf, maxLen, nil)
			if err != test.err {
				t.Fatalf("got pr.ResolvePacket(...) = _, %v, want = _, %v", err, test.err)
			}
			if test.err != nil {
				return
			}

			var res dnsmessage.Message
			if err := res.Unpack(resBuf); err != nil {
				t.Fatal("res.Unpack() =", err)
			}

			want := dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:         true,
					Truncated:        true,
					Authoritative:    true,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
				Answers:     []dnsmessage.Resource{},
				Authorities: []dnsmessage.Resource{},
				Additionals: []dnsmessage.Resource{},
			}

			// If the message shouldn't be truncated, expect the original.
			if !test.truncated {
				want = testMsg
			}

			if !reflect.DeepEqual(res, want) {
				t.Errorf("got response:\n%#v\n\nwant:\n%#v", &res, &want)
			}
		})
	}
}

func TestStaticResolver(t *testing.T) {
	r, err := resolvers.NewStaticResolver(
		map[dnsmessage.Question]dnsmessage.Message{},
		resolvers.NewErroringResolver(),
	)
	if err != nil {
		t.Fatal("NewStaticResolver(...) =", err)
	}

	want := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RCode:              dnsmessage.RCodeNotImplemented,
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{{}},
	}
	if got, ok := r.Resolve(context.Background(), dnsmessage.Question{}, true); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("got r.Resolve(dnsmessage.Question{}, true) = %#v, %t, want = %#v, %t", got, ok, want, true)
	}
}

func TestPacketResolverResponseTypeRequest(t *testing.T) {
	pr, err := dnsresolver.NewPacketResolver(
		dnsresolver.PacketResolverConfig{},
		resolvers.NewErroringResolver(),
	)
	if err != nil {
		t.Fatal("NewPacketResolver(...) = _,", err)
	}

	req := dnsmessage.Message{Header: dnsmessage.Header{Response: true}}
	buf, err := req.Pack()
	if err != nil {
		t.Fatal("req.Pack() =", err)
	}
	resp, err := pr.ResolvePacket(context.Background(), buf, 0, nil)
	if err != dnsresolver.ErrResponseTypeRequest || resp != nil {
		t.Errorf("got pr.ResolvePacket(nil, 0) = %#v, %v, want = %#v, %v", resp, err, []byte(nil), dnsresolver.ErrResponseTypeRequest)
	}
}
