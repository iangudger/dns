// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package resolvers provides simple DNS resolvers useful for testing.
package resolvers

import (
	"context"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
)

// NewErroringResolver creates a catchall Resolver which responds to all
// requests with an error.
func NewErroringResolver() dnsresolver.Resolver {
	return dnsresolver.ResolverFunc(func(_ context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
		return ResolveError(question, dnsmessage.RCodeNotImplemented, recursionDesired), true
	})
}

// ResolveError builds an error DNS response.
func ResolveError(question dnsmessage.Question, rcode dnsmessage.RCode, recursionDesired bool) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RCode:              rcode,
			RecursionDesired:   recursionDesired,
			RecursionAvailable: recursionDesired,
		},
		Questions: []dnsmessage.Question{question},
	}
}

const nameLen = 255

// normalizeName converts a name to lower case.
//
// TODO(iangudger): Add proper case insensitivity to the Name type.
func normalizeName(n dnsmessage.Name) (dnsmessage.Name, error) {
	b, err := n.Bytes(make([]byte, 0, nameLen))
	if err != nil {
		return dnsmessage.Name{}, err
	}
	for i := range b {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 0x20
		}
		b[i] = c
	}
	return dnsmessage.NewNameBytes(b)
}

// NewStaticResolver creates a new DNS resolver that retrieves answers from the
// provided static lookup table m.
//
// Questions which can't be answered with the static lookup table will be
// delegated to the nested Resolver, which must not be nil.
func NewStaticResolver(mapping map[dnsmessage.Question]dnsmessage.Message, nested dnsresolver.Resolver) (dnsresolver.Resolver, error) {
	m := map[dnsmessage.Question]dnsmessage.Message{}
	for q, r := range mapping {
		var err error
		q.Name, err = normalizeName(q.Name)
		if err != nil {
			return nil, err
		}
		m[q] = r
	}
	return dnsresolver.ResolverFunc(func(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
		nq := question

		n, err := normalizeName(nq.Name)
		if err != nil {
			// We can't handle this name.
			return nested.Resolve(ctx, question, recursionDesired)
		}
		nq.Name = n

		r, ok := m[nq]
		if !ok {
			return nested.Resolve(ctx, question, recursionDesired)
		}
		return dnsmessage.Message{
			Header: dnsmessage.Header{
				Response:           true,
				Authoritative:      r.Authoritative,
				RecursionDesired:   recursionDesired,
				RecursionAvailable: r.RecursionAvailable,
			},
			Questions: []dnsmessage.Question{question},

			Answers:     append([]dnsmessage.Resource(nil), r.Answers...),
			Authorities: append([]dnsmessage.Resource(nil), r.Authorities...),
			Additionals: append([]dnsmessage.Resource(nil), r.Additionals...),
		}, true
	}), nil
}
