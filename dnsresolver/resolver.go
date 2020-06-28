// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsresolver provides basic DNS question answering functionality.
package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/iangudger/dns/dnsmessage"
)

var (
	// ErrResponseTypeRequest indicates that a received DNS packet is a
	// response instead of a request as expected.
	ErrResponseTypeRequest = errors.New("DNS request has type response")

	// ErrNoQuestions indicates that a received DNS packet does not contain
	// any questions.
	ErrNoQuestions = errors.New("DNS request does not contain questions")

	// ErrNoResponse indicates that the DNS resolver did not return a
	// response.
	ErrNoResponse = errors.New("DNS resolver did not return a response")

	// ErrInvalidRCode indicates that the provided DNS Response Code is not
	// a valid value.
	ErrInvalidRCode = errors.New("invalid DNS Response Code")

	// ErrTruncatedResponseTooBig indicates that packing the DNS response
	// message into a response packet failed because the message couldn't
	// be reduced to fit within the size constraints.
	ErrTruncatedResponseTooBig = errors.New("packing DNS response packet: response too big")
)

type sourceContextKey struct{}

var (
	// SourceContextKey is a context key. It can be used in Resolver and
	// PacketResolver implementations. The associated value is of type
	// *net.UDPAddr from a UDP server and *net.TCPAddr from a TCP server.
	// If no source is available (e.g. a request originating in the same
	// binary), SourceContextKey is omitted.
	SourceContextKey = &sourceContextKey{}
)

// A PacketResolver responds to binary DNS packet requests with binary DNS
// packet responses.
type PacketResolver interface {
	// ResolvePacket creates a binary DNS packet to respond to a binary DNS
	// packet request and appends it to buf, using append semantics. If buf
	// is nil, a new buffer will be allocated.
	//
	// ctx includes a SourceContextKey, if applicable.
	//
	// maxPacketLength is the maximum final packet length to be appended to
	// buf. Intermediate packets may be appended, but the final returned
	// slice must be no more than maxPacketLength bytes longer than buf.
	ResolvePacket(ctx context.Context, packet []byte, maxPacketLength int, buf []byte) ([]byte, error)
}

// PacketResolverFunc implements PacketResolver with a function.
type PacketResolverFunc func(ctx context.Context, packet []byte, maxPacketLength int, buf []byte) ([]byte, error)

// ResolvePacket implements PacketResolver.ResolvePacket.
func (f PacketResolverFunc) ResolvePacket(ctx context.Context, packet []byte, maxPacketLength int, buf []byte) ([]byte, error) {
	return f(ctx, packet, maxPacketLength, buf)
}

// A Resolver answers DNS Questions.
type Resolver interface {
	// Resolve creates a Message in response to a Question.
	//
	// If no message is to be returned, Resolve returns false.
	//
	// ctx includes a SourceContextKey, if applicable.
	//
	// recursionDesired indicates that question should be resolved
	// recursively.
	Resolve(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool)
}

// ResolverFunc implements Resolver with a function.
type ResolverFunc func(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool)

// Resolve implements Resolver.Resolve.
func (f ResolverFunc) Resolve(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
	return f(ctx, question, recursionDesired)
}

// PacketResolverConfig contains optional configuration options for the default PacketResolver.
type PacketResolverConfig struct {
	_ struct{} // Prevent positional initialization.
}

// NewPacketResolver creates a DNS resolver that responds to raw DNS packets.
//
// The Resolver must not be nil.
func NewPacketResolver(config PacketResolverConfig, res Resolver) (PacketResolver, error) {
	return PacketResolverFunc(func(ctx context.Context, packet []byte, maxPacketLength int, buf []byte) ([]byte, error) {
		// Check for expired context.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var p dnsmessage.Parser
		h, err := p.Start(packet)
		if err != nil {
			return nil, fmt.Errorf("parsing DNS packet: %v", err)
		}

		if h.Response {
			return nil, ErrResponseTypeRequest
		}

		q, err := p.Question()
		if err != nil {
			return respondError(h, dnsmessage.RCodeFormatError)
		}

		// Check for a malformed packet.
		if err := p.SkipQuestion(); err == nil {
			// We don't support requests with multiple questions.
			//
			// See http://maradns.samiam.org/multiple.qdcount.html
			return respondError(h, dnsmessage.RCodeNotImplemented)
		} else if err != dnsmessage.ErrSectionDone {
			return respondError(h, dnsmessage.RCodeFormatError)
		}

		resp, ok := res.Resolve(ctx, q, h.RecursionDesired)
		if !ok {
			return nil, ErrNoResponse
		}

		// Copy the message ID so the requester knows which request this
		// is a response for.
		resp.Header.ID = h.ID

		respBuf, err := resp.AppendPack(buf)
		if err != nil {
			return nil, fmt.Errorf("packing DNS response packet: %v", err)
		}

		// TODO(iangudger): Add EDNS0 support to allow longer
		// packets.
		if maxPacketLength == 0 || len(respBuf) <= maxPacketLength {
			return respBuf, nil
		}

		// The whole response is too big. Return a truncated packet.
		resp.Header.Truncated = true
		resp.Additionals = nil
		resp.Authorities = nil
		resp.Answers = nil

		respBuf, err = resp.AppendPack(buf)
		if err != nil {
			return nil, fmt.Errorf("packing DNS response packet: %v", err)
		}

		if len(respBuf) > maxPacketLength {
			// This should never happen. The response is
			// still too big even though we stripped out all
			// of the new fields.
			return nil, ErrTruncatedResponseTooBig
		}

		return respBuf, nil
	}), nil
}

func respondError(h dnsmessage.Header, rcode dnsmessage.RCode) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               h.ID,
			Response:         true,
			RCode:            rcode,
			RecursionDesired: h.RecursionDesired,
		},
	}
	respBuf, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS response packet: %v", err)
	}
	return respBuf, nil
}

// Stats collects counts of various DNS-related events that have
// occurred for a particular DNS Resolver.
//
// All methods are safe for concurrent use.
type Stats struct {
	questions uint64
	rejected  uint64
	errors    uint64
	deferrals uint64
	answers   uint64
}

// Questions returns the number of DNS questions a resolver has received.
func (rs *Stats) Questions() uint64 {
	return atomic.LoadUint64(&rs.questions)
}

// AddQuestion records that a resolver has received a DNS question.
//
// If rs is nil, AddQuestion is a no-op.
func (rs *Stats) AddQuestion() {
	if rs == nil {
		return
	}
	atomic.AddUint64(&rs.questions, 1)
}

// Rejected returns the number of requests a resolver has rejected.
func (rs *Stats) Rejected() uint64 {
	return atomic.LoadUint64(&rs.rejected)
}

// AddRejected records that a resolver has rejected a request.
//
// If rs is nil, AddRejected is a no-op.
func (rs *Stats) AddRejected() {
	if rs == nil {
		return
	}
	atomic.AddUint64(&rs.rejected, 1)
}

// Errors returns the number of errors a resolver has encountered.
func (rs *Stats) Errors() uint64 {
	return atomic.LoadUint64(&rs.errors)
}

// AddError records that a resolver has encountered an error.
//
// If rs is nil, AddError is a no-op.
func (rs *Stats) AddError() {
	if rs == nil {
		return
	}
	atomic.AddUint64(&rs.errors, 1)
}

// Deferrals returns the number of times the resolver has deferred to a nested
// resolver.
func (rs *Stats) Deferrals() uint64 {
	return atomic.LoadUint64(&rs.deferrals)
}

// AddDeferral records that a resolver has deferred to a nested resolver.
//
// If rs is nil, AddDeferral is a no-op.
func (rs *Stats) AddDeferral() {
	if rs == nil {
		return
	}
	atomic.AddUint64(&rs.deferrals, 1)
}

// Answers returns the number of DNS questions a resolver has answered.
func (rs *Stats) Answers() uint64 {
	return atomic.LoadUint64(&rs.answers)
}

// AddAnswer records that a resolver has answered a DNS question.
//
// If rs is nil, AddAnswer is a no-op.
func (rs *Stats) AddAnswer() {
	if rs == nil {
		return
	}
	atomic.AddUint64(&rs.answers, 1)
}
