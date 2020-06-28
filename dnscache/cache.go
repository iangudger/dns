// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnscache provides a basic DNS cache.
//
// The cache is currently case-sensitive. This may change in the future.
//
// The caching behavior of DNS resolvers is spread across multiple RFCs on how
// the TTL on resource records should be treated. Some required/useful reading
// to understand caching in DNS servers includes the following documents.
//
//  - https://www.ietf.org/rfc/rfc1034.txt
//  - https://www.ietf.org/rfc/rfc1035.txt
//  - https://www.ietf.org/rfc/rfc2308.txt (negative caching)
//  - https://tools.ietf.org/html/rfc2181#section-7 (SOA TTLs)
//  - https://tools.ietf.org/html/rfc2181#section-8
//  - https://tools.ietf.org/html/rfc1123#section-6.1.2.1
//  - https://00f.net/2011/11/17/how-long-does-a-dns-ttl-last/
//    (nice article on behavior of various caching DNS servers)
package dnscache

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
)

const (
	defaultMaxTTL = 3600 // in seconds.
)

// A cacheKey contains the arguments for the resolver.
type cacheKey struct {
	question         dnsmessage.Question
	recursionDesired bool
}

// A cacheEntry is an entry in the DNS cache, it stores the actual DNS
// response, an expiration time and the creation time of the entry.
type cacheEntry struct {
	cacheListEntry

	// key is the key associated with this entry.
	key cacheKey

	// msg is the cached DNS response.
	msg dnsmessage.Message

	// negative indicates that this is a negative cache entry.
	negative bool

	// expires indicates the time after which this response must not be
	// returned.
	expires time.Time

	// created is the time when this entry was cached. This is used to
	// update TTLs in cached Resources before responding to a query.
	created time.Time
}

// A cachingResolver caches successful DNS responses.
type cachingResolver struct {
	// config contains configuration options.
	config Config

	// mu protects m and l below.
	mu sync.Mutex

	// m is the cache used to store DNS responses.
	m map[cacheKey]*cacheEntry

	// l is an LRU queue.
	l cacheListList

	// nested is the nested resolver to which we defer all queries which
	// cannot be served by the cache.
	nested dnsresolver.Resolver
}

// adjustTTL deducts elapsed from the TTL of each Resource. In case where for a
// given Resource elapsed > TTL, it will set the corresponding TTL to zero.
func adjustTTL(rs []dnsmessage.Resource, elapsed time.Duration, negative bool) {
	for i := range rs {
		r := &rs[i]
		ttlSec := r.Header.TTL

		// From RFC 2308, section 5:
		// When the authoritative server creates [the SOA] record its
		// TTL is taken from the minimum of the SOA.MINIMUM field and
		// SOA's TTL. This TTL decrements in a similar manner to a
		// normal cached answer...
		if negative {
			if soa, ok := r.Body.(*dnsmessage.SOAResource); ok {
				if ttlSec > soa.MinTTL {
					ttlSec = soa.MinTTL
				}
			}
		}

		ttl := time.Duration(ttlSec) * time.Second
		newTTL := ttl - elapsed
		if newTTL < 0 {
			newTTL = 0
		}
		r.Header.TTL = uint32(newTTL / time.Second)
	}
}

// shuffleRecords shuffles the contents of rr at the positions in the array
// indicated in pos.
func shuffleRecords(rr []dnsmessage.Resource, pos []int, rnd *rand.Rand) {
	if len(pos) <= 1 {
		return
	}
	rnd.Shuffle(len(pos), func(i, j int) {
		rr[pos[i]], rr[pos[j]] = rr[pos[j]], rr[pos[i]]
	})
}

// rotateRecords rotates the contents of rr at the positions in the array
// indicated in pos.
func rotateRecords(rr []dnsmessage.Resource, pos []int, _ *rand.Rand) {
	if len(pos) <= 1 {
		return
	}
	rr0 := rr[pos[0]]
	for i := 0; i < len(pos)-1; i++ {
		rr[pos[i]] = rr[pos[i+1]]
	}
	rr[pos[len(pos)-1]] = rr0
}

// reorderMsg reorders the A, AAAA, MX, and NS records within msg using f. We
// reorder to ensure that each entry has an equal chance of being the first one
// returned.
func reorderMsg(msg *dnsmessage.Message, f func([]dnsmessage.Resource, []int, *rand.Rand), rnd *rand.Rand) {
	if msg == nil || len(msg.Answers) <= 1 {
		return
	}
	var (
		off      = len(msg.Answers)
		pos      = make([]int, 4*off)
		typeA    int
		typeAAAA int
		typeMX   int
		typeNS   int
	)
	for i, r := range msg.Answers {
		switch r.Header.Type {
		case dnsmessage.TypeA:
			pos[typeA] = i
			typeA++
		case dnsmessage.TypeAAAA:
			pos[off+typeAAAA] = i
			typeAAAA++
		case dnsmessage.TypeMX:
			pos[2*off+typeMX] = i
			typeMX++
		case dnsmessage.TypeNS:
			pos[3*off+typeNS] = i
			typeNS++
		}
	}
	f(msg.Answers, pos[:typeA], rnd)
	f(msg.Answers, pos[off:off+typeAAAA], rnd)
	f(msg.Answers, pos[2*off:2*off+typeMX], rnd)
	f(msg.Answers, pos[3*off:3*off+typeNS], rnd)
}

// lookup checks the cache for a matching cached entry. It adjusts the TTLs of
// the cached records.
func (c *cachingResolver) lookup(question dnsmessage.Question, recursionDesired bool) (msg dnsmessage.Message, ok bool) {
	c.mu.Lock()
	key := cacheKey{question, recursionDesired}
	e, ok := c.m[key]
	if !ok {
		c.mu.Unlock()
		return dnsmessage.Message{}, false
	}

	now := c.config.now()
	if now.After(e.expires) {
		delete(c.m, key)
		c.l.Remove(e)
		c.mu.Unlock()
		return dnsmessage.Message{}, false
	}

	// Move the entry to the front of LRU queue.
	c.l.Remove(e)
	c.l.PushFront(e)

	// Compute elapsed while holding entry lock.
	elapsed := now.Sub(e.created)

	if c.config.Reordering == RotationReordering {
		// Rotate the A, AAAA, MX and NS records so every IP address
		// has an equal chance of appearing first within the lists of
		// records of those types.
		reorderMsg(&e.msg, rotateRecords, c.config.rand)
	}

	// Make copies of the Resources as we are modifying them.
	m := dnsmessage.Message{
		Header:      e.msg.Header,
		Questions:   []dnsmessage.Question{question},
		Answers:     append([]dnsmessage.Resource(nil), e.msg.Answers...),
		Authorities: append([]dnsmessage.Resource(nil), e.msg.Authorities...),
		Additionals: append([]dnsmessage.Resource(nil), e.msg.Additionals...),
	}
	c.mu.Unlock()

	if c.config.Reordering == RandomReordering {
		reorderMsg(&m, shuffleRecords, c.config.rand)
	}

	// Adjust the Resource TTLs.
	adjustTTL(m.Answers, elapsed, false)
	adjustTTL(m.Authorities, elapsed, e.negative)
	adjustTTL(m.Additionals, elapsed, false)
	return m, true
}

// minTTL returns the minimum of prevMinTTL and the TTLs in each Resource.
func minTTL(rs []dnsmessage.Resource, prevMinTTL uint32) uint32 {
	minTTL := prevMinTTL
	for _, r := range rs {
		if r.Header.TTL < minTTL {
			minTTL = r.Header.TTL
		}
	}
	return minTTL
}

// putResponse stores an entry in the cache.
func (c *cachingResolver) putResponse(question dnsmessage.Question, recursionDesired bool, msg dnsmessage.Message) {
	if len(msg.Answers) == 0 && len(msg.Authorities) == 0 && len(msg.Additionals) == 0 {
		// Do not cache the response if there are no Resources.
		return
	}

	// Compute the minimum TTL from the returned RRs.
	ttl := minTTL(msg.Answers, math.MaxUint32)
	ttl = minTTL(msg.Authorities, ttl)
	ttl = minTTL(msg.Additionals, ttl)
	if ttl == 0 {
		// Do not cache the response.
		return
	}

	if ttl > c.config.MaxTTL {
		ttl = c.config.MaxTTL
	}
	c.put(question, recursionDesired, msg, ttl, false /* negative */)
}

// putNegativeResponse stores a negative DNS response in the cache.
func (c *cachingResolver) putNegativeResponse(question dnsmessage.Question, recursionDesired bool, msg dnsmessage.Message) {
	ttl := uint32(0)
	// From RFC 2308, section 3:
	// The TTL of this record is set from the minimum
	// of the MINIMUM field of the SOA record and the TTL of
	// the SOA itself.
	for _, rr := range msg.Authorities {
		if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
			ttl = rr.Header.TTL
			if ttl > soa.MinTTL {
				ttl = soa.MinTTL
			}
			break
		}
	}
	if ttl == 0 {
		// Do not cache negative responses when either the TTL is 0
		// (uncacheable) or the TTL cannot be retrieved from an SOA
		// record (RFC 2308, section 5).
		return
	}

	if ttl > c.config.MaxTTL {
		ttl = c.config.MaxTTL
	}

	// From RFC 2308, section 5:
	// As with caching positive responses it is sensible for a resolver to
	// limit for how long it will cache a negative response as the protocol
	// supports caching for up to 68 years.  Such a limit should not be
	// greater than that applied to positive answers and preferably be
	// tunable.  Values of one to three hours have been found to work well
	// and would make sensible a default.  Values exceeding one day have
	// been found to be problematic.
	c.put(question, recursionDesired, msg, ttl, true /* negative */)
}

// put stores an entry in the cache.
//
// negative means that the entry is a negative cache entry.
func (c *cachingResolver) put(question dnsmessage.Question, recursionDesired bool, msg dnsmessage.Message, ttl uint32, negative bool) {
	// Make copies of the Resources to store in cache as we don't want a
	// concurrent request for the same Question reading them while they
	// are being packed by the goroutine that put them in the cache.
	msg.Answers = append([]dnsmessage.Resource(nil), msg.Answers...)
	msg.Authorities = append([]dnsmessage.Resource(nil), msg.Authorities...)
	msg.Additionals = append([]dnsmessage.Resource(nil), msg.Additionals...)

	// Cache the copy of the response.
	c.mu.Lock()
	now := c.config.now()
	k := cacheKey{question, recursionDesired}
	e := cacheEntry{
		key:      k,
		msg:      msg,
		expires:  now.Add(time.Duration(ttl) * time.Second),
		created:  now,
		negative: negative,
	}
	c.m[k] = &e
	c.l.PushFront(&e)

	// Evict an old entry if needed.
	if c.config.MaxSize > 0 && len(c.m) > c.config.MaxSize {
		evict := c.l.Back()
		c.l.Remove(evict)
		delete(c.m, evict.key)
	}

	c.mu.Unlock()
}

// Resolve implements dnsresolver.Resolver.Resolve.
func (c *cachingResolver) Resolve(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
	c.config.Stats.AddQuestion()

	if msg, ok := c.lookup(question, recursionDesired); ok {
		c.config.Stats.AddAnswer()
		return msg, true
	}

	msg, ok := c.nested.Resolve(ctx, question, recursionDesired)
	c.config.Stats.AddDeferral()
	if !ok {
		return dnsmessage.Message{}, false
	}

	if c.config.Reordering != NoReordering {
		reorderMsg(&msg, shuffleRecords, c.config.rand)
	}

	if c.config.EnableNegativeCaching && isCacheableNegativeResponse(question, msg) {
		c.putNegativeResponse(question, recursionDesired, msg)
	} else if msg.Header.RCode == dnsmessage.RCodeSuccess {
		c.putResponse(question, recursionDesired, msg)
	}

	return msg, true
}

// ReorderingMode specifies how answer records should be reordered.
type ReorderingMode uint8

const (
	// NoReordering indicates that answer records are not reordered.
	NoReordering ReorderingMode = iota

	// RandomReordering indicates that answer records are always
	// randomized.
	RandomReordering

	// RotationReordering indicates that answer records are
	// initially randomized and then rotates on each access.
	RotationReordering

	// invalidReordering is one more than the maximum reordering value.
	invalidReordering
)

// Config contains optional configuration options for the
// resolver.
type Config struct {
	Reordering ReorderingMode

	// EnableNegativeCaching when true causes resolver to cache negative
	// DNS responses in accordance to RFC 2308.
	EnableNegativeCaching bool

	// MaxTTL is the maximum amount of time (in seconds) that records
	// should be cached.
	//
	// If zero, a sensible default will be used.
	//
	// According to RFC 2308, section 5:
	// "Values of one to three hours have been found to work well ... [and]
	// values exceeding one day have been found to be problematic.""
	MaxTTL uint32

	// MaxSize is the maximum number of responses to cache.
	//
	// Cache is infinite if not positive.
	MaxSize int

	// Stats optionally records statistics about resolver operation.
	Stats *dnsresolver.Stats

	// now returns the current time. Useful for testing.
	now func() time.Time

	// rand provides random numbers. Useful for testing.
	rand *rand.Rand

	// empty prevents positional initialization.
	empty struct{}
}

var ErrInvalidReorderingMode = errors.New("invalid reordering mode")

// NewResolver creates a new DNS resolver that caches responses from the
// nested resolver.
func NewResolver(config Config, nested dnsresolver.Resolver) (dnsresolver.Resolver, error) {
	if config.MaxTTL == 0 {
		config.MaxTTL = defaultMaxTTL
	}
	if config.now == nil {
		config.now = time.Now
	}
	if config.rand == nil {
		config.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if config.Reordering >= invalidReordering {
		return nil, ErrInvalidReorderingMode
	}
	return &cachingResolver{
		config: config,
		m:      make(map[cacheKey]*cacheEntry),
		nested: nested,
	}, nil
}

// Check if a negative response should be cache in accordance to
// RFC 2308, section 2.
func isCacheableNegativeResponse(question dnsmessage.Question, msg dnsmessage.Message) bool {
	switch msg.Header.RCode {
	case dnsmessage.RCodeSuccess:
		// Check for NODATA.
		for _, rr := range msg.Answers {
			if rr.Header.Type == question.Type {
				return false
			}
		}
		return true
	case dnsmessage.RCodeNameError:
		return true
	default:
		return false
	}
}
