// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnscache

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iangudger/dns/dnsmessage"
	"github.com/iangudger/dns/dnsresolver"
	"github.com/iangudger/dns/internal/resolvers"
)

type stubTime struct {
	time.Time
}

func newStubTime() *stubTime {
	return &stubTime{time.Now()}
}

func (st *stubTime) now() time.Time {
	return st.Time
}

func (st *stubTime) sleep(d time.Duration) {
	st.Time = st.Add(d)
}

func TestResolver(t *testing.T) {
	m := map[dnsmessage.Question]dnsmessage.Message{
		{dnsmessage.MustNewName("foo."), dnsmessage.TypeAAAA, dnsmessage.ClassINET}: {
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("foo."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("foo."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}},
			}},
		},
		{dnsmessage.MustNewName("foo.bar."), dnsmessage.TypeA, dnsmessage.ClassINET}: {
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("foo.bar."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("foo.bar."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 1}},
				},
				{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("foo.bar."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 0}},
				},
			},
		},
	}

	r, err := resolvers.NewStaticResolver(m, resolvers.NewErroringResolver())
	if err != nil {
		t.Fatal("NewStaticResolver(...) =", err)
	}

	ctx := context.Background()

	tests := []struct {
		name     string
		q        dnsmessage.Question
		want     dnsmessage.Message
		sleepDur time.Duration
	}{
		// These test cases are duplicated from the static resolver
		// tests to make sure caching resolver doesn't break any static
		// resolver tests.
		{
			name: "foo. TypeAAAA (sanity test for simple queries)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("foo."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("foo."),
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AAAAResource{
						AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
					},
				}},
			},
		},
		{
			name: "foo. TypeA (sanity test for simple queries)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("foo."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
			want: resolvers.ResolveError(dnsmessage.Question{
				Name:  dnsmessage.MustNewName("foo."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}, dnsmessage.RCodeNotImplemented, true /* recursionDesired */),
		},
		{
			name: "foo.bar. TypeA (sanity test for simple queries)",
			q:    dnsmessage.Question{Name: dnsmessage.MustNewName("foo.bar."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo.bar."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   10,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 0}},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   10,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 1}},
					},
				},
			},
		},

		// Tests related to actual caching resolver behavior.
		// This query should be served from the cache as we just
		// queried it above and should give us a record with ttl-1 as
		// the TTL for records served from cache immediately after
		// caching.
		{
			name:     "foo.bar. TypeA (test that responses served from cache will have a reduced TTL)",
			q:        dnsmessage.Question{Name: dnsmessage.MustNewName("foo.bar."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			sleepDur: time.Nanosecond,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo.bar."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   9,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 0}},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   9,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 1}},
					},
				},
			},
		},

		// This one should refetch from the underlying resolver with a
		// ttl of 10 seconds as the cache entry should have expired
		// after we sleep for 11 seconds as specified in the sleepDur
		// below.
		{
			name:     "foo.bar. TypeA (check that we re-fetch from underlying resolver after TTL duration has elapsed)",
			q:        dnsmessage.Question{Name: dnsmessage.MustNewName("foo.bar."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			sleepDur: 11 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo.bar."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   10,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 0}},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   10,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 1}},
					},
				},
			},
		},

		// This one should serve from the cache with a TTL of zero as
		// we are sleeping for 10 seconds and the TTL of record is 10.
		// Due to TTL being at a second precision, we should make sure
		// downstream doesn't cache our response, so we should respond
		// with a zero TTL.
		{
			name:     "foo.bar. TypeA (check that records with <= 1s TTL are served with 0s TTL)",
			q:        dnsmessage.Question{Name: dnsmessage.MustNewName("foo.bar."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			sleepDur: 10 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo.bar."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   0,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 0}},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("foo.bar."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   0,
						},
						Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 1}},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			st := newStubTime()

			// Create a caching resolver in front of the static
			// resolver.
			r, err := NewResolver(Config{EnableNegativeCaching: true, now: st.now}, r)
			if err != nil {
				t.Fatal("NewResolver(...) =", err)
			}

			got, ok := r.Resolve(ctx, test.q, true)
			if !ok {
				t.Fatal("first resolve did not return packet")
			}
			if test.sleepDur > 0 {
				st.sleep(test.sleepDur)
				got, ok = r.Resolve(ctx, test.q, true)
				if !ok {
					t.Fatal("second resolve did not return packet")
				}
			}

			sort.Slice(got.Answers, func(i, j int) bool {
				if test.q.Type == dnsmessage.TypeAAAA {
					a1 := got.Answers[i].Body.(*dnsmessage.AAAAResource)
					a2 := got.Answers[j].Body.(*dnsmessage.AAAAResource)
					return string(a1.AAAA[:]) < string(a2.AAAA[:])
				}
				a1 := got.Answers[i].Body.(*dnsmessage.AResource)
				a2 := got.Answers[j].Body.(*dnsmessage.AResource)
				return string(a1.A[:]) < string(a2.A[:])
			})

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got = %#v, want = %#v) ", &got, &test.want)
			}
		})
	}
}

// This resolver responds to all queries with one CNAME and two A records.
func testShuffleResolver() dnsresolver.Resolver {
	return dnsresolver.ResolverFunc(func(_ context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
		cname := "addr-" + question.Name.String()
		return dnsmessage.Message{
			Header: dnsmessage.Header{
				Response:         true,
				RecursionDesired: recursionDesired,
			},
			Questions: []dnsmessage.Question{question},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  dnsmessage.TypeCNAME,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.CNAMEResource{
						CNAME: dnsmessage.MustNewName(cname),
					},
				},
				{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AResource{
						A: [4]byte{127, 1, 1, 0},
					},
				},
				{
					Header: dnsmessage.ResourceHeader{
						Name:  question.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AResource{
						A: [4]byte{127, 1, 1, 1},
					},
				},
			},
		}, true
	})
}

// verifyShuffleRR verifys that the message has a CNAME followed by two A
// records, and returns the A record IP addresses (in string form) in order of
// their appearance in the message.
func verifyShuffleRR(msg dnsmessage.Message) (string, error) {
	if len(msg.Answers) != 3 {
		return "", fmt.Errorf("got %d answers, want 3", len(msg.Answers))
	}
	want := [3]dnsmessage.Type{dnsmessage.TypeCNAME, dnsmessage.TypeA, dnsmessage.TypeA}
	var ips []string
	for i, got := range msg.Answers {
		t := got.Header.Type
		if t != want[i] {
			return "", fmt.Errorf("answer %d: got %v, want %v", i, t, want[i])
		}
		if t == dnsmessage.TypeA {
			ips = append(ips, net.IP(got.Body.(*dnsmessage.AResource).A[:]).String())
		}
	}
	return strings.Join(ips, ", "), nil
}

func TestRRReordering(t *testing.T) {
	for _, mode := range []ReorderingMode{RandomReordering, RotationReordering} {
		t.Run(fmt.Sprint("reordering mode: ", mode), func(t *testing.T) {
			r, err := NewResolver(Config{
				Reordering: RandomReordering,
				rand:       rand.New(rand.NewSource(2)),
			}, testShuffleResolver())
			if err != nil {
				t.Fatal("NewResolver(...) =", err)
			}

			q := dnsmessage.Question{
				Name:  dnsmessage.MustNewName("foo.bar."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}
			// Cache miss (first response) should shuffle (swap) the A records,
			// based on the chosen random seed (above).
			ctx := context.Background()
			got1, ok := r.Resolve(ctx, q, true)
			if !ok {
				t.Fatal("got first r.Resolve(...) = _, false; want _, true")
			}
			ips1, err := verifyShuffleRR(got1)
			if err != nil {
				t.Error(err)
			}
			const shuffled1 = "127.1.1.1, 127.1.1.0"
			if ips1 != shuffled1 {
				t.Errorf("cache miss did not shuffle: got %q, want %q", ips1, shuffled1)
			}

			got2, ok := r.Resolve(ctx, q, true)
			if !ok {
				t.Fatal("got second r.Resolve(...) = _, false; want _, true")
			}
			ips2, err := verifyShuffleRR(got2)
			if err != nil {
				t.Error(err)
			}
			const shuffled2 = "127.1.1.0, 127.1.1.1"
			if ips2 != shuffled2 {
				t.Errorf("cache hit did not shuffle: got %q, want %q", ips2, shuffled2)
			}
		})
	}
}

func TestResolverNegativeCache(t *testing.T) {
	m := map[dnsmessage.Question]dnsmessage.Message{
		{dnsmessage.MustNewName("boo.baz."), dnsmessage.TypeAAAA, dnsmessage.ClassINET}: {
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("boo.baz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("boo.baz."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 2}},
			}},
		},
		{dnsmessage.MustNewName("hoo.faz."), dnsmessage.TypeAAAA, dnsmessage.ClassINET}: {
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("hoo.faz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("hoo.faz."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 2}},
			}},
			Authorities: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeSOA,
					Class: dnsmessage.ClassINET,
					TTL:   12,
				},
				Body: &dnsmessage.SOAResource{
					NS:      dnsmessage.MustNewName("hoo.faz."),
					Serial:  1,
					Refresh: 2,
					Retry:   3,
					Expire:  4,
					MinTTL:  10,
				},
			}},
		},
		{dnsmessage.MustNewName("foo.qux."), dnsmessage.TypeAAAA, dnsmessage.ClassINET}: {
			Questions: []dnsmessage.Question{{
				Name:  dnsmessage.MustNewName("foo.qux."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			}},
			Authorities: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeSOA,
					Class: dnsmessage.ClassINET,
					TTL:   12,
				},
				Body: &dnsmessage.SOAResource{
					NS:      dnsmessage.MustNewName("foo.qux."),
					Serial:  1,
					Refresh: 2,
					Retry:   3,
					Expire:  4,
					MinTTL:  20,
				},
			}},
		},
	}

	r := resolvers.NewErroringResolver()
	var err error
	r, err = resolvers.NewStaticResolver(
		m,
		getNXDomainResolver(r),
	)
	if err != nil {
		t.Fatal("NewStaticResolver(...) =", err)
	}

	ctx := context.Background()

	tests := []struct {
		name     string
		q        dnsmessage.Question
		want     dnsmessage.Message
		sleepDur time.Duration
	}{
		{
			name: "boo.baz. TypeAAAA (Test negative caching for NODATA case without SOA record. This will not be cached.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("boo.baz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 9 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("boo.baz."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("boo.baz."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 2}},
				}},
			},
		},
		{
			name: "hoo.faz. TypeAAAA (Test negative caching for NODATA case with SOA record. TTL should be 0 since we sleep for the TTL.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("hoo.faz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 10 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("hoo.faz."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("hoo.faz."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   0,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 2}},
				}},
				Authorities: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Type:  dnsmessage.TypeSOA,
						Class: dnsmessage.ClassINET,
						TTL:   0,
					},
					Body: &dnsmessage.SOAResource{
						NS:      dnsmessage.MustNewName("hoo.faz."),
						Serial:  1,
						Refresh: 2,
						Retry:   3,
						Expire:  4,
						MinTTL:  10,
					},
				}},
			},
		},
		{
			name: "hoo.faz. TypeAAAA (Test negative caching for NODATA case with SOA record. TTL should reduced 0 since we sleep for part of the TTL.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("hoo.faz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 5 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("hoo.faz."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("hoo.faz."),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   5,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 1, 1, 2}},
				}},
				Authorities: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Type:  dnsmessage.TypeSOA,
						Class: dnsmessage.ClassINET,
						TTL:   5,
					},
					Body: &dnsmessage.SOAResource{
						NS:      dnsmessage.MustNewName("hoo.faz."),
						Serial:  1,
						Refresh: 2,
						Retry:   3,
						Expire:  4,
						MinTTL:  10,
					},
				}},
			},
		},
		{
			name: "moo.naz. TypeAAAA (Test negative caching for NXDOMAIN case with SOA record. TTL should be 0 since we sleep for the TTL.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("moo.naz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 10 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeNameError,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("moo.naz."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Authorities: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Type:  dnsmessage.TypeSOA,
						Class: dnsmessage.ClassINET,
						TTL:   0,
					},
					Body: &dnsmessage.SOAResource{
						NS:      dnsmessage.MustNewName("moo.naz."),
						Serial:  1,
						Refresh: 2,
						Retry:   3,
						Expire:  4,
						MinTTL:  10,
					},
				}},
			},
		},
		{
			name: "moo.naz. TypeAAAA (Test negative caching for NXDOMAIN case with SOA record. TTL should be reduced since we sleep for part of the TTL.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("moo.naz."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 5 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					OpCode:             0,
					Authoritative:      false,
					Truncated:          false,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeNameError,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("moo.naz."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Authorities: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Type:  dnsmessage.TypeSOA,
						Class: dnsmessage.ClassINET,
						TTL:   5,
					},
					Body: &dnsmessage.SOAResource{
						NS:      dnsmessage.MustNewName("moo.naz."),
						Serial:  1,
						Refresh: 2,
						Retry:   3,
						Expire:  4,
						MinTTL:  10,
					},
				}},
			},
		},
		{
			name: "foo.qux. TypeAAAA (Test negative caching for r.TTL > r.SOA.MinTTL.)",
			q: dnsmessage.Question{
				Name:  dnsmessage.MustNewName("foo.qux."),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			},
			sleepDur: 5 * time.Second,
			want: dnsmessage.Message{
				Header: dnsmessage.Header{
					Response:           true,
					RecursionDesired:   true,
					RecursionAvailable: false,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("foo.qux."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
				Authorities: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Type:  dnsmessage.TypeSOA,
						Class: dnsmessage.ClassINET,
						TTL:   7,
					},
					Body: &dnsmessage.SOAResource{
						NS:      dnsmessage.MustNewName("foo.qux."),
						Serial:  1,
						Refresh: 2,
						Retry:   3,
						Expire:  4,
						MinTTL:  20,
					},
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			st := newStubTime()

			// Create a caching resolver in front of the static resolver.
			r, err := NewResolver(Config{EnableNegativeCaching: true, now: st.now}, r)
			if err != nil {
				t.Fatal("NewResolver(...) =", err)
			}

			got, ok := r.Resolve(ctx, test.q, true)
			if !ok {
				t.Fatal("first resolve did not return packet")
			}
			if test.sleepDur > 0 {
				st.sleep(test.sleepDur)
				got, ok = r.Resolve(ctx, test.q, true)
				if !ok {
					t.Fatal("second resolve did not return packet")
				}
			}

			sort.Slice(got.Answers, func(i, j int) bool {
				if test.q.Type == dnsmessage.TypeAAAA {
					a1 := got.Answers[i].Body.(*dnsmessage.AAAAResource)
					a2 := got.Answers[j].Body.(*dnsmessage.AAAAResource)
					return string(a1.AAAA[:]) < string(a2.AAAA[:])
				}
				a1 := got.Answers[i].Body.(*dnsmessage.AResource)
				a2 := got.Answers[j].Body.(*dnsmessage.AResource)
				return string(a1.A[:]) < string(a2.A[:])
			})

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got = %#v, want = %#v) ", &got, &test.want)
			}
		})
	}
}

func TestResolverNegativeCacheExpiry(t *testing.T) {
	r := resolvers.NewErroringResolver()
	var err error
	r, err = resolvers.NewStaticResolver(
		map[dnsmessage.Question]dnsmessage.Message{},
		getNXDomainResolver(r),
	)
	if err != nil {
		t.Fatal("NewStaticResolver(...) =", err)
	}

	ctx := context.Background()
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("moo.naz."),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}
	want := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeNameError,
		},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("moo.naz."),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Type: dnsmessage.TypeSOA,
				Class: dnsmessage.ClassINET,
				TTL:   2,
			},
			Body: &dnsmessage.SOAResource{
				NS:      dnsmessage.MustNewName("moo.naz."),
				Serial:  1,
				Refresh: 2,
				Retry:   3,
				Expire:  4,
				MinTTL:  10,
			},
		}},
	}

	st := newStubTime()

	r, err = NewResolver(Config{EnableNegativeCaching: true, now: st.now}, r)
	if err != nil {
		t.Fatal("NewResolver(...) =", err)
	}

	// This should result in RCodeNameError response for "moo.naz." being
	// cached.
	got, ok := r.Resolve(ctx, q, true)
	if !ok {
		t.Errorf("first resolve did not return packet")
	}

	st.sleep(8 * time.Second)

	// Retrieve from Cache.
	got, ok = r.Resolve(ctx, q, true)
	if !ok {
		t.Errorf("second resolve did not return packet")
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got = %#v, want = %#v) ", &got, &want)
	}

	// Sleeping again should expire the entry and fetch from
	// underlying resolver again.
	st.sleep(3 * time.Second)
	want = dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeNameError,
		},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("moo.naz."),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Type:  dnsmessage.TypeSOA,
				Class: dnsmessage.ClassINET,
				TTL:   12,
			},
			Body: &dnsmessage.SOAResource{
				NS:      dnsmessage.MustNewName("moo.naz."),
				Serial:  1,
				Refresh: 2,
				Retry:   3,
				Expire:  4,
				MinTTL:  10,
			},
		}},
	}

	// Retrieve from Cache
	got, ok = r.Resolve(ctx, q, true)
	if !ok {
		t.Errorf("second resolve did not return packet")
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got = %#v, want = %#v) ", &got, &want)
	}
}

func getNXDomainResolver(nested dnsresolver.Resolver) dnsresolver.ResolverFunc {
	return func(ctx context.Context, question dnsmessage.Question, recursionDesired bool) (dnsmessage.Message, bool) {
		if question.Name.String() != "moo.naz." {
			return nested.Resolve(ctx, question, recursionDesired)
		}
		return dnsmessage.Message{
			Header: dnsmessage.Header{
				Response:         true,
				RCode:            dnsmessage.RCodeNameError,
				RecursionDesired: recursionDesired,
			},
			Questions: []dnsmessage.Question{question},
			Authorities: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeSOA,
					Class: dnsmessage.ClassINET,
					TTL:   12,
				},
				Body: &dnsmessage.SOAResource{
					NS:      dnsmessage.MustNewName("moo.naz."),
					Serial:  1,
					Refresh: 2,
					Retry:   3,
					Expire:  4,
					MinTTL:  10,
				},
			}},
		}, true
	}
}

func TestCacheSize(t *testing.T) {
	var count uint16
	r, err := NewResolver(
		Config{MaxSize: 2},
		dnsresolver.ResolverFunc(func(_ context.Context, _ dnsmessage.Question, _ bool) (dnsmessage.Message, bool) {
			count++
			return dnsmessage.Message{
				Header: dnsmessage.Header{ID: count},
				Answers: []dnsmessage.Resource{{
					dnsmessage.ResourceHeader{TTL: 3600},
					&dnsmessage.AResource{},
				}},
			}, true
		}),
	)
	if err != nil {
		t.Fatal("NewResolver(...) =", err)
	}

	ctx := context.Background()

	q1 := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("moo.a."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	q2 := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("moo.b."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	q3 := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("moo.c."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	tests := []struct {
		name string
		q    dnsmessage.Question
		want uint16
	}{
		{
			"first question",
			q1,
			1,
		},
		{
			"first question again",
			q1,
			1,
		},
		{
			"second question",
			q2,
			2,
		},
		{
			"first question after second question",
			q1,
			1,
		},
		{
			"second question again",
			q2,
			2,
		},
		{
			"third question",
			q3,
			3,
		},
		{
			"second question after third question",
			q2,
			2,
		},
		{
			"third question again",
			q3,
			3,
		},
		{
			"first question after third question",
			q1,
			4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m, ok := r.Resolve(ctx, test.q, false)
			if !ok {
				t.Fatal("Resolve returned no answer")
			}
			if got := m.Header.ID; got != test.want {
				t.Errorf("got ID = %d, want = %d", got, test.want)
			}
		})
	}
}
