// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated with gvisor.dev/gvisor/pkg/ilist. DO NOT EDIT.

package dnscache

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type cacheListElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (cacheListElementMapper) linkerFor(elem *cacheEntry) *cacheEntry { return elem }

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//      for e := l.Front(); e != nil; e = e.Next() {
// 		// do something with e.
//      }
//
// +stateify savable
type cacheListList struct {
	head *cacheEntry
	tail *cacheEntry
}

// Reset resets list l to the empty state.
func (l *cacheListList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *cacheListList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *cacheListList) Front() *cacheEntry {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *cacheListList) Back() *cacheEntry {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *cacheListList) PushFront(e *cacheEntry) {
	cacheListElementMapper{}.linkerFor(e).SetNext(l.head)
	cacheListElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		cacheListElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *cacheListList) PushBack(e *cacheEntry) {
	cacheListElementMapper{}.linkerFor(e).SetNext(nil)
	cacheListElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		cacheListElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *cacheListList) PushBackList(m *cacheListList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		cacheListElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		cacheListElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *cacheListList) InsertAfter(b, e *cacheEntry) {
	a := cacheListElementMapper{}.linkerFor(b).Next()
	cacheListElementMapper{}.linkerFor(e).SetNext(a)
	cacheListElementMapper{}.linkerFor(e).SetPrev(b)
	cacheListElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		cacheListElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *cacheListList) InsertBefore(a, e *cacheEntry) {
	b := cacheListElementMapper{}.linkerFor(a).Prev()
	cacheListElementMapper{}.linkerFor(e).SetNext(a)
	cacheListElementMapper{}.linkerFor(e).SetPrev(b)
	cacheListElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		cacheListElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *cacheListList) Remove(e *cacheEntry) {
	prev := cacheListElementMapper{}.linkerFor(e).Prev()
	next := cacheListElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		cacheListElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		cacheListElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type cacheListEntry struct {
	next *cacheEntry
	prev *cacheEntry
}

// Next returns the entry that follows e in the list.
func (e *cacheListEntry) Next() *cacheEntry {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *cacheListEntry) Prev() *cacheEntry {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *cacheListEntry) SetNext(elem *cacheEntry) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *cacheListEntry) SetPrev(elem *cacheEntry) {
	e.prev = elem
}
