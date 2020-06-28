# Modular DNS server for Go

Based on golang.org/x/net/dns, a very high performance DNS wire format library.

## Goals
* Safe. Should not [crash on bad input](https://blog.cloudflare.com/dns-parser-meet-go-fuzzer/). This library has been fuzzed, but if you find any crash bugs, please report them.
* Modular. Should allow arbitrary DNS implementations.
* Fast. Minimize allocations.
* Clean code. Show follow the [Go style guide](https://github.com/golang/go/wiki/CodeReviewComments).
