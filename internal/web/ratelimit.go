package web

import (
	"container/list"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultLimiterSize is how many client addresses the limiter keeps; past
// it, the address seen longest ago is forgotten.
const DefaultLimiterSize = 100_000

// Limiter limits failed attempts per client with a token bucket: each
// client may fail burst times and earns one more failure every interval, up
// to burst. A client with no failures left is blocked until it earns one.
//
// A client is its address (an IPv6 address by its /64, which one host
// usually holds whole), found by ClientIP. The limiter keeps the size
// clients seen last, in least-recently-used order, so a failure costs the
// same however many clients there are.
type Limiter struct {
	now      func() time.Time
	buckets  map[string]*list.Element
	order    *list.List // of *bucket, most recently used first
	trusted  []netip.Prefix
	interval time.Duration
	burst    float64
	size     int
	mu       sync.Mutex
}

type bucket struct {
	last   time.Time
	key    string
	tokens float64
}

// NewLimiter returns a limiter of burst failures, refilled one every
// interval, that keeps size clients and reads the client address behind
// the trusted proxies.
func NewLimiter(burst int, interval time.Duration, size int, trusted []netip.Prefix) *Limiter {
	return &Limiter{
		now:      time.Now,
		buckets:  make(map[string]*list.Element),
		order:    list.New(),
		trusted:  trusted,
		interval: interval,
		burst:    float64(burst),
		size:     size,
	}
}

// SetClock replaces the limiter's clock, for tests.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Blocked reports whether the client of r has no failures left.
func (l *Limiter) Blocked(r *http.Request) bool {
	return l.BlockedKey(ClientKey(ClientIP(r, l.trusted)))
}

// BlockedKey is Blocked for the client key.
func (l *Limiter) BlockedKey(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.buckets[key]
	return e != nil && l.refilled(e.Value.(*bucket), l.now()) < 1
}

// Fail counts a failed attempt of the client of r.
func (l *Limiter) Fail(r *http.Request) {
	l.FailKey(ClientKey(ClientIP(r, l.trusted)))
}

// FailKey is Fail for the client key.
func (l *Limiter) FailKey(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	e := l.buckets[key]
	if e == nil {
		e = l.order.PushFront(&bucket{key: key, tokens: l.burst, last: now})
		l.buckets[key] = e
		for l.order.Len() > l.size {
			oldest := l.order.Back()
			l.order.Remove(oldest)
			delete(l.buckets, oldest.Value.(*bucket).key)
		}
	} else {
		l.order.MoveToFront(e)
	}
	b := e.Value.(*bucket)
	b.tokens, b.last = max(0, l.refilled(b, now)-1), now
}

// Len returns how many clients the limiter holds.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

func (l *Limiter) refilled(b *bucket, now time.Time) float64 {
	return min(l.burst, b.tokens+float64(now.Sub(b.last))/float64(l.interval))
}

// ClientIP returns the address of r's client. It is the connection's peer
// address, unless the peer is one of the trusted proxies: then it is the
// rightmost X-Forwarded-For hop that is not a trusted proxy, the first one
// no proxy of ours could have written. A hop that is not an address ends
// the walk at the trusted hop before it. With no trusted proxies,
// X-Forwarded-For is never read, since a client can send any.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := peerAddr(r)
	if !isTrusted(peer, trusted) {
		return peer
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return client
		}
		client = a.Unmap()
		if !isTrusted(client, trusted) {
			return client
		}
	}
	return client
}

func peerAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientKey is the limiter's key of address a: an IPv4 address whole, an
// IPv6 address by its /64.
func ClientKey(a netip.Addr) string {
	if a.Is6() {
		p, err := a.Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return a.String()
}

// ParsePrefixes reads a comma-separated list of CIDR prefixes, or bare
// addresses taken as one address each.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR prefix or an address", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}
