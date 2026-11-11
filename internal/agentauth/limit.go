package agentauth

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Default limits on calls to STS, per env and process. A login that passes
// every local check costs one STS call, and anyone can make one, so the calls
// are limited: per source address first, so one source cannot use them all
// up, and then overall. The overall burst lets an env's whole fleet, up to
// 100 agents, log in at once after a restart. Agents renew their sessions
// without STS, so they call it only when they start or their session lapsed.
const (
	DefaultSTSCallsPerSecond = 1
	DefaultSTSBurst          = 100
	// a source may make a call every sourceSTSInterval, after a burst of
	// sourceSTSBurst: far less than every source together, so the calls
	// one source makes leave the overall limit room for the others. A login
	// that succeeds gives its source's call back, so agents sharing an
	// address (behind a NAT gateway, say) do not use up its limit.
	sourceSTSInterval = 5 * time.Second
	sourceSTSBurst    = 20
	// maxSTSSources bounds the sources tracked; past it, those with a full
	// allowance are forgotten, as they would start afresh anyway
	maxSTSSources = 10_000
)

// STSLimiter limits calls to STS per source address and overall. It is safe
// for concurrent use.
type STSLimiter struct {
	overall *rate.Limiter
	every   time.Duration
	burst   float64

	mu      sync.Mutex
	sources map[string]*allowance
}

// allowance is a source's calls left, as of when they were last counted.
type allowance struct {
	calls float64
	at    time.Time
}

// NewSTSLimiter returns a limiter with the default STS call limits.
func NewSTSLimiter() *STSLimiter {
	return newSTSLimiter(rate.NewLimiter(DefaultSTSCallsPerSecond, DefaultSTSBurst), sourceSTSInterval, sourceSTSBurst)
}

func newSTSLimiter(overall *rate.Limiter, every time.Duration, burst int) *STSLimiter {
	return &STSLimiter{overall: overall, every: every, burst: float64(burst), sources: map[string]*allowance{}}
}

// take allows one call to STS from source, or returns an error wrapping
// ErrTooManyLogins. An empty source, whose address is not known, has only
// the overall limit.
func (l *STSLimiter) take(source string, now time.Time) error {
	if source != "" && !l.takeFrom(source, now) {
		return fmt.Errorf("%w: sts call limit reached for source %s", ErrTooManyLogins, source)
	}
	if !l.overall.AllowN(now, 1) {
		return fmt.Errorf("%w: sts call limit reached", ErrTooManyLogins)
	}
	return nil
}

func (l *STSLimiter) takeFrom(source string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.sources[source]
	if a == nil {
		if len(l.sources) >= maxSTSSources {
			l.forgetFull(now)
		}
		a = &allowance{calls: l.burst, at: now}
		l.sources[source] = a
	}
	l.refill(a, now)
	if a.calls < 1 {
		return false
	}
	a.calls--
	return true
}

// giveBack returns a call to source after a login succeeded: a registered
// agent's logins do not count against its address.
func (l *STSLimiter) giveBack(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a := l.sources[source]; a != nil {
		a.calls = min(a.calls+1, l.burst)
	}
}

func (l *STSLimiter) refill(a *allowance, now time.Time) {
	if elapsed := now.Sub(a.at); elapsed > 0 {
		a.calls = min(a.calls+float64(elapsed)/float64(l.every), l.burst)
		a.at = now
	}
}

// forgetFull drops the sources with every call left, or all of them when
// that frees nothing. It must hold mu.
func (l *STSLimiter) forgetFull(now time.Time) {
	for source, a := range l.sources {
		if l.refill(a, now); a.calls >= l.burst {
			delete(l.sources, source)
		}
	}
	if len(l.sources) >= maxSTSSources {
		clear(l.sources)
	}
}

type sourceKey struct{}

// WithSource returns ctx carrying the address a login request came from
// (http.Request.RemoteAddr), for the STS call limit.
func WithSource(ctx context.Context, remoteAddr string) context.Context {
	return context.WithValue(ctx, sourceKey{}, source(remoteAddr))
}

// SourceFrom returns the source ctx carries (WithSource): an address, or an
// IPv6 /64, or empty when it is not known.
func SourceFrom(ctx context.Context) string {
	s, _ := ctx.Value(sourceKey{}).(string)
	return s
}

// source names the address a request came from: an IPv4 address, or an
// IPv6 address's /64, which one host or network usually holds whole. It is
// empty when the address cannot be read, or is a private one: that is
// mostly a proxy's, such as a load balancer's in front of a container,
// which every agent would share.
func source(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return ""
	}
	if addr.Is6() {
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	}
	return addr.String()
}
