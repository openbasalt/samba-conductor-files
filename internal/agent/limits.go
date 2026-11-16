package agent

import (
	"net"
	"sync"
	"time"
)

// Limits on what a peer that has not proven a pinned key can cost the
// agent. Such a peer reaches the listener with any key while an enrollment
// code is outstanding, and with no key at all before the TLS handshake.
const (
	// handshakeTimeout bounds the TLS handshake of every connection.
	handshakeTimeout = 5 * time.Second
	// unauthRequestTimeout bounds reading and answering the one request of
	// a connection whose key is not pinned (only enroll can succeed there).
	unauthRequestTimeout = 10 * time.Second
	// requestTimeout bounds one request of a pinned conductor.
	requestTimeout = 10 * time.Minute
	// preAuthPerSource is the number of connections one source address may
	// hold before its key is known to be pinned (handshakes and enrollment
	// requests).
	preAuthPerSource = 4
	// preAuthMax is the number of such connections from all sources. When
	// it is reached the oldest one is closed to admit the new one, so a
	// flood from many addresses delays a conductor's handshake by at most
	// one round instead of locking it out.
	preAuthMax = 64
	// maxTrackedSources bounds the per-source tables below.
	maxTrackedSources = 4096
	// unauthAuditInterval is the least time between two audit entries
	// written for the same unauthenticated source address.
	unauthAuditInterval = time.Minute
	// unauthAuditPerMinute caps the audit entries written for
	// unauthenticated peers from all sources in one minute.
	unauthAuditPerMinute = 30
)

// sourceOf returns the host part of a remote address ("192.0.2.7:51234"
// gives "192.0.2.7"); anything else is used as it is.
func sourceOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// ---- connections before authentication ----

// preAuthConn is one admitted connection whose key is not known to be
// pinned yet.
type preAuthConn struct {
	conn     net.Conn
	source   string
	admitted time.Time
	released bool
}

// connLimiter bounds the connections that have not proven a pinned key,
// per source address and in total, apart from the slots of pinned
// conductors (Agent.sem), which such connections can never take.
type connLimiter struct {
	mu        sync.Mutex
	perSource int
	max       int
	bySource  map[string]int
	conns     map[*preAuthConn]struct{}
	now       func() time.Time
}

func newConnLimiter(perSource, max int) *connLimiter {
	return &connLimiter{perSource: perSource, max: max, bySource: map[string]int{}, conns: map[*preAuthConn]struct{}{},
		now: time.Now}
}

// admit registers conn. It refuses a source that holds perSource
// connections already; when the total is reached it closes the oldest
// connection of another source to make room. The returned release must be
// called once the connection is pinned or done (it is idempotent).
func (l *connLimiter) admit(conn net.Conn, source string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bySource[source] >= l.perSource {
		return nil, false
	}
	if len(l.conns) >= l.max {
		var oldest *preAuthConn
		for c := range l.conns {
			if c.source == source {
				continue
			}
			if oldest == nil || c.admitted.Before(oldest.admitted) {
				oldest = c
			}
		}
		if oldest == nil {
			return nil, false
		}
		l.releaseLocked(oldest)
		_ = oldest.conn.Close()
	}
	c := &preAuthConn{conn: conn, source: source, admitted: l.now()}
	l.conns[c] = struct{}{}
	l.bySource[source]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.releaseLocked(c)
	}, true
}

func (l *connLimiter) releaseLocked(c *preAuthConn) {
	if c.released {
		return
	}
	c.released = true
	delete(l.conns, c)
	if l.bySource[c.source]--; l.bySource[c.source] <= 0 {
		delete(l.bySource, c.source)
	}
}

// count returns the admitted connections (tests).
func (l *connLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

// ---- enrollment attempts ----

// enrollLimiter counts wrong enrollment codes per source address for the
// outstanding code. A source that reaches max is refused for the rest of
// that code's life; other sources, conductor's among them, keep their own
// attempts, so no stranger can cancel the code.
type enrollLimiter struct {
	mu       sync.Mutex
	max      int
	code     string
	failures map[string]int
}

func newEnrollLimiter(max int) *enrollLimiter {
	return &enrollLimiter{max: max, failures: map[string]int{}}
}

// reset starts over when the outstanding code changed (callers hold mu).
func (l *enrollLimiter) reset(code string) {
	if code != l.code {
		l.code = code
		l.failures = map[string]int{}
	}
}

// allowed reports whether source may still try the code.
func (l *enrollLimiter) allowed(code, source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reset(code)
	return l.failures[source] < l.max
}

// fail records a wrong code from source.
func (l *enrollLimiter) fail(code, source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reset(code)
	if _, ok := l.failures[source]; !ok && len(l.failures) >= maxTrackedSources {
		// The table is full: forget one source. It only gets its attempts
		// back, and a 256-bit token cannot be guessed in any number of them.
		for k := range l.failures {
			delete(l.failures, k)
			break
		}
	}
	l.failures[source]++
}

// ---- audit entries for unauthenticated peers ----

// auditLimiter bounds the audit entries that peers without a pinned key can
// cause: at most one per source address per unauthAuditInterval and
// unauthAuditPerMinute from all sources. What it drops is counted and
// reported in the next entry it lets through.
type auditLimiter struct {
	mu         sync.Mutex
	last       map[string]time.Time
	minute     time.Time
	inMinute   int
	suppressed int
	interval   time.Duration
	perMinute  int
	maxSources int
}

func newAuditLimiter() *auditLimiter {
	return &auditLimiter{last: map[string]time.Time{}, interval: unauthAuditInterval, perMinute: unauthAuditPerMinute,
		maxSources: maxTrackedSources}
}

// allow reports whether an entry for source may be written at now and, if
// so, how many entries were suppressed since the last one written.
func (l *auditLimiter) allow(source string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.minute) >= time.Minute {
		l.minute, l.inMinute = now, 0
	}
	if t, ok := l.last[source]; ok && now.Sub(t) < l.interval {
		l.suppressed++
		return false, 0
	}
	if l.inMinute >= l.perMinute {
		l.suppressed++
		return false, 0
	}
	if _, ok := l.last[source]; !ok && len(l.last) >= l.maxSources {
		for k, t := range l.last {
			if now.Sub(t) >= l.interval {
				delete(l.last, k)
			}
		}
		if len(l.last) >= l.maxSources {
			l.suppressed++
			return false, 0
		}
	}
	l.last[source] = now
	l.inMinute++
	n := l.suppressed
	l.suppressed = 0
	return true, n
}
