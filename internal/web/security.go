package web

import (
	"crypto/subtle"
	"net"
	"net/http"
	"sync"
	"time"
)

// SessionCookie is the name of the session cookie.
const SessionCookie = "swa_session"

// contentSecurityPolicy is sent on every response.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

// SecurityHeaders sets the security headers on every response, including
// redirects, errors and htmx fragments.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// SetSessionCookie sends the session cookie. It has no expiry (it is dropped
// when the browser closes); the server enforces the idle and absolute limits.
func SetSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie asks the browser to delete the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// RequireSession lets a request through only with a valid session, which it
// stores in the request context (see SessionFrom). Otherwise it redirects to
// /login with 303 or, for htmx requests, answers 200 with HX-Redirect so that
// htmx navigates the whole page instead of swapping the login page into a
// fragment.
func RequireSession(store *SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SessionCookie); err == nil {
			if s, ok := store.Get(c.Value); ok {
				next.ServeHTTP(w, r.WithContext(withSession(r.Context(), s)))
				return
			}
		}
		if r.Header.Get("HX-Request") != "" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// CSRF rejects state-changing requests (any method other than GET, HEAD and
// OPTIONS) whose "csrf" form field or X-CSRF-Token header does not match the
// session's token. It must run inside RequireSession; without a session in
// the context every unsafe request is rejected.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		s, ok := SessionFrom(r.Context())
		if !ok {
			forbidden(w, r)
			return
		}
		tok := r.Header.Get("X-CSRF-Token")
		if tok == "" {
			tok = r.PostFormValue("csrf")
		}
		if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.CSRF)) != 1 {
			forbidden(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var embeddedCatalog = sync.OnceValue(func() Catalog {
	c, err := EmbeddedCatalogs()
	if err != nil {
		panic("web: " + err.Error()) // a build error, not a runtime condition
	}
	return c
})

// forbidden answers a failed CSRF check with a localized plain-text 403.
func forbidden(w http.ResponseWriter, r *http.Request) {
	http.Error(w, embeddedCatalog().T(Negotiate(r), "error.forbidden"), http.StatusForbidden)
}

// ClientIP is the peer address of the request. X-Forwarded-For is
// deliberately ignored: the daemon is not meant to run behind a proxy and the
// header is client-controlled.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LoginLimiter allows at most max failed logins per key (client IP) inside a
// sliding window. It is safe for concurrent use.
type LoginLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
	sweepAt  time.Time
}

// NewLoginLimiter returns a limiter allowing max failures per window.
func NewLoginLimiter(max int, window time.Duration, now func() time.Time) *LoginLimiter {
	if now == nil {
		now = time.Now
	}
	return &LoginLimiter{max: max, window: window, now: now, failures: map[string][]time.Time{}}
}

// recentLocked drops the failures of ip that fell out of the window.
func (l *LoginLimiter) recentLocked(ip string, now time.Time) []time.Time {
	ts := l.failures[ip]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.failures, ip)
		return nil
	}
	l.failures[ip] = ts
	return ts
}

// Allow reports whether ip may attempt a login.
func (l *LoginLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recentLocked(ip, l.now())) < l.max
}

// Begin atomically reserves a login attempt for ip: it refuses (false) when
// the window already holds max attempts, otherwise it records one and returns
// true. Unlike Allow followed by Fail, parallel requests cannot all pass the
// check before any of them is recorded. A successful login calls Reset, an
// attempt that did not reach a verdict (server unreachable) calls Cancel.
func (l *LoginLimiter) Begin(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	ts := l.recentLocked(ip, now)
	if len(ts) >= l.max {
		return false
	}
	l.failures[ip] = append(ts, now)
	return true
}

// Cancel gives back the attempt most recently reserved with Begin for ip.
func (l *LoginLimiter) Cancel(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ts := l.failures[ip]; len(ts) > 1 {
		l.failures[ip] = ts[:len(ts)-1]
	} else {
		delete(l.failures, ip)
	}
}

// Fail records a failed login attempt from ip.
func (l *LoginLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !now.Before(l.sweepAt) { // bound memory: forget stale keys once a minute
		l.sweepAt = now.Add(time.Minute)
		for k := range l.failures {
			l.recentLocked(k, now)
		}
	}
	l.failures[ip] = append(l.recentLocked(ip, now), now)
}

// Reset forgets the failures of ip (after a successful login).
func (l *LoginLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}
