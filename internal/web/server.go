package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

const (
	maxBodyBytes = 1 << 20
	// A state other than "password set" is re-probed by the first request
	// that finds the last probe older than staleRetry, so that the pages
	// recover soon after the server does; /status (polled every 3 s) uses
	// the shorter statusMaxAge.
	staleRetry   = 5 * time.Second
	statusMaxAge = 2 * time.Second
	// setupTimeout bounds setup.Manager.Complete, which runs detached from
	// the request context.
	setupTimeout = 60 * time.Second

	roleServerAdmin = "server_admin"
)

// Deps are the collaborators of the Server. Client is the one and only
// *rpc.Client of the process (shared with Prober and Setup, so that trust on
// first use cannot race); all of Cfg, Client, Prober, Setup and Sessions are
// required. Audit may be nil (no audit output) and Now defaults to time.Now.
type Deps struct {
	Cfg      config.Config
	Client   *rpc.Client
	Prober   softether.Prober
	Setup    *setup.Manager
	Sessions *SessionStore
	Audit    *audit.Logger
	Now      func() time.Time
}

// Server is the HTTP handler of the web admin. It is created by NewServer;
// the probe loop (RunProbeLoop) keeps its view of the VPN server's state
// current.
type Server struct {
	d       Deps
	rnd     Renderer
	cat     Catalog
	limiter *LoginLimiter
	pre     *preCSRF
	handler http.Handler

	probeMu sync.Mutex // at most one on-demand probe at a time

	mu       sync.RWMutex // guards the fields below
	state    softether.State
	probed   bool
	probedAt time.Time
	mismatch rpc.CertMismatchError // valid while state == StateCertMismatch
}

// NewServer builds the handler tree. It panics if the embedded assets are
// broken, which is a build error, not a runtime condition.
func NewServer(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	cat, err := EmbeddedCatalogs()
	if err != nil {
		panic("web: " + err.Error())
	}
	rnd, err := NewRenderer(cat, EmbeddedTemplates())
	if err != nil {
		panic("web: " + err.Error())
	}
	s := &Server{
		d:       d,
		rnd:     rnd.WithLogger(d.Audit.Slog()),
		cat:     cat,
		limiter: NewLoginLimiter(d.Cfg.LoginMaxFailures, d.Cfg.LoginWindow, d.Now),
		pre:     newPreCSRF(d.Now),
	}

	auth := func(h http.HandlerFunc) http.Handler { return RequireSession(d.Sessions, CSRF(h)) }
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(StaticFS())))
	mux.Handle("GET /lang", LangHandler())
	mux.Handle("GET /{$}", http.HandlerFunc(s.root))
	mux.Handle("GET /setup", s.pre.protect(http.HandlerFunc(s.setupForm)))
	mux.Handle("POST /setup", s.pre.protect(http.HandlerFunc(s.setupSubmit)))
	mux.Handle("GET /login", s.pre.protect(http.HandlerFunc(s.loginForm)))
	mux.Handle("POST /login", s.pre.protect(http.HandlerFunc(s.loginSubmit)))
	mux.Handle("POST /logout", auth(s.logout))
	mux.Handle("GET /dashboard", auth(s.dashboard))
	mux.Handle("POST /adminip/restrict", auth(s.restrictAdminIP))
	mux.Handle("GET /status", http.HandlerFunc(s.status))
	mux.Handle("GET /unreachable", s.optionalSession(http.HandlerFunc(s.unreachable)))
	mux.Handle("GET /certmismatch", s.optionalSession(http.HandlerFunc(s.certMismatch)))

	s.handler = SecurityHeaders(limitBody(s.gate(mux)))
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// limitBody caps every request body at maxBodyBytes before any form parsing.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// optionalSession puts the session, if the request has a valid one, in the
// context without redirecting otherwise: the safety pages are shown to
// everybody, but a logged-in user gets the logout button on them.
func (s *Server) optionalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SessionCookie); err == nil {
			if sess, ok := s.d.Sessions.Get(c.Value); ok {
				r = r.WithContext(withSession(r.Context(), sess))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- probe state -----------------------------------------------------------

func (s *Server) setState(st softether.State, mm *rpc.CertMismatchError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.probed, s.probedAt = st, true, s.d.Now()
	s.mismatch = rpc.CertMismatchError{}
	if st == softether.StateCertMismatch && mm != nil {
		s.mismatch = *mm
	}
}

func (s *Server) snapshot() (st softether.State, probed bool, at time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state, s.probed, s.probedAt
}

// ProbeOnce probes the VPN server, records the state, lets the setup manager
// align the setup token with it and drops the expired sessions (so that they
// do not keep a SoftEther password in memory). It returns the state.
func (s *Server) ProbeOnce(ctx context.Context) softether.State {
	st, err := s.d.Prober.Probe(ctx)
	var mm *rpc.CertMismatchError
	if st == softether.StateCertMismatch {
		errors.As(err, &mm)
	} else if err != nil {
		s.d.Audit.Slog().Warn("probe failed", "err", err.Error())
	}
	s.setState(st, mm)
	if err := s.d.Setup.Refresh(ctx, st); err != nil {
		s.d.Audit.Slog().Error("setup token refresh failed", "err", err.Error())
	}
	s.d.Sessions.Sweep()
	return st
}

// RunProbeLoop calls ProbeOnce immediately and then every Cfg.ProbeInterval
// until ctx is done.
func (s *Server) RunProbeLoop(ctx context.Context) {
	interval := s.d.Cfg.ProbeInterval
	if interval <= 0 {
		interval = time.Minute
	}
	s.ProbeOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.ProbeOnce(ctx)
		}
	}
}

// probeIfStale returns the last known state, probing first when there is
// none yet or it is older than maxAge. Concurrent callers share one probe.
func (s *Server) probeIfStale(ctx context.Context, maxAge time.Duration) softether.State {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if st, probed, at := s.snapshot(); probed && s.d.Now().Sub(at) <= maxAge {
		return st
	}
	return s.ProbeOnce(ctx)
}

// currentState is the state used for routing. A healthy server (password
// set) is trusted until the next scheduled probe; every other state is
// re-checked at most every staleRetry.
func (s *Server) currentState(ctx context.Context) softether.State {
	st, probed, _ := s.snapshot()
	if probed && st == softether.StatePasswordSet {
		return st
	}
	return s.probeIfStale(ctx, staleRetry)
}

// observe records, from a failed call made by a handler, that the server is
// unreachable or presents another certificate, and reports whether err was
// one of the two.
func (s *Server) observe(err error) (page string, ok bool) {
	var mm *rpc.CertMismatchError
	switch {
	case errors.As(err, &mm):
		s.setState(softether.StateCertMismatch, mm)
		return "/certmismatch", true
	case errors.Is(err, rpc.ErrUnreachable):
		s.setState(softether.StateUnreachable, nil)
		return "/unreachable", true
	}
	return "", false
}

// gate routes by the last probed state (before any handler runs):
//
//   - empty password: everything goes to /setup;
//   - certificate mismatch: everything goes to /certmismatch;
//   - unreachable: everything goes to /unreachable (sessions are kept);
//   - password set: /setup, /unreachable and /certmismatch are not pages
//     anymore (GET goes to /login, resp. /).
//
// /status, /static/, /lang and /logout are always reachable: /status feeds
// the polling of the "uncertain" page, /logout must work during an outage.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/status" || p == "/lang" || p == "/logout" || strings.HasPrefix(p, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		target := ""
		switch s.currentState(r.Context()) {
		case softether.StateEmptyPassword:
			target = "/setup"
		case softether.StateCertMismatch:
			target = "/certmismatch"
		case softether.StateUnreachable:
			target = "/unreachable"
		default: // password set
			switch {
			case p == "/setup" && r.Method != http.MethodPost:
				s.redirect(w, r, "/login")
				return
			case p == "/unreachable" || p == "/certmismatch":
				s.redirect(w, r, "/")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if p == target {
			next.ServeHTTP(w, r)
			return
		}
		s.redirect(w, r, target)
	})
}

// --- helpers ---------------------------------------------------------------

// redirect sends the browser to target: 303 for a normal request, HX-Redirect
// for an htmx request, so that htmx navigates the whole page instead of
// swapping the target into a fragment.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// text translates key into the language of the request.
func (s *Server) text(r *http.Request, key string, args ...any) string {
	return s.cat.T(Negotiate(r), key, args...)
}

func (s *Server) audit(r *http.Request, e audit.Event) {
	e.RemoteIP = ClientIP(r)
	s.d.Audit.Log(r.Context(), e)
}

// failRPC handles an error of a JSON-RPC call made for the request:
//   - unauthorized with a session credential: the session is destroyed (the
//     password it holds is no longer valid) and the user goes to /login;
//   - unreachable server or certificate mismatch: the safety pages; the
//     session stays valid;
//   - anything else: a plain 502.
func (s *Server) failRPC(w http.ResponseWriter, r *http.Request, sess *Session, method string, err error) {
	if errors.Is(err, rpc.ErrUnauthorized) && sess != nil {
		s.d.Sessions.Destroy(sess.ID)
		ClearSessionCookie(w)
		s.audit(r, audit.Event{Action: "session_expired_unauthorized", Role: roleServerAdmin, Method: method, Result: "unauthorized"})
		s.redirect(w, r, "/login")
		return
	}
	if page, ok := s.observe(err); ok {
		s.redirect(w, r, page)
		return
	}
	s.d.Audit.Slog().Error("rpc call failed", "method", method, "err", err.Error())
	http.Error(w, s.text(r, "error.upstream"), http.StatusBadGateway)
}

// startSession creates a session for cred, replacing any session the request
// already carried (always a new ID), and sets the cookie.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, cred rpc.Credential) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		s.d.Sessions.Destroy(c.Value)
	}
	sess := s.d.Sessions.Create(cred, Negotiate(r))
	SetSessionCookie(w, sess.ID)
}

// root sends the visitor to the dashboard or the login page (the gate has
// already dealt with the unhealthy states).
func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if _, ok := s.d.Sessions.Get(c.Value); ok {
			s.redirect(w, r, "/dashboard")
			return
		}
	}
	s.redirect(w, r, "/login")
}
