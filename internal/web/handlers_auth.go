package web

import (
	"errors"
	"net/http"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if _, ok := s.d.Sessions.Get(c.Value); ok {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}
	d := formData{}
	if r.URL.Query().Get("notice") == "configured" { // exact value only
		d.Notice = "setup.already_configured"
	}
	s.rnd.Page(w, r, "login", d)
}

// loginSubmit logs in the server administrator: only the password is asked
// (empty user name). The per-IP limiter is consulted before the VPN server
// is called, and reset on success. A successful Test is confirmed by a fresh
// probe (design 5.2): with an empty password any credential succeeds.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.text(r, "error.bad_request"), http.StatusBadRequest)
		return
	}
	ip := ClientIP(r)
	// The attempt is reserved before the VPN server is called, so that
	// parallel requests cannot exceed the limit.
	if !s.limiter.Begin(ip) {
		s.audit(r, audit.Event{Action: "login_rate_limited", Role: roleServerAdmin, Result: "rate_limited"})
		s.rnd.PageStatus(w, r, http.StatusTooManyRequests, "login", formData{Error: "login.rate_limited"})
		return
	}
	cred := rpc.Credential{Username: "", Password: r.PostFormValue("password")}
	err := s.d.Client.Test(r.Context(), cred)
	switch {
	case err == nil:
		// A server whose password was removed from outside accepts any
		// credential, and the cached state may still say "password set":
		// confirm with a fresh probe before trusting the success.
		if st := s.probeNow(r.Context()); st != softether.StatePasswordSet {
			s.limiter.Cancel(ip) // no verdict on the password
			s.audit(r, audit.Event{Action: "login_refused", Role: roleServerAdmin, Method: "Test", Result: st.String()})
			s.redirect(w, r, stateTarget(st))
			return
		}
		s.limiter.Reset(ip)
		s.startSession(w, r, cred)
		s.audit(r, audit.Event{Action: "login_succeeded", Role: roleServerAdmin, Method: "Test", Result: "ok"})
		s.redirect(w, r, "/dashboard")
	case errors.Is(err, rpc.ErrUnauthorized):
		// The reservation stays: it is the recorded failure.
		s.audit(r, audit.Event{Action: "login_failed", Role: roleServerAdmin, Method: "Test", Result: "unauthorized"})
		s.rnd.Page(w, r, "login", formData{Error: "login.failed"})
	default:
		s.limiter.Cancel(ip) // no verdict: not the user's failure
		s.failRPC(w, r, nil, "Test", err)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := SessionFrom(r.Context()); ok {
		s.d.Sessions.Destroy(sess.ID)
	}
	ClearSessionCookie(w)
	s.audit(r, audit.Event{Action: "logout", Role: roleServerAdmin, Result: "ok"})
	s.redirect(w, r, "/login")
}
