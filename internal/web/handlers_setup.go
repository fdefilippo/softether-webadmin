package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

// formData is the data of the login and setup pages: Error and Notice are
// catalog keys.
type formData struct {
	Error  string
	Notice string
}

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	s.rnd.Page(w, r, "setup", formData{})
}

func (s *Server) setupFail(w http.ResponseWriter, r *http.Request, key, result string) {
	s.audit(r, audit.Event{Action: "setup_failed", Role: "setup", Result: result})
	s.rnd.Page(w, r, "setup", formData{Error: key})
}

// setupSubmit sets the administrator password with the one-time token.
func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.text(r, "error.bad_request"), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	password := r.PostFormValue("password")
	if password != r.PostFormValue("password2") {
		s.setupFail(w, r, "setup.password_mismatch", "password_mismatch")
		return
	}

	// Detached from the request: a browser that disconnects after the write
	// must not turn a successful change into a spurious ErrUncertain.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), setupTimeout)
	defer cancel()
	err := s.d.Setup.Complete(ctx, token, password)

	var mm *rpc.CertMismatchError
	switch {
	case err == nil:
		s.setState(softether.StatePasswordSet, nil)
		s.startSession(w, r, rpc.Credential{Username: "", Password: password})
		s.audit(r, audit.Event{Action: "setup_completed", Role: "setup", Method: "SetServerPassword", Result: "ok"})
		s.redirect(w, r, "/dashboard")
	case errors.Is(err, setup.ErrBadToken):
		s.setupFail(w, r, "setup.bad_token", "bad_token")
	case errors.Is(err, setup.ErrWeakPassword):
		s.setupFail(w, r, "setup.weak_password", "weak_password")
	case errors.Is(err, setup.ErrPasswordTooLong):
		s.setupFail(w, r, "setup.long_password", "long_password")
	case errors.Is(err, setup.ErrPasswordInvalid):
		s.setupFail(w, r, "setup.invalid_password", "invalid_password")
	case errors.Is(err, setup.ErrAlreadyConfigured), errors.Is(err, setup.ErrNoToken):
		if errors.Is(err, setup.ErrAlreadyConfigured) {
			s.setState(softether.StatePasswordSet, nil)
		}
		s.audit(r, audit.Event{Action: "setup_failed", Role: "setup", Result: "already_configured"})
		s.redirect(w, r, "/login?notice=configured")
	case errors.As(err, &mm), errors.Is(err, rpc.ErrUnreachable):
		page, _ := s.observe(err)
		s.audit(r, audit.Event{Action: "setup_failed", Role: "setup", Result: "server_unavailable"})
		s.redirect(w, r, page)
	case errors.Is(err, setup.ErrUncertain):
		// Learn the current state right away so that the first poll of
		// /status already reflects it. The write is never repeated.
		s.ProbeOnce(ctx)
		s.audit(r, audit.Event{Action: "setup_failed", Role: "setup", Method: "SetServerPassword", Result: "uncertain"})
		s.rnd.Page(w, r, "uncertain", nil)
	default:
		s.audit(r, audit.Event{Action: "setup_failed", Role: "setup", Result: "error"})
		s.d.Audit.Slog().Error("setup failed", "err", err.Error())
		http.Error(w, s.text(r, "error.upstream"), http.StatusBadGateway)
	}
}
