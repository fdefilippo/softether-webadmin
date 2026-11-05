package web

import (
	"net/http"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

type dashboardData struct {
	Info      rpc.ServerInfo
	Status    rpc.ServerStatus
	Isolation softether.Isolation
	// IsolationErr is true when adminip.txt could not be read; the banner
	// then says so instead of guessing.
	IsolationErr bool
	// ShowRestrict: the "restrict to loopback" banner is shown (file missing
	// or not isolated).
	ShowRestrict bool
	// NoticeKey/NoticeArg: result of a POST, a catalog key and its argument.
	NoticeKey string
	NoticeArg string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	s.renderDashboard(w, r, sess, "", "")
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, sess *Session, noticeKey, noticeArg string) {
	info, err := s.d.Client.GetServerInfo(r.Context(), sess.Cred)
	if err != nil {
		s.failRPC(w, r, sess, "GetServerInfo", err)
		return
	}
	status, err := s.d.Client.GetServerStatus(r.Context(), sess.Cred)
	if err != nil {
		s.failRPC(w, r, sess, "GetServerStatus", err)
		return
	}
	d := dashboardData{Info: info, Status: status, NoticeKey: noticeKey, NoticeArg: noticeArg}
	// Only the server administrator exists in this milestone, so the
	// isolation banner is always for them.
	iso, err := softether.ClassifyAdminIP(s.d.Cfg.AdminIPPath)
	if err != nil {
		d.IsolationErr = true
		s.d.Audit.Slog().Warn("cannot read adminip.txt", "err", err.Error())
	} else {
		d.Isolation = iso
		d.ShowRestrict = iso.Missing || !iso.Isolated
	}
	s.rnd.Page(w, r, "dashboard", d)
}

// restrictAdminIP rewrites adminip.txt so that only loopback may administer
// the server, after an explicit confirmation (confirm=yes), and shows the
// backup path.
func (s *Server) restrictAdminIP(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	if err := r.ParseForm(); err != nil || r.PostFormValue("confirm") != "yes" {
		http.Error(w, s.text(r, "error.bad_request"), http.StatusBadRequest)
		return
	}
	backup, err := softether.RestrictToLoopback(s.d.Cfg.AdminIPPath, s.d.Now())
	if err != nil {
		s.audit(r, audit.Event{Action: "adminip_restricted", Role: roleServerAdmin, Result: "error"})
		s.d.Audit.Slog().Error("restrict adminip.txt failed", "err", err.Error())
		http.Error(w, s.text(r, "error.internal"), http.StatusInternalServerError)
		return
	}
	s.audit(r, audit.Event{Action: "adminip_restricted", Role: roleServerAdmin, Result: "ok"})
	if backup == "" {
		s.renderDashboard(w, r, sess, "adminip.done_nobackup", "")
		return
	}
	s.renderDashboard(w, r, sess, "adminip.done", backup)
}

// --- pages without a session requirement ----------------------------------

type statusData struct{ State string }

// status is the htmx fragment polled by the "uncertain" page. It re-probes
// when the last probe is older than statusMaxAge.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st := s.probeIfStale(r.Context(), statusMaxAge)
	s.rnd.Fragment(w, r, "status", statusData{State: st.String()})
}

func (s *Server) unreachable(w http.ResponseWriter, r *http.Request) {
	s.rnd.Page(w, r, "unreachable", nil)
}

type certMismatchData struct {
	Pinned, Presented string
	Command           string
}

func (s *Server) certMismatch(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mm := s.mismatch
	s.mu.RUnlock()
	s.rnd.Page(w, r, "certmismatch", certMismatchData{
		Pinned: mm.Pinned, Presented: mm.Presented,
		Command: "softether-webadmin trust-server-cert --fingerprint " + mm.Presented,
	})
}
