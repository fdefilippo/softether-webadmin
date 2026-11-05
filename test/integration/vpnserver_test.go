//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
	"github.com/fdefilippo/softether-webadmin/internal/web"
)

// adminPassword has a colon, a space and a non-ASCII letter on purpose: the
// real server must accept what the Basic header carries.
const adminPassword = "pa:ss è long enough"

// daemon is the web admin wired to a real vpnserver, driven in-process like
// the unit tests drive it (the session cookie is Secure, so a plain
// http.Client cookie jar would not send it back).
type daemon struct {
	t       *testing.T
	srv     *web.Server
	prober  softether.Prober
	cfg     config.Config
	pins    rpc.PinStore
	apiURL  string
	cookies map[string]string
}

func newDaemon(t *testing.T, apiURL string) *daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.SoftEtherURL = apiURL
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.RuntimeDir = filepath.Join(dir, "run")
	cfg.AdminIPPath = filepath.Join(dir, "adminip.txt")
	if err := os.WriteFile(cfg.AdminIPPath, []byte("127.0.0.1/32\n::1/128\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Same wiring as serve(): one client, trust on first use enabled.
	pins := rpc.PinStore{Path: filepath.Join(cfg.StateDir, "server-cert.sha256")}
	client := rpc.NewClient(apiURL, pins, true)
	prober := softether.Prober{Client: client}
	srv := web.NewServer(web.Deps{
		Cfg:      cfg,
		Client:   client,
		Prober:   prober,
		Setup:    setup.NewManager(cfg.RuntimeDir, client, prober, slog.New(slog.NewTextHandler(io.Discard, nil))),
		Sessions: web.NewSessionStore(cfg.SessionIdle, cfg.SessionMax, time.Now),
		Audit:    audit.New(io.Discard),
	})
	return &daemon{t: t, srv: srv, prober: prober, cfg: cfg, pins: pins, apiURL: apiURL, cookies: map[string]string{}}
}

func (d *daemon) probe() softether.State {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return d.srv.ProbeOnce(ctx)
}

func (d *daemon) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	d.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range d.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rec := httptest.NewRecorder()
	d.srv.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(d.cookies, c.Name)
		} else {
			d.cookies[c.Name] = c.Value
		}
	}
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrf loads page and returns the CSRF token of its form (for the form pages
// this also stores the pre-session swa_csrf cookie).
func (d *daemon) csrf(page string) string {
	d.t.Helper()
	rec := d.do("GET", page, nil)
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		d.t.Fatalf("no csrf field in %s (code %d):\n%s", page, rec.Code, rec.Body.String())
	}
	return m[1]
}

func (d *daemon) wantRedirect(rec *httptest.ResponseRecorder, to string) {
	d.t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		d.t.Fatalf("got %d Location=%q, want 303 %q\n%s", rec.Code, rec.Header().Get("Location"), to, rec.Body.String())
	}
}

func (d *daemon) setupPassword(password string) *httptest.ResponseRecorder {
	d.t.Helper()
	token, err := setup.ReadTokenFile(d.cfg.RuntimeDir)
	if err != nil {
		d.t.Fatalf("read setup token: %v", err)
	}
	return d.do("POST", "/setup", url.Values{
		"csrf": {d.csrf("/setup")}, "token": {token}, "password": {password}, "password2": {password},
	})
}

func (d *daemon) login(password string) *httptest.ResponseRecorder {
	d.t.Helper()
	return d.do("POST", "/login", url.Values{"csrf": {d.csrf("/login")}, "password": {password}})
}

func TestRealFirstAccess(t *testing.T) {
	apiURL, _ := StartVPNServer(t)
	d := newDaemon(t, apiURL)

	if st := d.probe(); st != softether.StateEmptyPassword {
		t.Fatalf("first probe = %v, want empty-password", st)
	}
	pin, ok, err := d.pins.Load()
	if err != nil || !ok || pin == "" {
		t.Fatalf("trust on first use did not pin the certificate: %q %v %v", pin, ok, err)
	}

	d.wantRedirect(d.do("GET", "/", nil), "/setup")

	rec := d.setupPassword(adminPassword)
	d.wantRedirect(rec, "/dashboard")

	rec = d.do("GET", "/dashboard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/dashboard = %d\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "5.02") {
		t.Errorf("dashboard does not show the server version 5.02:\n%s", rec.Body.String())
	}

	if st := d.probe(); st != softether.StatePasswordSet {
		t.Fatalf("probe after setup = %v, want password-set", st)
	}
	// The new password really works on the real server, and a wrong one does not.
	client := rpc.NewClient(apiURL, d.pins, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Test(ctx, rpc.Credential{Password: adminPassword}); err != nil {
		t.Errorf("new password refused by the server: %v", err)
	}
	if err := client.Test(ctx, rpc.Credential{Password: "wrong password"}); !errors.Is(err, rpc.ErrUnauthorized) {
		t.Errorf("wrong password: err = %v, want ErrUnauthorized", err)
	}
	// The setup token is gone together with the first-access phase.
	if _, err := setup.ReadTokenFile(d.cfg.RuntimeDir); err == nil {
		t.Error("setup token file still present after setup")
	}
}

func TestRealLoginAndLogout(t *testing.T) {
	apiURL, _ := StartVPNServer(t)
	d := newDaemon(t, apiURL)
	d.probe()
	d.wantRedirect(d.setupPassword(adminPassword), "/dashboard")

	// A fresh browser (no session) must log in with the password just set.
	d.cookies = map[string]string{}
	d.wantRedirect(d.do("GET", "/dashboard", nil), "/login")

	rec := d.login("not the password")
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("login with a wrong password redirected to %q", rec.Header().Get("Location"))
	}
	d.wantRedirect(d.login(adminPassword), "/dashboard")

	rec = d.do("GET", "/dashboard", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "5.02") {
		t.Fatalf("/dashboard after login = %d\n%s", rec.Code, rec.Body.String())
	}

	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no csrf field in the dashboard (logout form)")
	}
	d.wantRedirect(d.do("POST", "/logout", url.Values{"csrf": {m[1]}}), "/login")
	d.wantRedirect(d.do("GET", "/dashboard", nil), "/login")
}

func TestRealPinMismatch(t *testing.T) {
	apiURL, _ := StartVPNServer(t)
	d := newDaemon(t, apiURL)
	if st := d.probe(); st != softether.StateEmptyPassword {
		t.Fatalf("first probe = %v", st)
	}
	d.wantRedirect(d.setupPassword(adminPassword), "/dashboard")
	d.cookies = map[string]string{}
	d.wantRedirect(d.do("GET", "/", nil), "/login")
	real, _, err := d.pins.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Pretend the server presented another certificate than the pinned one.
	fake := strings.Repeat("ab", 32)
	if fake == real {
		t.Fatal("fake fingerprint equals the real one")
	}
	if err := d.pins.Save(fake); err != nil {
		t.Fatal(err)
	}

	// The prober refuses to talk (its Test call sends no credentials: the
	// TLS layer rejects the connection first), and the pages say so.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, perr := d.prober.Probe(ctx)
	var mm *rpc.CertMismatchError
	if st != softether.StateCertMismatch || !errors.As(perr, &mm) {
		t.Fatalf("Probe = %v, %v; want StateCertMismatch with a *CertMismatchError", st, perr)
	}
	if mm.Pinned != fake || mm.Presented != real {
		t.Errorf("mismatch = pinned %s presented %s; want pinned %s presented %s", mm.Pinned, mm.Presented, fake, real)
	}
	if got := d.probe(); got != softether.StateCertMismatch {
		t.Fatalf("ProbeOnce = %v, want cert-mismatch", got)
	}
	d.wantRedirect(d.do("GET", "/", nil), "/certmismatch")
	d.wantRedirect(d.do("GET", "/login", nil), "/certmismatch")
	rec := d.do("GET", "/certmismatch", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), real) {
		t.Fatalf("/certmismatch = %d, must show the presented fingerprint\n%s", rec.Code, rec.Body.String())
	}
	// The pin was not silently replaced.
	if cur, _, _ := d.pins.Load(); cur != fake {
		t.Fatalf("pin changed to %s without an explicit trust", cur)
	}

	// The operator's explicit decision: trust the server certificate.
	got, err := rpc.TrustServerCert(ctx, apiURL, d.pins, real)
	if err != nil || got != real {
		t.Fatalf("TrustServerCert = %q, %v; want %s", got, err, real)
	}
	if st := d.probe(); st != softether.StatePasswordSet {
		t.Fatalf("probe after trust = %v, want password-set", st)
	}
	d.wantRedirect(d.do("GET", "/", nil), "/login")
	d.wantRedirect(d.login(adminPassword), "/dashboard")
}
