package web

import (
	"bytes"
	"context"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/rpc/rpctest"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

const (
	adminPassword = "pa:ss è long enough"
	otherPassword = "another password 123"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type env struct {
	t       *testing.T
	fake    *rpctest.FakeServer
	srv     *Server
	cfg     config.Config
	audit   *lockedBuffer
	clock   *fakeClock
	cat     Catalog
	pins    rpc.PinStore
	adminIP string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := rpctest.New(t)
	dir := t.TempDir()
	pins := rpc.PinStore{Path: filepath.Join(dir, "pin")}
	if err := pins.Save(rpc.Fingerprint(fake.Cert().Raw)); err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, fake, pins, dir)
}

func newEnvWith(t *testing.T, fake *rpctest.FakeServer, pins rpc.PinStore, dir string) *env {
	t.Helper()
	cfg := config.Default()
	cfg.RuntimeDir = filepath.Join(dir, "run")
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.AdminIPPath = filepath.Join(dir, "adminip.txt")
	cfg.SoftEtherURL = fake.URL()

	clock := newClock()
	client := rpc.NewClient(fake.URL(), pins, false)
	prober := softether.Prober{Client: client}
	mgr := setup.NewManager(cfg.RuntimeDir, client, prober, slog.New(slog.NewTextHandler(io.Discard, nil)))
	buf := &lockedBuffer{}
	srv := NewServer(Deps{
		Cfg: cfg, Client: client, Prober: prober, Setup: mgr,
		Sessions: NewSessionStore(cfg.SessionIdle, cfg.SessionMax, clock.Now),
		Audit:    audit.New(buf),
		Now:      clock.Now,
	})
	cat, err := EmbeddedCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, fake: fake, srv: srv, cfg: cfg, audit: buf, clock: clock, cat: cat, pins: pins, adminIP: cfg.AdminIPPath}
}

// configured returns an env whose server already has a password and whose
// adminip.txt is isolated.
func configured(t *testing.T) *env {
	e := newEnv(t)
	e.fake.SetPassword(adminPassword)
	e.writeAdminIP("127.0.0.1/32\n::1/128\n")
	e.srv.ProbeOnce(context.Background())
	return e
}

func (e *env) writeAdminIP(s string) {
	e.t.Helper()
	if err := os.WriteFile(e.adminIP, []byte(s), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) tr(key string, args ...any) string { return e.cat.T("en", key, args...) }

// browser keeps cookies between requests (ignoring the Secure flag, which
// httptest does not care about).
type browser struct {
	e       *env
	cookies map[string]string
	lastRec *httptest.ResponseRecorder
}

func (e *env) browser() *browser { return &browser{e: e, cookies: map[string]string{}} }

func (b *browser) do(method, target string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for k, v := range b.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rec := httptest.NewRecorder()
	b.e.srv.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	b.lastRec = rec
	return rec
}

func (b *browser) get(target string) *httptest.ResponseRecorder {
	return b.do("GET", target, nil, nil)
}

func (b *browser) post(target string, form url.Values) *httptest.ResponseRecorder {
	return b.do("POST", target, form, nil)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// formCSRF loads page and extracts the CSRF token of its form.
func (b *browser) formCSRF(page string) string {
	b.e.t.Helper()
	rec := b.get(page)
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		b.e.t.Fatalf("no csrf field in %s (code %d):\n%s", page, rec.Code, rec.Body.String())
	}
	return m[1]
}

func (b *browser) login(password string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	return b.post("/login", url.Values{"csrf": {b.formCSRF("/login")}, "password": {password}})
}

func (b *browser) mustLogin(password string) {
	b.e.t.Helper()
	rec := b.login(password)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		b.e.t.Fatalf("login: code %d location %q\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

// sessionCSRF is the CSRF token of the browser's session.
func (b *browser) sessionCSRF() string {
	b.e.t.Helper()
	s, ok := b.e.srv.d.Sessions.Get(b.cookies[SessionCookie])
	if !ok {
		b.e.t.Fatal("browser has no valid session")
	}
	return s.CSRF
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		t.Fatalf("got %d Location=%q, want 303 %q\n%s", rec.Code, rec.Header().Get("Location"), to, rec.Body.String())
	}
}

func wantBody(t *testing.T, rec *httptest.ResponseRecorder, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(rec.Body.String(), w) && !strings.Contains(rec.Body.String(), html.EscapeString(w)) {
			t.Errorf("body lacks %q\n%s", w, rec.Body.String())
		}
	}
}

func (e *env) setupToken() string {
	e.t.Helper()
	tok, err := setup.ReadTokenFile(e.cfg.RuntimeDir)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (b *browser) postSetup(token, pw, pw2 string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	return b.post("/setup", url.Values{"csrf": {b.formCSRF("/setup")}, "token": {token}, "password": {pw}, "password2": {pw2}})
}

// --- setup -----------------------------------------------------------------

func TestFreshServerRedirectsToSetup(t *testing.T) {
	e := newEnv(t)
	if st := e.srv.ProbeOnce(context.Background()); st != softether.StateEmptyPassword {
		t.Fatalf("state = %v", st)
	}
	b := e.browser()
	wantRedirect(t, b.get("/"), "/setup")
	wantRedirect(t, b.get("/login"), "/setup")
	wantRedirect(t, b.get("/dashboard"), "/setup")
	rec := b.get("/setup")
	if rec.Code != 200 {
		t.Fatalf("/setup = %d", rec.Code)
	}
	wantBody(t, rec, `name="token"`, `name="password2"`)
}

func TestSetupWrongToken(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	b := e.browser()
	rec := b.postSetup("WRONGTOKEN", "a good long password", "a good long password")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	wantBody(t, rec, e.tr("setup.bad_token"))
	if e.fake.MethodCount("SetServerPassword") != 0 {
		t.Fatal("password write reached the server")
	}
	// The server password is still empty: any credential works.
	if err := rpc.NewClient(e.fake.URL(), e.pins, false).Test(context.Background(), rpc.Credential{Password: "x"}); err != nil {
		t.Fatalf("password must still be empty: %v", err)
	}
}

func TestSetupPasswordMismatchAndWeak(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	b := e.browser()
	tok := e.setupToken()
	rec := b.postSetup(tok, "a good long password", "a different long password")
	wantBody(t, rec, e.tr("setup.password_mismatch"))
	rec = b.postSetup(tok, "short", "short")
	wantBody(t, rec, e.tr("setup.weak_password"))
	if e.fake.MethodCount("SetServerPassword") != 0 {
		t.Fatal("password write reached the server")
	}
	// A weak password does not consume the token.
	rec = b.postSetup(tok, adminPassword, adminPassword)
	wantRedirect(t, rec, "/dashboard")
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	b := e.browser()
	rec := b.postSetup(e.setupToken(), adminPassword, adminPassword)
	wantRedirect(t, rec, "/dashboard")

	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" {
		t.Fatalf("session cookie = %+v", sc)
	}
	// The fake now has the password, and the new session works.
	if err := rpc.NewClient(e.fake.URL(), e.pins, false).Test(context.Background(), rpc.Credential{Password: adminPassword}); err != nil {
		t.Fatalf("new password does not work: %v", err)
	}
	if err := rpc.NewClient(e.fake.URL(), e.pins, false).Test(context.Background(), rpc.Credential{Password: "wrong"}); err == nil {
		t.Fatal("password was not set")
	}
	if rec := b.get("/dashboard"); rec.Code != 200 {
		t.Fatalf("/dashboard = %d", rec.Code)
	}
	if e.srv.d.Setup.Active() {
		t.Fatal("token still active after setup")
	}
	// /setup is no longer available.
	wantRedirect(t, b.get("/setup"), "/login")
}

func TestSetupAlreadyConfiguredRedirectsToLogin(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	b := e.browser()
	tok := e.setupToken()
	csrf := b.formCSRF("/setup")
	e.fake.SetPassword(otherPassword) // somebody else won the race
	rec := b.post("/setup", url.Values{"csrf": {csrf}, "token": {tok}, "password": {adminPassword}, "password2": {adminPassword}})
	wantRedirect(t, rec, "/login?notice=configured")
	wantBody(t, e.browser().get("/login?notice=configured"), e.tr("setup.already_configured"))

	// A second submit after the token is gone gives the same answer (ErrNoToken).
	rec = b.post("/setup", url.Values{"csrf": {csrf}, "token": {tok}, "password": {adminPassword}, "password2": {adminPassword}})
	wantRedirect(t, rec, "/login?notice=configured")
}

func TestSetupUnreachableAndUncertain(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		e := newEnv(t)
		e.srv.ProbeOnce(context.Background())
		b := e.browser()
		tok := e.setupToken()
		csrf := b.formCSRF("/setup")
		e.fake.Stop()
		rec := b.post("/setup", url.Values{"csrf": {csrf}, "token": {tok}, "password": {adminPassword}, "password2": {adminPassword}})
		wantRedirect(t, rec, "/unreachable")
		wantBody(t, b.get("/unreachable"), e.tr("unreachable.title"))
	})
	t.Run("uncertain", func(t *testing.T) {
		e := newEnv(t)
		e.srv.ProbeOnce(context.Background())
		b := e.browser()
		tok := e.setupToken()
		csrf := b.formCSRF("/setup")
		e.fake.StopAfter("SetServerPassword") // applied, then the server vanishes
		rec := b.post("/setup", url.Values{"csrf": {csrf}, "token": {tok}, "password": {adminPassword}, "password2": {adminPassword}})
		if rec.Code != 200 {
			t.Fatalf("code = %d\n%s", rec.Code, rec.Body.String())
		}
		wantBody(t, rec, e.tr("uncertain.title"), `hx-get="/status"`, `hx-trigger="load, every 3s"`)
		if e.fake.MethodCount("SetServerPassword") != 1 {
			t.Fatalf("write sent %d times", e.fake.MethodCount("SetServerPassword"))
		}
		// While the server is down, the status fragment keeps polling.
		s := b.get("/status")
		wantBody(t, s, e.tr("status.unreachable"), `hx-trigger="every 3s"`)
		// Back up with the password set: the fragment says to log in and stops polling.
		e.fake.Start()
		e.clock.Add(time.Minute)
		s = b.get("/status")
		wantBody(t, s, e.tr("status.password_set"), `href="/login"`)
		if strings.Contains(s.Body.String(), "every 3s") {
			t.Fatal("fragment must stop polling once the password is set")
		}
		if strings.Contains(s.Body.String(), "<html") {
			t.Fatal("status must be a fragment")
		}
	})
}

func TestStatusEmptyPasswordSendsBackToSetup(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	rec := e.browser().get("/status")
	wantBody(t, rec, `href="/setup"`, e.tr("status.empty_password"))
}

// --- login -----------------------------------------------------------------

func TestLoginSuccess(t *testing.T) {
	e := configured(t)
	b := e.browser()
	rec := b.login(adminPassword) // contains ':', space and a non-ASCII rune
	wantRedirect(t, rec, "/dashboard")
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v", sc)
	}
	wantRedirect(t, b.get("/"), "/dashboard")
	wantRedirect(t, b.get("/login"), "/dashboard")
}

func TestLoginWrongPassword(t *testing.T) {
	e := configured(t)
	b := e.browser()
	for i := 1; i <= 5; i++ {
		rec := b.login("wrong")
		if rec.Code != 200 {
			t.Fatalf("attempt %d: code %d", i, rec.Code)
		}
		wantBody(t, rec, e.tr("login.failed"))
		if !strings.Contains(e.tr("login.failed"), "adminip.txt") || !strings.Contains(strings.ToLower(e.tr("login.failed")), "password") {
			t.Fatalf("login.failed must mention the password and adminip.txt: %q", e.tr("login.failed"))
		}
	}
	before := e.fake.MethodCount("Test")
	rec := b.login(adminPassword) // right password, but the 6th attempt
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: code %d, want 429", rec.Code)
	}
	wantBody(t, rec, e.tr("login.rate_limited"))
	if e.fake.MethodCount("Test") != before {
		t.Fatal("rate-limited attempt reached the VPN server")
	}
	if !strings.Contains(e.audit.String(), `"action":"login_rate_limited"`) {
		t.Fatalf("no login_rate_limited audit event:\n%s", e.audit.String())
	}
}

func TestLoginSuccessResetsLimiter(t *testing.T) {
	e := configured(t)
	b := e.browser()
	for i := 0; i < 4; i++ {
		b.login("wrong")
	}
	b.mustLogin(adminPassword)
	b2 := e.browser()
	for i := 0; i < 5; i++ {
		if rec := b2.login("wrong"); rec.Code != 200 {
			t.Fatalf("attempt %d: code %d (limiter was not reset)", i, rec.Code)
		}
	}
}

func TestLoginRequiresCSRF(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.get("/login") // gets the pre-session cookie
	for name, form := range map[string]url.Values{
		"missing": {"password": {adminPassword}},
		"forged":  {"csrf": {"x.y.z"}, "password": {adminPassword}},
	} {
		if rec := b.post("/login", form); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code %d, want 403", name, rec.Code)
		}
	}
	// A valid token from one browser does not work with another's cookie.
	tok := e.browser().formCSRF("/login")
	if rec := b.post("/login", url.Values{"csrf": {tok}, "password": {adminPassword}}); rec.Code != http.StatusForbidden {
		t.Errorf("token/cookie mismatch: code %d, want 403", rec.Code)
	}
	// And no cookie at all.
	if rec := e.browser().post("/login", url.Values{"csrf": {tok}, "password": {adminPassword}}); rec.Code != http.StatusForbidden {
		t.Errorf("no cookie: code %d, want 403", rec.Code)
	}
	if e.fake.MethodCount("Test") != 1 { // only the probe
		t.Fatalf("Test called %d times", e.fake.MethodCount("Test"))
	}
}

func TestSetupRequiresCSRF(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	b := e.browser()
	b.get("/setup")
	rec := b.post("/setup", url.Values{"token": {e.setupToken()}, "password": {adminPassword}, "password2": {adminPassword}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if e.fake.MethodCount("SetServerPassword") != 0 {
		t.Fatal("write reached the server")
	}
}

func TestLogout(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	old := b.cookies[SessionCookie]

	if rec := b.post("/logout", url.Values{}); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf = %d, want 403", rec.Code)
	}
	rec := b.post("/logout", url.Values{"csrf": {b.sessionCSRF()}})
	wantRedirect(t, rec, "/login")
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie not cleared")
	}
	// Replaying the old cookie: no data, back to the login page.
	b.cookies[SessionCookie] = old
	wantRedirect(t, b.get("/dashboard"), "/login")
	if !strings.Contains(e.audit.String(), `"action":"logout"`) {
		t.Fatal("no logout audit event")
	}
}

// --- dashboard -------------------------------------------------------------

func TestDashboardShowsServerInfo(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	rec := b.get("/dashboard")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	wantBody(t, rec, "Version 5.02 Build 5189 (English)", "SoftEther VPN Server (Fake)", "fake-vpnserver")
	for h, want := range map[string]string{
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": contentSecurityPolicy,
	} {
		if rec.Header().Get(h) != want {
			t.Errorf("%s = %q", h, rec.Header().Get(h))
		}
	}
}

func TestDashboardRequiresSession(t *testing.T) {
	e := configured(t)
	b := e.browser()
	wantRedirect(t, b.get("/dashboard"), "/login")
	rec := b.do("GET", "/dashboard", nil, map[string]string{"HX-Request": "true"})
	if rec.Code != 200 || rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("htmx: %d %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

func TestDashboardIsolationBanner(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)

	// Isolated: no banner at all.
	rec := b.get("/dashboard")
	if strings.Contains(rec.Body.String(), "/adminip/restrict") {
		t.Fatalf("banner shown for an isolated adminip.txt:\n%s", rec.Body.String())
	}

	// Missing.
	if err := os.Remove(e.adminIP); err != nil {
		t.Fatal(err)
	}
	rec = b.get("/dashboard")
	wantBody(t, rec, e.tr("adminip.missing"), `action="/adminip/restrict"`, `name="confirm" value="yes"`, `name="csrf"`)

	// Offending lines (and an ignored one, listed separately).
	e.writeAdminIP("10.1.2.3/24\n127.0.0.1\nbogus!\n")
	rec = b.get("/dashboard")
	wantBody(t, rec, e.tr("adminip.not_isolated"), "10.1.2.3/24", e.tr("adminip.ignored"), "bogus!", `action="/adminip/restrict"`)
	if strings.Contains(rec.Body.String(), e.tr("adminip.missing")) {
		t.Fatal("missing message shown for an existing file")
	}

	// Isolated but with an ignored line: only the ignored warning.
	e.writeAdminIP("127.0.0.1\nbogus!\n")
	rec = b.get("/dashboard")
	wantBody(t, rec, e.tr("adminip.ignored"), "bogus!")
	if strings.Contains(rec.Body.String(), "/adminip/restrict") || strings.Contains(rec.Body.String(), e.tr("adminip.not_isolated")) {
		t.Fatalf("isolation banner for an isolated file:\n%s", rec.Body.String())
	}
}

func TestRestrictAdminIPRequiresConfirm(t *testing.T) {
	e := configured(t)
	e.writeAdminIP("0.0.0.0/0\n")
	b := e.browser()
	b.mustLogin(adminPassword)
	csrf := b.sessionCSRF()

	if rec := b.post("/adminip/restrict", url.Values{"csrf": {csrf}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("without confirm: %d, want 400", rec.Code)
	}
	if rec := b.post("/adminip/restrict", url.Values{"csrf": {csrf}, "confirm": {"no"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm=no: %d, want 400", rec.Code)
	}
	if rec := b.post("/adminip/restrict", url.Values{"confirm": {"yes"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf: %d, want 403", rec.Code)
	}
	if iso, _ := softether.ClassifyAdminIP(e.adminIP); iso.Isolated {
		t.Fatal("file was rewritten without confirmation")
	}

	rec := b.post("/adminip/restrict", url.Values{"csrf": {csrf}, "confirm": {"yes"}})
	if rec.Code != 200 {
		t.Fatalf("with confirm: %d\n%s", rec.Code, rec.Body.String())
	}
	iso, err := softether.ClassifyAdminIP(e.adminIP)
	if err != nil || !iso.Isolated {
		t.Fatalf("file not isolated: %+v %v", iso, err)
	}
	backups, _ := filepath.Glob(e.adminIP + ".bak-*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	wantBody(t, rec, backups[0])
	if !strings.Contains(e.audit.String(), `"action":"adminip_restricted"`) {
		t.Fatal("no adminip_restricted audit event")
	}
}

// --- failure modes ---------------------------------------------------------

func TestServerStopsWhileLoggedIn(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	cookie := b.cookies[SessionCookie]
	ctx := context.Background()

	e.fake.Stop()
	if st := e.srv.ProbeOnce(ctx); st != softether.StateUnreachable {
		t.Fatalf("state = %v", st)
	}
	wantRedirect(t, b.get("/"), "/unreachable")
	wantRedirect(t, b.get("/dashboard"), "/unreachable")
	rec := b.get("/unreachable")
	if rec.Code != 200 {
		t.Fatalf("/unreachable = %d", rec.Code)
	}
	wantBody(t, rec, e.tr("unreachable.title"))
	if b.cookies[SessionCookie] != cookie {
		t.Fatal("session cookie was dropped")
	}

	e.fake.Start()
	if st := e.srv.ProbeOnce(ctx); st != softether.StatePasswordSet {
		t.Fatalf("state = %v", st)
	}
	rec = b.get("/dashboard")
	if rec.Code != 200 {
		t.Fatalf("/dashboard after restart = %d (session lost?)\n%s", rec.Code, rec.Body.String())
	}
	if b.cookies[SessionCookie] != cookie {
		t.Fatal("session cookie changed")
	}
}

func TestServerStopsBetweenProbesShowsUnreachable(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	e.fake.Stop()
	// The state is still "password set": the dashboard call itself fails.
	wantRedirect(t, b.get("/dashboard"), "/unreachable")
	if _, ok := e.srv.d.Sessions.Get(b.cookies[SessionCookie]); !ok {
		t.Fatal("session destroyed by an unreachable server")
	}
	e.fake.Start()
	e.srv.ProbeOnce(context.Background())
	if rec := b.get("/dashboard"); rec.Code != 200 {
		t.Fatalf("/dashboard = %d", rec.Code)
	}
}

func TestUnauthorizedDestroysSession(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	old := b.cookies[SessionCookie]

	e.fake.SetPassword(otherPassword)
	wantRedirect(t, b.get("/dashboard"), "/login")
	if _, ok := e.srv.d.Sessions.Get(old); ok {
		t.Fatal("session still valid")
	}
	b.cookies[SessionCookie] = old
	wantRedirect(t, b.get("/dashboard"), "/login")
	if !strings.Contains(e.audit.String(), `"action":"session_expired_unauthorized"`) {
		t.Fatalf("no session_expired_unauthorized event:\n%s", e.audit.String())
	}
}

func TestUnauthorizedOnHTMXRequestUsesHXRedirect(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	e.fake.SetPassword(otherPassword)
	rec := b.do("GET", "/dashboard", nil, map[string]string{"HX-Request": "true"})
	if rec.Code != 200 || rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("code %d HX-Redirect %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

func TestCertMismatchPage(t *testing.T) {
	fake := rpctest.New(t)
	dir := t.TempDir()
	pins := rpc.PinStore{Path: filepath.Join(dir, "pin")}
	wrong := strings.Repeat("ab", 32)
	if err := pins.Save(wrong); err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, fake, pins, dir)
	if st := e.srv.ProbeOnce(context.Background()); st != softether.StateCertMismatch {
		t.Fatalf("state = %v", st)
	}
	b := e.browser()
	wantRedirect(t, b.get("/"), "/certmismatch")
	wantRedirect(t, b.get("/login"), "/certmismatch")
	presented := rpc.Fingerprint(fake.Cert().Raw)
	rec := b.get("/certmismatch")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	wantBody(t, rec, presented, wrong, "softether-webadmin trust-server-cert --fingerprint "+presented)
	if fake.MethodCount("Test") != 0 {
		t.Fatal("a request (and its credentials) reached a server with a mismatched certificate")
	}
}

func TestPagesAreLocalizedWithNegotiate(t *testing.T) {
	e := configured(t)
	b := e.browser()
	rec := b.do("GET", "/login", nil, map[string]string{"Accept-Language": "it"})
	wantBody(t, rec, `<html lang="it">`, e.cat.T("it", "login.submit"))
	// The cookie wins over the header.
	b.cookies[LangCookie] = "en"
	rec = b.do("GET", "/login", nil, map[string]string{"Accept-Language": "it"})
	wantBody(t, rec, `<html lang="en">`, e.cat.T("en", "login.submit"))
}

func TestOversizedBodyIsRejected(t *testing.T) {
	e := configured(t)
	b := e.browser()
	csrf := b.formCSRF("/login")
	rec := b.post("/login", url.Values{"csrf": {csrf}, "password": {strings.Repeat("x", 2<<20)}})
	if rec.Code == 200 || rec.Code == http.StatusSeeOther {
		t.Fatalf("2 MiB body accepted: %d", rec.Code)
	}
	if e.fake.MethodCount("Test") != 1 { // only the probe
		t.Fatal("oversized login reached the server")
	}
}

func TestStaticAndLangRoutes(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background()) // EmptyPassword: these must stay reachable
	b := e.browser()
	if rec := b.get("/static/app.css"); rec.Code != 200 {
		t.Fatalf("/static/app.css = %d", rec.Code)
	}
	rec := b.get("/lang?l=it&next=/setup")
	wantRedirect(t, rec, "/setup")
}

// --- probe and audit -------------------------------------------------------

func TestProbeOnceSweepsExpiredSessions(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	id := b.cookies[SessionCookie]
	e.clock.Add(e.cfg.SessionIdle + time.Minute)
	e.srv.ProbeOnce(context.Background())
	e.srv.d.Sessions.mu.Lock()
	_, there := e.srv.d.Sessions.sessions[id]
	e.srv.d.Sessions.mu.Unlock()
	if there {
		t.Fatal("expired session (holding the password) still in memory after ProbeOnce")
	}
}

func TestRunProbeLoop(t *testing.T) {
	e := newEnv(t)
	e.srv.d.Cfg.ProbeInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.RunProbeLoop(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for e.fake.MethodCount("Test") < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.fake.MethodCount("Test") < 3 {
		t.Fatal("probe loop did not probe repeatedly")
	}
	wantRedirect(t, e.browser().get("/"), "/setup") // the immediate probe set the state
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunProbeLoop did not stop after cancel")
	}
}

func TestAuditNoSecrets(t *testing.T) {
	e := newEnv(t)
	e.srv.ProbeOnce(context.Background())
	tok := e.setupToken()
	b := e.browser()
	b.postSetup("WRONG-"+tok, adminPassword, adminPassword)
	wantRedirect(t, b.postSetup(tok, adminPassword, adminPassword), "/dashboard")
	b.post("/logout", url.Values{"csrf": {b.sessionCSRF()}})
	b2 := e.browser()
	b2.login("not-the-" + adminPassword)
	b2.login(adminPassword)

	out := e.audit.String()
	for _, secret := range []string{adminPassword, "not-the-" + adminPassword, tok, b2.cookies[SessionCookie], b2.cookies["swa_csrf"]} {
		if secret != "" && strings.Contains(out, secret) {
			t.Fatalf("audit output contains a secret %q:\n%s", secret, out)
		}
	}
	for _, action := range []string{"setup_failed", "setup_completed", "logout", "login_failed", "login_succeeded"} {
		if !strings.Contains(out, `"action":"`+action+`"`) {
			t.Errorf("missing audit action %s:\n%s", action, out)
		}
	}
	if !strings.Contains(out, `"remote_ip":"192.0.2.1"`) {
		t.Errorf("audit lacks remote_ip:\n%s", out)
	}
}

// --- fix round 1 -----------------------------------------------------------

func TestLoginParallelAttemptsAreBounded(t *testing.T) {
	e := configured(t)
	const n = 30
	bs := make([]*browser, n)
	forms := make([]url.Values, n)
	for i := range bs {
		bs[i] = e.browser()
		forms[i] = url.Values{"csrf": {bs[i].formCSRF("/login")}, "password": {"wrong"}}
	}
	before := e.fake.MethodCount("Test")
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range bs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = bs[i].post("/login", forms[i]).Code
		}()
	}
	wg.Wait()
	if got := e.fake.MethodCount("Test") - before; got > e.cfg.LoginMaxFailures {
		t.Fatalf("%d parallel logins reached the VPN server, limit is %d", got, e.cfg.LoginMaxFailures)
	}
	limited := 0
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != n-e.cfg.LoginMaxFailures {
		t.Fatalf("%d requests got 429, want %d", limited, n-e.cfg.LoginMaxFailures)
	}
}

func TestLoginUnreachableDoesNotConsumeAttempts(t *testing.T) {
	e := configured(t)
	b := e.browser()
	csrf := b.formCSRF("/login")
	e.fake.Stop()
	for i := 0; i < 10; i++ {
		b.post("/login", url.Values{"csrf": {csrf}, "password": {"x"}})
	}
	e.fake.Start()
	e.srv.ProbeOnce(context.Background())
	b2 := e.browser()
	if rec := b2.login("wrong"); rec.Code != 200 {
		t.Fatalf("code = %d, outage attempts must not count as failures", rec.Code)
	}
}

func TestRestrictAdminIPWithoutExistingFile(t *testing.T) {
	e := configured(t)
	if err := os.Remove(e.adminIP); err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	b.mustLogin(adminPassword)
	rec := b.post("/adminip/restrict", url.Values{"csrf": {b.sessionCSRF()}, "confirm": {"yes"}})
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	wantBody(t, rec, e.tr("adminip.done_nobackup"))
	if strings.Contains(rec.Body.String(), "%!") {
		t.Fatalf("formatting error in body:\n%s", rec.Body.String())
	}
	if iso, _ := softether.ClassifyAdminIP(e.adminIP); !iso.Isolated {
		t.Fatal("file not created")
	}
}

func (e *env) stateNow() softether.State {
	st, _, _ := e.srv.snapshot()
	return st
}

func TestAbortedRequestDoesNotChangeState(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	serve := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", target, nil).WithContext(cancelled)
		for k, v := range b.cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		rec := httptest.NewRecorder()
		e.srv.ServeHTTP(rec, req)
		return rec
	}

	serve("/dashboard")
	if st := e.stateNow(); st != softether.StatePasswordSet {
		t.Fatalf("aborted /dashboard changed the state to %v", st)
	}
	if _, ok := e.srv.d.Sessions.Get(b.cookies[SessionCookie]); !ok {
		t.Fatal("aborted request destroyed the session")
	}

	e.clock.Add(time.Minute) // make the stored probe stale
	serve("/status")         // on-demand probe must not depend on the client
	if st := e.stateNow(); st != softether.StatePasswordSet {
		t.Fatalf("aborted /status changed the state to %v", st)
	}
	if rec := b.get("/dashboard"); rec.Code != 200 {
		t.Fatalf("/dashboard after the aborted requests = %d", rec.Code)
	}
}

func TestPreSessionCSRFFailureRerendersLocalizedForm(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.cookies[LangCookie] = "it"
	b.get("/login")
	rec := b.post("/login", url.Values{"csrf": {"expired.token.x"}, "password": {adminPassword}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	wantBody(t, rec, e.cat.T("it", "csrf.expired"), `name="password"`)
	if strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatal("bare English text in the response")
	}
	// The fresh token in the page works with the fresh cookie.
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no fresh csrf field")
	}
	wantRedirect(t, b.post("/login", url.Values{"csrf": {m[1]}, "password": {adminPassword}}), "/dashboard")

	e2 := newEnv(t)
	e2.srv.ProbeOnce(context.Background())
	b2 := e2.browser()
	b2.get("/setup")
	rec = b2.post("/setup", url.Values{"csrf": {"nope"}, "token": {"x"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/setup: code = %d", rec.Code)
	}
	wantBody(t, rec, e2.tr("csrf.expired"), `name="token"`)
}

func TestSessionCSRFForbiddenIsLocalized(t *testing.T) {
	e := configured(t)
	b := e.browser()
	b.mustLogin(adminPassword)
	b.cookies[LangCookie] = "it"
	rec := b.post("/logout", url.Values{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), e.cat.T("it", "error.forbidden")) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// C1: the administrator password removed from outside (vpncmd
// ServerPasswordSet with an empty password) while the cached state still says
// "password set". SoftEther then accepts any credential, so a successful Test
// proves nothing: the login must re-probe and must not open a session.
func TestLoginAfterExternalPasswordRemovalGoesToSetup(t *testing.T) {
	e := configured(t)
	b := e.browser()
	csrf := b.formCSRF("/login") // the cached state is still "password set"
	e.fake.SetPassword("")
	rec := b.post("/login", url.Values{"csrf": {csrf}, "password": {"anything at all"}})
	wantRedirect(t, rec, "/setup")
	if _, ok := b.cookies[SessionCookie]; ok {
		t.Fatal("a session cookie was set")
	}
	e.srv.d.Sessions.mu.Lock()
	n := len(e.srv.d.Sessions.sessions)
	e.srv.d.Sessions.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d sessions created, want 0", n)
	}
	if st := e.stateNow(); st != softether.StateEmptyPassword {
		t.Fatalf("state = %v, want empty-password", st)
	}
	if !e.srv.d.Setup.Active() {
		t.Fatal("no setup token generated for the empty password")
	}
	if strings.Contains(e.audit.String(), `"action":"login_succeeded"`) {
		t.Fatalf("login_succeeded audited:\n%s", e.audit.String())
	}
	wantRedirect(t, b.get("/dashboard"), "/setup")
}
