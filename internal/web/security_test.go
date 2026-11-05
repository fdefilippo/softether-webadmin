package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
)

const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

func ok200(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(http.HandlerFunc(ok200)).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	want := map[string]string{
		"Content-Security-Policy": wantCSP,
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}
	for k, v := range want {
		if vals := rec.Header().Values(k); len(vals) != 1 || vals[0] != v {
			t.Errorf("%s = %q, want exactly %q", k, vals, v)
		}
	}
}

func TestSecurityHeadersOnRedirectAndError(t *testing.T) {
	h := SecurityHeaders(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 404 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("code=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

func newTestStore() (*SessionStore, *fakeClock) {
	clk := newClock()
	return NewSessionStore(30*time.Minute, 8*time.Hour, clk.Now), clk
}

func TestRequireSessionRedirect(t *testing.T) {
	st, _ := newTestStore()
	h := SecurityHeaders(RequireSession(st, http.HandlerFunc(ok200)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/vhubs", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("plain: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	req := httptest.NewRequest("GET", "/vhubs", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("htmx: code=%d HX-Redirect=%q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
	if rec.Header().Get("Location") != "" {
		t.Error("htmx response must not carry a Location header")
	}
}

func TestRequireSessionPassesAndExposesSession(t *testing.T) {
	st, _ := newTestStore()
	s := st.Create(rpc.Credential{Password: "x"}, "en")
	var seen *Session
	h := RequireSession(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = SessionFrom(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: s.ID})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen == nil || seen.ID != s.ID {
		t.Fatalf("session not in context: %v", seen)
	}
}

// Review Focus 4: back button / reopened URL after logout.
func TestBackAfterLogout(t *testing.T) {
	st, _ := newTestStore()
	s := st.Create(rpc.Credential{}, "en")
	st.Destroy(s.ID)

	h := SecurityHeaders(RequireSession(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("protected handler must not run after logout")
	})))
	req := httptest.NewRequest("GET", "/vhubs", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: s.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "abc")
	c := rec.Result().Cookies()[0]
	if c.Name != "swa_session" || c.Value != "abc" || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie = %+v", c)
	}
	rec = httptest.NewRecorder()
	ClearSessionCookie(rec)
	c = rec.Result().Cookies()[0]
	if c.Name != "swa_session" || c.MaxAge >= 0 || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("clear cookie = %+v", c)
	}
}

func TestCSRF(t *testing.T) {
	st, _ := newTestStore()
	s := st.Create(rpc.Credential{}, "en")
	h := RequireSession(st, CSRF(http.HandlerFunc(ok200)))

	do := func(method, body string, hdr map[string]string) int {
		req := httptest.NewRequest(method, "/x", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: s.ID})
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	form := func(tok string) string { return url.Values{"csrf": {tok}}.Encode() }

	if c := do("POST", "", nil); c != 403 {
		t.Errorf("POST without token = %d, want 403", c)
	}
	if c := do("POST", form("wrong"), nil); c != 403 {
		t.Errorf("POST wrong form token = %d, want 403", c)
	}
	if c := do("POST", form(s.CSRF), nil); c != 200 {
		t.Errorf("POST form token = %d, want 200", c)
	}
	if c := do("POST", "", map[string]string{"X-CSRF-Token": s.CSRF}); c != 200 {
		t.Errorf("POST header token = %d, want 200", c)
	}
	if c := do("POST", "", map[string]string{"X-CSRF-Token": "wrong"}); c != 403 {
		t.Errorf("POST wrong header token = %d, want 403", c)
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		if c := do(m, "", nil); c != 403 {
			t.Errorf("%s without token = %d, want 403", m, c)
		}
		if c := do(m, "", map[string]string{"X-CSRF-Token": s.CSRF}); c != 200 {
			t.Errorf("%s with token = %d, want 200", m, c)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if c := do(m, "", nil); c != 200 {
			t.Errorf("%s = %d, want 200 (safe method)", m, c)
		}
	}
}

func TestCSRFWithoutSessionRejects(t *testing.T) {
	h := CSRF(http.HandlerFunc(ok200))
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("X-CSRF-Token", "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("POST without a session = %d, want 403", rec.Code)
	}
}

func TestLoginLimiter(t *testing.T) {
	clk := newClock()
	l := NewLoginLimiter(5, 15*time.Minute, clk.Now)
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("Allow false after %d failures", i)
		}
		l.Fail("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("Allow must be false after 5 failures")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("another IP must be unaffected")
	}
	clk.Add(14 * time.Minute)
	if l.Allow("1.2.3.4") {
		t.Fatal("still blocked inside the window")
	}
	clk.Add(2 * time.Minute)
	if !l.Allow("1.2.3.4") {
		t.Fatal("Allow must be true again after the window")
	}
}

func TestLoginLimiterReset(t *testing.T) {
	l := NewLoginLimiter(2, time.Hour, newClock().Now)
	l.Fail("a")
	l.Fail("a")
	l.Reset("a")
	if !l.Allow("a") {
		t.Fatal("Reset must clear the failures")
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := ClientIP(req); got != "10.0.0.7" {
		t.Fatalf("ClientIP = %q", got)
	}
	req.RemoteAddr = "[::1]:80"
	if got := ClientIP(req); got != "::1" {
		t.Fatalf("ClientIP = %q", got)
	}
	req.RemoteAddr = "garbage"
	if got := ClientIP(req); got != "garbage" {
		t.Fatalf("ClientIP = %q", got)
	}
}
