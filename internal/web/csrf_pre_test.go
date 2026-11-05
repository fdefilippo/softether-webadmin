package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPreCSRFTokenValidity(t *testing.T) {
	clk := newClock()
	p := newPreCSRF(clk.Now)
	tok := p.issue()
	if !p.valid(tok) {
		t.Fatal("fresh token rejected")
	}
	if p.valid(tok + "x") {
		t.Fatal("tampered signature accepted")
	}
	if i := strings.Index(tok, "."); p.valid("9999999999" + tok[i:]) {
		t.Fatal("tampered expiry accepted")
	}
	if newPreCSRF(clk.Now).valid(tok) {
		t.Fatal("token accepted by a server with another key")
	}
	clk.Add(preCSRFTTL + time.Second)
	if p.valid(tok) {
		t.Fatal("expired token accepted")
	}
	for _, bad := range []string{"", ".", "a.b", "a.b.c"} {
		if p.valid(bad) {
			t.Errorf("garbage %q accepted", bad)
		}
	}
}

func TestPreCSRFReissuedWhenHalfExpired(t *testing.T) {
	clk := newClock()
	p := newPreCSRF(clk.Now)
	tok := p.issue()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: PreCSRFCookie, Value: tok})
	if got := p.token(rec, req); got != tok || len(rec.Result().Cookies()) != 0 {
		t.Fatal("a young token must be reused without a new cookie")
	}

	clk.Add(preCSRFTTL/2 + time.Minute) // less than half of the lifetime left
	rec = httptest.NewRecorder()
	got := p.token(rec, req)
	if got == tok || !p.valid(got) || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("an ageing token must be replaced by a fresh cookie (got %q)", got)
	}
}
