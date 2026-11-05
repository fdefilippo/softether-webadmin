package web

import (
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
