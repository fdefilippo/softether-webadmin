package web

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
)

type fakeClock struct{ t time.Time }

func newClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time      { return c.t }
func (c *fakeClock) Add(d time.Duration) { c.t = c.t.Add(d) }

func TestSessionCreateGet(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(30*time.Minute, 8*time.Hour, clk.Now)
	s := st.Create(rpc.Credential{Password: "pw"}, "it")
	if len(s.ID) != 43 || len(s.CSRF) != 43 { // 32 bytes, unpadded base64url
		t.Fatalf("ID/CSRF length = %d/%d, want 43/43", len(s.ID), len(s.CSRF))
	}
	if s.ID == s.CSRF {
		t.Fatal("ID and CSRF must differ")
	}
	got, ok := st.Get(s.ID)
	if !ok || got.CSRF != s.CSRF || got.Lang != "it" || got.Cred.Password != "pw" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if _, ok := st.Get("nope"); ok {
		t.Fatal("unknown id must not be valid")
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(30*time.Minute, 8*time.Hour, clk.Now)
	s := st.Create(rpc.Credential{}, "en")

	clk.Add(29 * time.Minute)
	if _, ok := st.Get(s.ID); !ok {
		t.Fatal("session expired before the idle timeout")
	}
	// Get refreshed LastSeen: another 29 minutes is still fine.
	clk.Add(29 * time.Minute)
	if _, ok := st.Get(s.ID); !ok {
		t.Fatal("Get must refresh LastSeen")
	}
	clk.Add(31 * time.Minute)
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("session must expire after more than 30 minutes idle")
	}
	// Once expired it stays gone.
	clk.Add(-31 * time.Minute)
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("expired session must be destroyed")
	}
}

func TestSessionMaxExpiry(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(30*time.Minute, 8*time.Hour, clk.Now)
	s := st.Create(rpc.Credential{}, "en")
	for i := 0; i < 15; i++ { // 15 x 29 min = 7h15
		clk.Add(29 * time.Minute)
		if _, ok := st.Get(s.ID); !ok {
			t.Fatalf("session expired early at step %d", i)
		}
	}
	for i := 0; i < 3; i++ { // keep it busy past 8h
		clk.Add(29 * time.Minute)
		if _, ok := st.Get(s.ID); !ok {
			if clk.Now().Sub(s.Created) <= 8*time.Hour {
				t.Fatalf("expired before the absolute limit (%v)", clk.Now().Sub(s.Created))
			}
			return
		}
	}
	t.Fatal("session survived past 8 hours of continuous use")
}

func TestSessionDestroy(t *testing.T) {
	st := NewSessionStore(time.Minute, time.Hour, newClock().Now)
	s := st.Create(rpc.Credential{}, "en")
	st.Destroy(s.ID)
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("destroyed session must not be valid")
	}
	st.Destroy("unknown") // must not panic
}

func TestSessionDoesNotLeakPassword(t *testing.T) {
	const pw = "s3cr3t-pw é"
	st := NewSessionStore(time.Minute, time.Hour, newClock().Now)
	s := st.Create(rpc.Credential{Username: "alice", Password: pw}, "en")
	for _, out := range []string{
		fmt.Sprintf("%+v", *s), fmt.Sprintf("%#v", *s), fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprint(s), fmt.Sprintf("%s", s),
	} {
		if strings.Contains(out, pw) {
			t.Errorf("password leaked: %s", out)
		}
		if strings.Contains(out, s.ID) || strings.Contains(out, s.CSRF) {
			t.Errorf("session secrets leaked: %s", out)
		}
	}
}
