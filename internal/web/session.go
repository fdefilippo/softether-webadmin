// Package web holds the HTTP layer of softether-webadmin: sessions, security
// middleware, i18n and page rendering.
package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
)

// Session is one logged-in administrator. It lives only in memory and holds
// the SoftEther credential used for that user's JSON-RPC calls.
type Session struct {
	ID, CSRF string
	Cred     rpc.Credential
	// Lang is the language negotiated at login. It is informational only:
	// pages are always rendered in Negotiate(r), so that the swa_lang cookie
	// takes effect immediately, even in an existing session.
	Lang     string
	Created  time.Time
	LastSeen time.Time
}

// String, GoString and LogValue never include the credential password, the
// session ID or the CSRF token, even when a Session is printed as a value
// (rpc.Credential's own redaction does not apply to fields of an outer
// struct printed with %+v).
func (s Session) String() string {
	return fmt.Sprintf("Session{User:%q Lang:%q Created:%s LastSeen:%s ID:<redacted> CSRF:<redacted> Password:<redacted>}",
		s.Cred.Username, s.Lang, s.Created.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer; see String.
func (s Session) GoString() string { return s.String() }

// LogValue implements slog.LogValuer; see String.
func (s Session) LogValue() slog.Value { return slog.StringValue(s.String()) }

// SessionStore keeps the sessions in memory. It is safe for concurrent use.
type SessionStore struct {
	idle, max time.Duration
	now       func() time.Time

	mu       sync.Mutex
	sessions map[string]*Session
	sweepAt  time.Time
}

// NewSessionStore returns a store whose sessions expire after idle without
// use, or max after creation, whichever comes first. now is the clock
// (time.Now in production).
func NewSessionStore(idle, max time.Duration, now func() time.Time) *SessionStore {
	if now == nil {
		now = time.Now
	}
	return &SessionStore{idle: idle, max: max, now: now, sessions: map[string]*Session{}}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("web: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create starts a new session for cred and returns a copy of it.
func (st *SessionStore) Create(cred rpc.Credential, lang string) *Session {
	now := st.now()
	s := &Session{ID: randomToken(), CSRF: randomToken(), Cred: cred, Lang: lang, Created: now, LastSeen: now}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked(now)
	st.sessions[s.ID] = s
	c := *s
	return &c
}

// Get returns a copy of the session with the given ID and refreshes its
// LastSeen. Expired sessions are removed and reported as not found.
func (st *SessionStore) Get(id string) (*Session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return nil, false
	}
	now := st.now()
	if st.expired(s, now) {
		delete(st.sessions, id)
		return nil, false
	}
	s.LastSeen = now
	c := *s
	return &c, true
}

// Destroy removes the session, if present.
func (st *SessionStore) Destroy(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, id)
}

func (st *SessionStore) expired(s *Session, now time.Time) bool {
	return now.Sub(s.LastSeen) > st.idle || now.Sub(s.Created) > st.max
}

// Sweep removes every expired session now. The probe loop calls it so that
// sessions nobody presents again do not keep the SoftEther password in
// memory until the next Create.
func (st *SessionStore) Sweep() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepAt = time.Time{}
	st.sweepLocked(st.now())
}

// sweepLocked drops expired sessions at most once a minute so that sessions
// that are never presented again do not accumulate.
func (st *SessionStore) sweepLocked(now time.Time) {
	if now.Before(st.sweepAt) {
		return
	}
	st.sweepAt = now.Add(time.Minute)
	for id, s := range st.sessions {
		if st.expired(s, now) {
			delete(st.sessions, id)
		}
	}
}

type ctxKey struct{}

// withSession returns ctx carrying s; RequireSession uses it so that CSRF and
// the Renderer can find the session without a second lookup.
func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// SessionFrom returns the session placed in ctx by RequireSession.
func SessionFrom(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok && s != nil
}
