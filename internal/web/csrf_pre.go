package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PreCSRFCookie is the cookie of the pre-session CSRF token.
const PreCSRFCookie = "swa_csrf"

const preCSRFTTL = 2 * time.Hour

type preCSRFKey struct{}

// preCSRF protects the forms shown without a session (login and first-access
// setup), where the per-session token of CSRF cannot exist yet.
//
// Design: signed double-submit cookie. The token is
// "<expiry unix>.<random nonce>.<HMAC-SHA256(key, expiry.nonce)>", the key
// being random per process. The same value is set as the HttpOnly, Secure,
// SameSite=Strict cookie swa_csrf and embedded in the form's hidden "csrf"
// field. A POST is accepted only if the cookie is validly signed and not
// expired and the form field equals the cookie (constant-time comparison).
// SameSite=Strict already keeps the cookie off cross-site POSTs; the
// signature stops an attacker who can plant a cookie (e.g. from a sibling
// subdomain) from choosing a value they also know, because they cannot sign
// one; and the server keeps no state per token. A restart invalidates the
// outstanding tokens, which only costs a page reload.
type preCSRF struct {
	key []byte
	now func() time.Time
}

func newPreCSRF(now func() time.Time) *preCSRF {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("web: crypto/rand failed: " + err.Error())
	}
	return &preCSRF{key: k, now: now}
}

func (p *preCSRF) sign(payload string) string {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *preCSRF) issue() string {
	payload := strconv.FormatInt(p.now().Add(preCSRFTTL).Unix(), 10) + "." + randomToken()
	return payload + "." + p.sign(payload)
}

// valid reports whether tok carries a correct signature and has not expired.
func (p *preCSRF) valid(tok string) bool {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return false
	}
	payload, sig := tok[:i], tok[i+1:]
	if !hmac.Equal([]byte(sig), []byte(p.sign(payload))) {
		return false
	}
	expStr, _, _ := strings.Cut(payload, ".")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	return err == nil && p.now().Unix() < exp
}

// token returns the request's valid pre-session token, or sets a new cookie.
func (p *preCSRF) token(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(PreCSRFCookie); err == nil && p.valid(c.Value) {
		return c.Value
	}
	tok := p.issue()
	http.SetCookie(w, &http.Cookie{
		Name: PreCSRFCookie, Value: tok, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	return tok
}

// page wraps a handler that renders a form: it makes sure the cookie exists
// and passes the token to the templates through the request context.
func (p *preCSRF) page(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := p.token(w, r)
		next.ServeHTTP(w, r.WithContext(contextWithPreCSRF(r, tok)))
	})
}

// protect rejects unsafe requests whose "csrf" field does not match a valid
// pre-session cookie. Safe methods pass (and get a token for their form).
func (p *preCSRF) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			p.page(next).ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(PreCSRFCookie)
		field := r.PostFormValue("csrf")
		if err != nil || !p.valid(c.Value) || field == "" ||
			subtle.ConstantTimeCompare([]byte(field), []byte(c.Value)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Keep the token in the context so that a re-rendered form (error
		// page) carries the same value as the cookie.
		next.ServeHTTP(w, r.WithContext(contextWithPreCSRF(r, c.Value)))
	})
}

func contextWithPreCSRF(r *http.Request, tok string) context.Context {
	return context.WithValue(r.Context(), preCSRFKey{}, tok)
}
