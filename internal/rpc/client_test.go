package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeAPI is a TLS server mimicking the SoftEther /api/ endpoint.
type fakeAPI struct {
	*httptest.Server
	hits atomic.Int64

	mu     sync.Mutex
	auth   string
	body   []byte
	status int
	reply  string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{status: http.StatusOK, reply: `{"jsonrpc":"2.0","id":"1","result":{"ServerType_u32":0}}`}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.auth = r.Header.Get("Authorization")
		f.body = body
		status, reply := f.status, f.reply
		f.mu.Unlock()
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) url() string { return f.Server.URL + "/api/" }

func (f *fakeAPI) set(status int, reply string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.reply = status, reply
}

func newPins(t *testing.T) PinStore {
	t.Helper()
	return PinStore{Path: filepath.Join(t.TempDir(), "state", "server-cert.sha256")}
}

func TestCallSendsBasicAuthAndEnvelope(t *testing.T) {
	srv := newFakeAPI(t)
	c := NewClient(srv.url(), newPins(t), true)

	var res struct {
		ServerType uint32 `json:"ServerType_u32"`
	}
	params := map[string]any{"Foo_str": "bar"}
	if err := c.Call(context.Background(), Credential{"", "pa:ss è"}, "Test", params, &res); err != nil {
		t.Fatalf("Call: %v", err)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":pa:ss è"))
	if srv.lastAuth() != want {
		t.Errorf("Authorization = %q, want %q", srv.lastAuth(), want)
	}
	var env struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      string         `json:"id"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if err := json.Unmarshal(srv.lastBody(), &env); err != nil {
		t.Fatalf("body %q: %v", srv.lastBody(), err)
	}
	if env.JSONRPC != "2.0" || env.Method != "Test" || env.ID == "" || env.Params["Foo_str"] != "bar" {
		t.Errorf("unexpected envelope: %s", srv.lastBody())
	}
}

func TestCallBasicAuthWithUsername(t *testing.T) {
	srv := newFakeAPI(t)
	c := NewClient(srv.url(), newPins(t), true)
	if err := c.Call(context.Background(), Credential{"hub:admin", "x"}, "Test", nil, nil); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("hub:admin:x"))
	if srv.lastAuth() != want {
		t.Errorf("Authorization = %q, want %q", srv.lastAuth(), want)
	}
	if !strings.Contains(string(srv.lastBody()), `"params"`) {
		t.Errorf("nil params must still produce a params member: %s", srv.lastBody())
	}
}

func TestCall401(t *testing.T) {
	srv := newFakeAPI(t)
	srv.set(http.StatusUnauthorized, "")
	c := NewClient(srv.url(), newPins(t), true)
	err := c.Call(context.Background(), Credential{}, "Test", nil, nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestCallOtherHTTPStatusIsNotUnauthorizedNorUnreachable(t *testing.T) {
	srv := newFakeAPI(t)
	srv.set(http.StatusInternalServerError, "")
	c := NewClient(srv.url(), newPins(t), true)
	err := c.Call(context.Background(), Credential{}, "Test", nil, nil)
	if err == nil || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
}

func TestCallAPIError(t *testing.T) {
	srv := newFakeAPI(t)
	srv.set(http.StatusOK, `{"jsonrpc":"2.0","id":"1","error":{"code":52,"message":"Not enough privileges."}}`)
	c := NewClient(srv.url(), newPins(t), true)
	err := c.Call(context.Background(), Credential{}, "CreateHub", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Code != 52 || apiErr.Message != "Not enough privileges." {
		t.Errorf("apiErr = %+v", apiErr)
	}
}

func TestCallBadJSON(t *testing.T) {
	srv := newFakeAPI(t)
	srv.set(http.StatusOK, `<html>`)
	c := NewClient(srv.url(), newPins(t), true)
	err := c.Call(context.Background(), Credential{}, "Test", nil, new(struct{}))
	if err == nil || errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
}

func TestCallUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := NewClient("https://"+addr+"/api/", newPins(t), true)
	err = c.Call(context.Background(), Credential{}, "Test", nil, nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestCallContextCanceledIsUnreachable(t *testing.T) {
	srv := newFakeAPI(t)
	c := NewClient(srv.url(), newPins(t), true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.Call(ctx, Credential{}, "Test", nil, nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if srv.hits.Load() != 0 {
		t.Error("request reached the server")
	}
}

func TestTOFUSavesPinThenMismatch(t *testing.T) {
	srv := newFakeAPI(t)
	pins := newPins(t)
	c := NewClient(srv.url(), pins, true)

	if err := c.Call(context.Background(), Credential{}, "Test", nil, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	want := Fingerprint(srv.Certificate().Raw)
	got, ok, err := pins.Load()
	if err != nil || !ok || got != want {
		t.Fatalf("pin = (%q, %v, %v), want %q", got, ok, err, want)
	}
	if c.ObservedFingerprint() != want {
		t.Errorf("ObservedFingerprint = %q, want %q", c.ObservedFingerprint(), want)
	}

	// A second call with the right pin works even though connections are never reused.
	if err := c.Call(context.Background(), Credential{}, "Test", nil, nil); err != nil {
		t.Fatalf("second call: %v", err)
	}

	bad := strings.Repeat("00", 32)
	if err := pins.Save(bad); err != nil {
		t.Fatal(err)
	}
	before := srv.hits.Load()
	err = c.Call(context.Background(), Credential{"", "secret"}, "Test", nil, nil)
	var mm *CertMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("err = %v, want *CertMismatchError", err)
	}
	if mm.Pinned != bad || mm.Presented != want {
		t.Errorf("mismatch = %+v", mm)
	}
	if srv.hits.Load() != before {
		t.Error("server received a request despite the certificate mismatch")
	}
	if c.ObservedFingerprint() != want {
		t.Errorf("ObservedFingerprint after mismatch = %q, want %q", c.ObservedFingerprint(), want)
	}
	// The mismatch must not overwrite the pin.
	if got, _, _ := pins.Load(); got != bad {
		t.Errorf("pin was changed to %q", got)
	}
}

func TestNoTOFUWithoutPin(t *testing.T) {
	srv := newFakeAPI(t)
	pins := newPins(t)
	c := NewClient(srv.url(), pins, false)
	err := c.Call(context.Background(), Credential{}, "Test", nil, nil)
	var mm *CertMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("err = %v, want *CertMismatchError", err)
	}
	if mm.Pinned != "" || mm.Presented != Fingerprint(srv.Certificate().Raw) {
		t.Errorf("mismatch = %+v", mm)
	}
	if srv.hits.Load() != 0 {
		t.Error("server received a request without a pin")
	}
	if _, ok, _ := pins.Load(); ok {
		t.Error("pin was saved although TOFU is disabled")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var other atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.Add(1)
	}))
	defer target.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	c := NewClient(redir.URL+"/api/", newPins(t), true)
	err := c.Call(context.Background(), Credential{"", "secret"}, "Test", nil, nil)
	if err == nil {
		t.Fatal("expected an error on redirect")
	}
	if other.Load() != 0 {
		t.Error("redirect was followed")
	}
}

func TestIgnoresProxyEnvironment(t *testing.T) {
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	srv := newFakeAPI(t)
	c := NewClient(srv.url(), newPins(t), true)
	if err := c.Call(context.Background(), Credential{"", "x"}, "Test", nil, nil); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 0 {
		t.Error("request went through the environment proxy")
	}
}

func TestCredentialRedaction(t *testing.T) {
	c := Credential{"admin", "hunter2"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(&c)} {
		if strings.Contains(s, "hunter2") {
			t.Errorf("password leaked in %q", s)
		}
	}
}

func TestTrustServerCertSaves(t *testing.T) {
	srv := newFakeAPI(t)
	pins := newPins(t)
	got, err := TrustServerCert(context.Background(), srv.url(), pins, "")
	if err != nil {
		t.Fatal(err)
	}
	want := Fingerprint(srv.Certificate().Raw)
	if got != want {
		t.Errorf("returned %q, want %q", got, want)
	}
	if saved, ok, err := pins.Load(); err != nil || !ok || saved != want {
		t.Errorf("pin = (%q, %v, %v), want %q", saved, ok, err, want)
	}
	if srv.hits.Load() != 0 {
		t.Error("TrustServerCert sent an HTTP request")
	}
}

func TestTrustServerCertExpectedMatchCaseInsensitive(t *testing.T) {
	srv := newFakeAPI(t)
	pins := newPins(t)
	want := Fingerprint(srv.Certificate().Raw)
	got, err := TrustServerCert(context.Background(), srv.url(), pins, strings.ToUpper(want))
	if err != nil || got != want {
		t.Fatalf("got (%q, %v), want %q", got, err, want)
	}
	if saved, ok, _ := pins.Load(); !ok || saved != want {
		t.Errorf("pin = %q, %v", saved, ok)
	}
}

func TestTrustServerCertExpectedMismatch(t *testing.T) {
	srv := newFakeAPI(t)
	pins := newPins(t)
	_, err := TrustServerCert(context.Background(), srv.url(), pins, strings.Repeat("00", 32))
	var mm *CertMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("err = %v, want *CertMismatchError", err)
	}
	if _, statErr := os.Stat(pins.Path); !os.IsNotExist(statErr) {
		t.Errorf("pin file created despite mismatch: %v", statErr)
	}
}

func TestTrustServerCertUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	pins := newPins(t)
	_, err = TrustServerCert(context.Background(), "https://"+addr+"/api/", pins, "")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if _, statErr := os.Stat(pins.Path); !os.IsNotExist(statErr) {
		t.Error("pin file created")
	}
}

func (f *fakeAPI) lastAuth() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth
}

func (f *fakeAPI) lastBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body
}
