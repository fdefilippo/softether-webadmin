package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/rpc/rpctest"
	"github.com/fdefilippo/softether-webadmin/internal/tlsself"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := out.String(); got != "softether-webadmin dev\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestRunUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"setup-token", "--fingerprint", "ab"}, // flag of another subcommand
		{"serve", "--nope"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("run(%v) exit = %d, want 2", args, code)
		}
	}
}

func TestRunMissingConfig(t *testing.T) {
	for _, cmd := range []string{"serve", "setup-token", "trust-server-cert"} {
		var out, errb bytes.Buffer
		code := run([]string{cmd, "--config", filepath.Join(t.TempDir(), "nope.toml")}, &out, &errb)
		if code != 1 {
			t.Errorf("%s: exit = %d, want 1", cmd, code)
		}
		if errb.Len() == 0 || out.Len() != 0 {
			t.Errorf("%s: stdout=%q stderr=%q", cmd, out.String(), errb.String())
		}
	}
}

// writeConfig writes a config file with the given TOML body and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSetupTokenCommand(t *testing.T) {
	runtime := t.TempDir()
	cfg := writeConfig(t, fmt.Sprintf("runtime_dir = %q\n", runtime))

	var out, errb bytes.Buffer
	if code := run([]string{"setup-token", "--config", cfg}, &out, &errb); code != 1 {
		t.Fatalf("without token: exit = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("without token: stdout = %q, want empty", out.String())
	}
	if want := "no active setup token (server already configured or daemon not running)"; !strings.Contains(errb.String(), want) {
		t.Errorf("without token: stderr = %q", errb.String())
	}

	if err := os.WriteFile(filepath.Join(runtime, "setup-token"), []byte("tok-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"setup-token", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("with token: exit = %d, stderr = %q", code, errb.String())
	}
	if out.String() != "tok-123\n" {
		t.Errorf("stdout = %q, want only the token and a newline", out.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errb.String())
	}

	// An empty token file is the same as no token.
	if err := os.WriteFile(filepath.Join(runtime, "setup-token"), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"setup-token", "--config", cfg}, &out, &errb); code != 1 || out.Len() != 0 {
		t.Errorf("empty token file: exit = %d, stdout = %q", code, out.String())
	}
}

func TestTrustServerCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	want := rpc.Fingerprint(srv.Certificate().Raw)

	state := t.TempDir()
	cfg := writeConfig(t, fmt.Sprintf("state_dir = %q\nsoftether_url = %q\n", state, srv.URL+"/api/"))
	pin := filepath.Join(state, "server-cert.sha256")

	// Wrong fingerprint: exit 1, nothing saved.
	wrong := strings.Repeat("00", 32)
	var out, errb bytes.Buffer
	if code := run([]string{"trust-server-cert", "--config", cfg, "--fingerprint", wrong}, &out, &errb); code != 1 {
		t.Fatalf("wrong fingerprint: exit = %d", code)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Errorf("pin written despite a wrong fingerprint (stat err = %v)", err)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), want) {
		t.Errorf("wrong fingerprint: stdout = %q stderr = %q (stderr should show the presented fingerprint)", out.String(), errb.String())
	}

	// No --fingerprint: trusts what the server presents.
	out.Reset()
	errb.Reset()
	if code := run([]string{"trust-server-cert", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errb.String())
	}
	got, ok, err := (rpc.PinStore{Path: pin}).Load()
	if err != nil || !ok || got != want {
		t.Fatalf("pin = %q ok=%v err=%v, want %q", got, ok, err, want)
	}
	if !strings.Contains(out.String(), want) {
		t.Errorf("stdout = %q, want the fingerprint", out.String())
	}
}

func TestTrustServerCertFingerprintFormats(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	want := rpc.Fingerprint(srv.Certificate().Raw)

	var colon []string
	for i := 0; i < len(want); i += 2 {
		colon = append(colon, strings.ToUpper(want[i:i+2]))
	}
	forms := map[string]string{
		"plain":      want,
		"upper":      strings.ToUpper(want),
		"colon":      strings.Join(colon, ":"),
		"openssl":    " " + strings.Join(colon, ":") + "\n",
		"with-space": strings.Join(colon[:16], ":") + " " + strings.Join(colon[16:], ":"),
	}
	for name, fp := range forms {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			cfg := writeConfig(t, fmt.Sprintf("state_dir = %q\nsoftether_url = %q\n", state, srv.URL+"/api/"))
			var out, errb bytes.Buffer
			if code := run([]string{"trust-server-cert", "--config", cfg, "--fingerprint", fp}, &out, &errb); code != 0 {
				t.Fatalf("exit = %d, stderr = %q", code, errb.String())
			}
			got, _, _ := (rpc.PinStore{Path: filepath.Join(state, "server-cert.sha256")}).Load()
			if got != want {
				t.Errorf("pin = %q, want %q", got, want)
			}
		})
	}
}

func TestTrustServerCertRejectsBadInput(t *testing.T) {
	state := t.TempDir()
	pin := filepath.Join(state, "server-cert.sha256")
	for name, tc := range map[string]struct{ url, fp string }{
		"not hex":       {"https://127.0.0.1:1/api/", strings.Repeat("zz", 32)},
		"too short":     {"https://127.0.0.1:1/api/", "abcd"},
		"http url":      {"http://127.0.0.1:5555/api/", ""},
		"no host":       {"https:///api/", ""},
		"not a url":     {"127.0.0.1:5555", ""},
		"empty url":     {"", ""},
		"bad colon hex": {"https://127.0.0.1:1/api/", "ab:cd:ef:gh"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := writeConfig(t, fmt.Sprintf("state_dir = %q\nsoftether_url = %q\n", state, tc.url))
			args := []string{"trust-server-cert", "--config", cfg}
			if tc.fp != "" {
				args = append(args, "--fingerprint", tc.fp)
			}
			var out, errb bytes.Buffer
			if code := run(args, &out, &errb); code != 1 {
				t.Errorf("exit = %d, want 1 (stderr %q)", code, errb.String())
			}
			if errb.Len() == 0 || out.Len() != 0 {
				t.Errorf("stdout = %q stderr = %q", out.String(), errb.String())
			}
			if _, err := os.Stat(pin); !os.IsNotExist(err) {
				t.Errorf("pin written (stat err = %v)", err)
			}
		})
	}
}

func TestTrustServerCertUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	cfg := writeConfig(t, fmt.Sprintf("state_dir = %q\nsoftether_url = \"https://%s/api/\"\n", t.TempDir(), addr))
	var out, errb bytes.Buffer
	if code := run([]string{"trust-server-cert", "--config", cfg}, &out, &errb); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// lockedBuffer is a bytes.Buffer safe for the concurrent writers of serve.
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

// waitForPin waits until the first probe has pinned the fake server's
// certificate, so that no background write is left when the test ends.
func waitForPin(t *testing.T, stateDir string) {
	t.Helper()
	pin := filepath.Join(stateDir, pinFileName)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(pin); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server certificate was not pinned")
}

func TestServe(t *testing.T) {
	fake := rpctest.New(t) // empty administrator password
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.SoftEtherURL = fake.URL()
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.RuntimeDir = filepath.Join(dir, "run")
	cfg.AdminIPPath = filepath.Join(dir, "adminip.txt")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedBuffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logs, func(a net.Addr) { ready <- a }) }()

	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve returned early: %v\nlogs: %s", err, logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("serve not ready")
	}

	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	resp, err := client.Get("https://" + addr.String() + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Errorf("GET / = %d, Location %q; want a redirect to /setup", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("TLS state = %+v", resp.TLS)
	}

	// The self-signed certificate was created, with private permissions, and
	// its fingerprint logged.
	certPath := filepath.Join(cfg.StateDir, "tls", "cert.pem")
	keyPath := filepath.Join(cfg.StateDir, "tls", "key.pem")
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key: %v, %v", st, err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Error(err)
	}
	if st, err := os.Stat(cfg.StateDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("state dir: %v, %v", st, err)
	}
	fp := rpc.Fingerprint(resp.TLS.PeerCertificates[0].Raw)
	if !strings.Contains(logs.String(), fp) {
		t.Errorf("logs lack the HTTPS certificate fingerprint %s:\n%s", fp, logs.String())
	}
	for _, want := range []string{addr.String(), fake.URL()} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %q:\n%s", want, logs.String())
		}
	}
	// The first connection to the fake server pinned its certificate.
	if got, ok, _ := (rpc.PinStore{Path: filepath.Join(cfg.StateDir, "server-cert.sha256")}).Load(); !ok || got != rpc.Fingerprint(fake.Cert().Raw) {
		t.Errorf("server pin = %q ok=%v", got, ok)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v after cancel, want nil", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop after cancel")
	}
	if _, err := client.Get("https://" + addr.String() + "/"); err == nil {
		t.Error("listener still accepting after shutdown")
	}
}

func TestServeConfiguredCertificate(t *testing.T) {
	// A configured certificate is served as is.
	fake := rpctest.New(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "my-cert.pem"), filepath.Join(dir, "my-key.pem")
	if _, err := tlsself.EnsureSelfSigned(certPath, keyPath, []string{"example.test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.SoftEtherURL = fake.URL()
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.RuntimeDir = filepath.Join(dir, "run")
	cfg.AdminIPPath = filepath.Join(dir, "adminip.txt")
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedBuffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logs, func(a net.Addr) { ready <- a }) }()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve: %v", err)
	}

	waitForPin(t, cfg.StateDir)
	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	got := rpc.Fingerprint(conn.ConnectionState().PeerCertificates[0].Raw)
	conn.Close()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := rpc.Fingerprint(pair.Certificate[0]); got != want || !strings.Contains(logs.String(), want) {
		t.Errorf("served %s, configured %s; logs:\n%s", got, want, logs.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestServeRejectsHalfConfiguredTLS(t *testing.T) {
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.RuntimeDir = filepath.Join(t.TempDir(), "run")
	cfg.TLSCert = "/some/cert.pem"
	if err := serve(context.Background(), cfg, &lockedBuffer{}, nil); err == nil {
		t.Error("serve accepted tls_cert without tls_key")
	}
}

// serveBriefly starts serve with cfg, waits until it listens, stops it and
// returns its logs.
func serveBriefly(t *testing.T, cfg config.Config) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &lockedBuffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logs, func(a net.Addr) { ready <- a }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve returned early: %v\nlogs: %s", err, logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("serve not ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	return logs.String()
}

// adminIPRecords returns the log records about adminip.txt.
func adminIPRecords(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if msg, _ := m["msg"].(string); strings.Contains(msg, "adminip.txt") {
			out = append(out, m)
		}
	}
	return out
}

// I2 (design 5.1): adminip.txt is classified at startup and the result is
// written to the journal: WARN when the administration is not limited to
// loopback (or the file cannot be read), INFO when it is.
func TestServeLogsAdminIPIsolation(t *testing.T) {
	cases := []struct {
		name    string
		content *string // nil: missing; "<dir>": a directory (read error)
		level   string
		want    []string // substrings of the record
	}{
		{"isolated", ptr("127.0.0.1/32\n::1/128\n"), "INFO", nil},
		{"missing", nil, "WARN", []string{`"missing":true`}},
		{"not isolated", ptr("10.1.2.3/24\nbogus!\n127.0.0.1\n"), "WARN", []string{`"offending":["10.1.2.3/24"]`, `"ignored":["bogus!"]`}},
		{"unreadable", ptr("<dir>"), "WARN", []string{`"err":`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := rpctest.New(t)
			dir := t.TempDir()
			cfg := config.Default()
			cfg.Listen = "127.0.0.1:0"
			cfg.SoftEtherURL = fake.URL()
			cfg.StateDir = filepath.Join(dir, "state")
			cfg.RuntimeDir = filepath.Join(dir, "run")
			cfg.AdminIPPath = filepath.Join(dir, "adminip.txt")
			switch {
			case c.content == nil:
			case *c.content == "<dir>":
				if err := os.Mkdir(cfg.AdminIPPath, 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(cfg.AdminIPPath, []byte(*c.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			logs := serveBriefly(t, cfg)
			recs := adminIPRecords(t, logs)
			if len(recs) != 1 {
				t.Fatalf("%d adminip.txt records, want 1:\n%s", len(recs), logs)
			}
			if recs[0]["level"] != c.level || recs[0]["path"] != cfg.AdminIPPath {
				t.Fatalf("record = %v, want level %s and path %s", recs[0], c.level, cfg.AdminIPPath)
			}
			raw, _ := json.Marshal(recs[0])
			for _, w := range c.want {
				if !strings.Contains(string(raw), w) {
					t.Errorf("record %s lacks %s", raw, w)
				}
			}
		})
	}
}

func ptr(s string) *string { return &s }

// T8: credentials never go in softether_url (they would be sent and logged
// with every request): a URL with userinfo is refused, by serve and by
// trust-server-cert, without echoing the secret.
func TestSoftEtherURLWithUserinfoIsRefused(t *testing.T) {
	const secret = "s3cr3t-pw"
	for _, raw := range []string{
		"https://admin:" + secret + "@127.0.0.1:5555/api/",
		"https://" + secret + "@127.0.0.1:5555/api/",
		"https://admin:" + secret + "@[::1/api/", // unparseable too
	} {
		err := validateSoftEtherURL(raw)
		if err == nil {
			t.Errorf("validateSoftEtherURL(%q) = nil", raw)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error echoes the secret: %v", err)
		}
	}

	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.SoftEtherURL = "https://admin:" + secret + "@127.0.0.1:5555/api/"
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.RuntimeDir = filepath.Join(t.TempDir(), "run")
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// If serve wrongly starts, stop it at once so that the test fails, not hangs.
	err := serve(ctx, cfg, logs, func(net.Addr) { cancel() })
	if err == nil {
		t.Fatal("serve accepted a softether_url with userinfo")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("secret leaked: err %v, logs %s", err, logs.String())
	}

	var out, errb bytes.Buffer
	path := writeConfig(t, fmt.Sprintf("state_dir = %q\nsoftether_url = %q\n", t.TempDir(), cfg.SoftEtherURL))
	if code := run([]string{"trust-server-cert", "--config", path}, &out, &errb); code != 1 || strings.Contains(errb.String(), secret) {
		t.Fatalf("trust-server-cert: exit %d, stderr %q", code, errb.String())
	}
}
