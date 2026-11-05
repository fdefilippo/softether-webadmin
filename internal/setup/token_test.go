package setup

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/rpc/rpctest"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

const goodPassword = "correct horse battery"

type env struct {
	fake   *rpctest.FakeServer
	client *rpc.Client
	dir    string
	logs   *bytes.Buffer
	mgr    *Manager
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := rpctest.New(t)
	pins := rpc.PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := pins.Save(rpc.Fingerprint(fake.Cert().Raw)); err != nil {
		t.Fatal(err)
	}
	client := rpc.NewClient(fake.URL(), pins, false)
	e := &env{fake: fake, client: client, dir: filepath.Join(t.TempDir(), "run"), logs: &bytes.Buffer{}}
	e.mgr = e.newManager()
	return e
}

func (e *env) newManager() *Manager {
	logger := slog.New(slog.NewTextHandler(e.logs, nil))
	return NewManager(e.dir, e.client, softether.Prober{Client: e.client}, logger)
}

func (e *env) tokenFile(t *testing.T) string {
	t.Helper()
	tok, err := ReadTokenFile(e.dir)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	return tok
}

func TestRefreshGeneratesTokenFile(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if e.mgr.Active() {
		t.Fatal("Active() before Refresh")
	}
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	if !e.mgr.Active() {
		t.Fatal("Active() = false after Refresh(StateEmptyPassword)")
	}
	st, err := os.Stat(filepath.Join(e.dir, "setup-token"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, want 0600", st.Mode().Perm())
	}
	if dst, err := os.Stat(e.dir); err != nil || dst.Mode().Perm() != 0o700 {
		t.Errorf("runtime dir: %v, %v; want 0700", dst, err)
	}
	tok := e.tokenFile(t)
	if len(tok) != 52 || strings.ToUpper(tok) != tok || strings.ContainsAny(tok, "=\n 018") {
		t.Errorf("token %q is not 32 bytes of unpadded base32", tok)
	}
	if !strings.Contains(e.logs.String(), "level=WARN") ||
		!strings.Contains(e.logs.String(), `msg="setup token generated"`) ||
		!strings.Contains(e.logs.String(), "token="+tok) {
		t.Errorf("missing WARN line with the token in logs:\n%s", e.logs)
	}

	// The token is stable while the daemon runs.
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	if got := e.tokenFile(t); got != tok {
		t.Errorf("token changed on second Refresh: %q -> %q", tok, got)
	}
	if n := strings.Count(e.logs.String(), "setup token generated"); n != 1 {
		t.Errorf("token logged %d times, want 1", n)
	}
	// Other states change nothing.
	for _, st := range []softether.State{softether.StateUnreachable, softether.StateCertMismatch} {
		if err := e.mgr.Refresh(ctx, st); err != nil {
			t.Fatal(err)
		}
		if !e.mgr.Active() || e.tokenFile(t) != tok {
			t.Errorf("Refresh(%v) altered the token", st)
		}
	}
}

func TestCompleteHappyPath(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	if err := e.mgr.Complete(ctx, tok, goodPassword); err != nil {
		t.Fatal(err)
	}
	if e.mgr.Active() {
		t.Error("Active() = true after Complete")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "setup-token")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file still present: %v", err)
	}
	// The new password works, the empty one no longer does.
	if err := e.client.Test(ctx, rpc.Credential{Username: "", Password: goodPassword}); err != nil {
		t.Errorf("new password refused: %v", err)
	}
	if st, _ := (softether.Prober{Client: e.client}).Probe(ctx); st != softether.StatePasswordSet {
		t.Errorf("state after Complete = %v", st)
	}
	if strings.Contains(e.logs.String(), goodPassword) {
		t.Error("password leaked into logs")
	}
}

func TestCompleteBadToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	before := e.fake.Requests()
	if err := e.mgr.Complete(ctx, "WRONG", goodPassword); !errors.Is(err, ErrBadToken) {
		t.Fatalf("Complete = %v, want ErrBadToken", err)
	}
	if e.fake.Requests() != before {
		t.Error("a bad token caused RPC traffic")
	}
	if st, _ := (softether.Prober{Client: e.client}).Probe(ctx); st != softether.StateEmptyPassword {
		t.Errorf("server password changed: state = %v", st)
	}
	if !e.mgr.Active() {
		t.Error("a bad token consumed the real token")
	}
}

func TestCompleteNoToken(t *testing.T) {
	e := newEnv(t)
	if err := e.mgr.Complete(context.Background(), "", goodPassword); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Complete = %v, want ErrNoToken", err)
	}
}

func TestCompleteWeakPassword(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	before := e.fake.Requests()
	// 11 runes but more than 12 bytes: the limit counts characters.
	if err := e.mgr.Complete(ctx, tok, "èèèèèèèèèèè"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Complete = %v, want ErrWeakPassword", err)
	}
	if e.fake.Requests() != before {
		t.Error("weak password caused RPC traffic")
	}
	if !e.mgr.Active() {
		t.Error("weak password consumed the token")
	}
	// Exactly 12 runes is accepted.
	if err := e.mgr.Complete(ctx, tok, "èèèèèèèèèèèè"); err != nil {
		t.Fatalf("12-rune password rejected: %v", err)
	}
}

func TestCompleteConcurrent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = e.mgr.Complete(ctx, tok, goodPassword)
		}()
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrAlreadyConfigured), errors.Is(err, ErrNoToken):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d successes (%v), want exactly 1", ok, errs)
	}
}

func TestExternalPasswordSetInvalidates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	e.fake.SetPassword("x")
	if err := e.mgr.Refresh(ctx, softether.StatePasswordSet); err != nil {
		t.Fatal(err)
	}
	if e.mgr.Active() {
		t.Error("Active() = true after password set externally")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "setup-token")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file still present: %v", err)
	}
	// Refresh(StatePasswordSet) with nothing to clean is not an error.
	if err := e.mgr.Refresh(ctx, softether.StatePasswordSet); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteAlreadyConfigured(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	e.fake.SetPassword("set-elsewhere")
	if err := e.mgr.Complete(ctx, tok, goodPassword); !errors.Is(err, ErrAlreadyConfigured) {
		t.Fatalf("Complete = %v, want ErrAlreadyConfigured", err)
	}
	if e.mgr.Active() {
		t.Error("token still active although the password is set")
	}
}

func TestCompleteServerUnreachable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	e.fake.Stop()
	err := e.mgr.Complete(ctx, tok, goodPassword)
	if !errors.Is(err, rpc.ErrUnreachable) || errors.Is(err, ErrAlreadyConfigured) {
		t.Fatalf("Complete = %v, want an ErrUnreachable error", err)
	}
	if !e.mgr.Active() {
		t.Error("token consumed although nothing was sent")
	}
}

func TestRestartReplacesStaleToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const stale = "STALETOKENFROMAPREVIOUSDAEMONRUN234567ABCDEFGHIJKLM"
	if err := os.WriteFile(filepath.Join(e.dir, "setup-token"), []byte(stale+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := e.newManager() // simulates the restarted daemon
	if m.Active() {
		t.Fatal("a token found on disk was trusted")
	}
	if err := m.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	fresh := e.tokenFile(t)
	if fresh == stale {
		t.Fatal("stale token was kept")
	}
	if err := m.Complete(ctx, stale, goodPassword); !errors.Is(err, ErrBadToken) {
		t.Fatalf("Complete(stale) = %v, want ErrBadToken", err)
	}
	if err := m.Complete(ctx, fresh, goodPassword); err != nil {
		t.Fatalf("Complete(fresh) = %v", err)
	}
}

func TestCompleteUncertain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	before := e.fake.Requests()
	// The server applies the change, then dies without answering, and stays
	// down: the outcome cannot be verified.
	e.fake.StopAfter("SetServerPassword")
	err := e.mgr.Complete(ctx, tok, goodPassword)
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("Complete = %v, want ErrUncertain", err)
	}
	if !e.mgr.Active() {
		t.Error("token invalidated although the outcome is uncertain")
	}
	// Reached the server: probe + write only (the verification probe found it
	// down). Exact counts; the retry guard proper is in
	// TestCompleteUncertainNotApplied, where a retry could reach the server.
	if got := e.fake.Requests() - before; got != 2 {
		t.Errorf("server received %d requests, want 2", got)
	}
	if n := e.fake.MethodCount("SetServerPassword"); n != 1 {
		t.Errorf("SetServerPassword received %d times, want 1", n)
	}
}

// The write is lost before being applied and the server stays reachable: the
// verification probe still sees an empty password, so the result is uncertain.
// A retry of the write would reach the server and be counted, so this test
// guards the "never retry a write" rule.
func TestCompleteUncertainNotApplied(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	before := e.fake.Requests()
	e.fake.DropBefore("SetServerPassword")
	err := e.mgr.Complete(ctx, tok, goodPassword)
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("Complete = %v, want ErrUncertain", err)
	}
	if !e.mgr.Active() {
		t.Error("token invalidated although the outcome is uncertain")
	}
	if got := e.fake.Requests() - before; got != 3 { // probe + write + probe
		t.Errorf("server received %d requests, want 3", got)
	}
	if n := e.fake.MethodCount("SetServerPassword"); n != 1 {
		t.Errorf("SetServerPassword received %d times, want 1 (no retry)", n)
	}
	if st, _ := (softether.Prober{Client: e.client}).Probe(ctx); st != softether.StateEmptyPassword {
		t.Errorf("password changed although the write was never applied: %v", st)
	}
}

// When the response is lost but the follow-up probe shows the password set,
// the operation succeeded.
func TestCompleteLostResponseButApplied(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.mgr.Refresh(ctx, softether.StateEmptyPassword); err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFile(t)
	before := e.fake.Requests()
	e.fake.DropAfter("SetServerPassword") // applied, connection dropped, server stays up
	if err := e.mgr.Complete(ctx, tok, goodPassword); err != nil {
		t.Fatalf("Complete = %v, want success", err)
	}
	if e.mgr.Active() {
		t.Error("token still active after success")
	}
	// A retried write (empty credential) would be refused with 401 but is
	// still counted by the fake.
	if got := e.fake.Requests() - before; got != 3 { // probe + write + probe
		t.Errorf("server received %d requests, want 3", got)
	}
	if n := e.fake.MethodCount("SetServerPassword"); n != 1 {
		t.Errorf("SetServerPassword received %d times, want 1 (no retry)", n)
	}
}
