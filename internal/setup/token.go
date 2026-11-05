// Package setup implements the first-access protection of the web admin: a
// one-time token, written to a root-only file and to the journal, that proves
// the operator has local access before the VPN server's administrator
// password can be set. Without it, whoever reaches the UI first while the
// password is empty (when SoftEther accepts any credential) could claim the
// server.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

const (
	tokenFileName = "setup-token"
	tokenBytes    = 32
	// MinPasswordLen is the minimum length, in characters, of the new
	// administrator password.
	MinPasswordLen = 12
	// MaxPasswordBytes is the maximum length, in bytes, of the new
	// administrator password: SoftEther copies the password of the Basic
	// Authorization header into a MAX_PASSWORD_LEN (255) byte buffer
	// (Cedar/Admin.c HttpParseBasicAuthHeader), so a longer one could be set
	// but would never match at login.
	MaxPasswordBytes = 255
)

var (
	// ErrBadToken: the supplied token does not match the active one.
	ErrBadToken = errors.New("setup: invalid setup token")
	// ErrNoToken: no token is active (none generated, or already consumed).
	ErrNoToken = errors.New("setup: no setup token is active")
	// ErrAlreadyConfigured: the server already has an administrator password.
	ErrAlreadyConfigured = errors.New("setup: server is already configured")
	// ErrUncertain: the password change was sent but its outcome could not be
	// verified. The write is never retried; the operator must check the server.
	ErrUncertain = errors.New("setup: outcome of the password change is uncertain")
	// ErrWeakPassword: the new password is shorter than MinPasswordLen characters.
	ErrWeakPassword = errors.New("setup: password too weak")
	// ErrPasswordTooLong: the new password is longer than MaxPasswordBytes bytes.
	ErrPasswordTooLong = errors.New("setup: password too long")
	// ErrPasswordInvalid: the new password contains a NUL character, which
	// SoftEther would take as the end of the password at login.
	ErrPasswordInvalid = errors.New("setup: password contains a NUL character")
)

// Manager owns the setup token. It is safe for concurrent use.
type Manager struct {
	dir    string
	client *rpc.Client
	prober softether.Prober
	logger *slog.Logger

	op    sync.Mutex // serializes Refresh and Complete (held across RPC calls)
	mu    sync.Mutex // guards token only; never held across I/O on the server
	token string     // "" when no token is active
}

// NewManager returns a Manager that keeps the token file in runtimeDir. A
// token left on disk by a previous process is never trusted: it is replaced
// on the first Refresh(StateEmptyPassword).
func NewManager(runtimeDir string, client *rpc.Client, prober softether.Prober, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Manager{dir: runtimeDir, client: client, prober: prober, logger: logger}
}

func (m *Manager) path() string { return filepath.Join(m.dir, tokenFileName) }

func (m *Manager) current() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

func (m *Manager) set(tok string) {
	m.mu.Lock()
	m.token = tok
	m.mu.Unlock()
}

// Active reports whether a setup token is currently valid.
func (m *Manager) Active() bool { return m.current() != "" }

// Refresh aligns the token with the observed server state: with an empty
// password it makes sure a token exists, with a password set it invalidates
// the token and deletes the file, with any other state it does nothing.
func (m *Manager) Refresh(ctx context.Context, state softether.State) error {
	m.op.Lock()
	defer m.op.Unlock()

	switch state {
	case softether.StateEmptyPassword:
		return m.ensureToken()
	case softether.StatePasswordSet:
		return m.invalidate()
	}
	return nil
}

func (m *Manager) ensureToken() error {
	if tok := m.current(); tok != "" {
		// Keep the file in step with the in-memory token (e.g. if it was
		// removed by a tmpfiles cleaner).
		if onDisk, err := ReadTokenFile(m.dir); err != nil || onDisk != tok {
			return m.writeFile(tok)
		}
		return nil
	}
	var b [tokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Errorf("setup: generate token: %w", err)
	}
	tok := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	if err := m.writeFile(tok); err != nil {
		return err
	}
	m.set(tok)
	// The only place where the token is logged.
	m.logger.Warn("setup token generated", "token", tok)
	return nil
}

// writeFile atomically (temp file + rename) writes the token with mode 0600.
func (m *Manager) writeFile(tok string) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("setup: runtime dir: %w", err)
	}
	f, err := os.CreateTemp(m.dir, ".setup-token-*")
	if err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	if err := os.Rename(tmp, m.path()); err != nil {
		return fmt.Errorf("setup: write token: %w", err)
	}
	ok = true
	return nil
}

// invalidate forgets the token and deletes the file. The token is forgotten
// even if the file cannot be removed.
func (m *Manager) invalidate() error {
	m.set("")
	if err := os.Remove(m.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("setup: remove token file: %w", err)
	}
	return nil
}

// Complete sets the administrator password, provided token is the active
// setup token and the server still has an empty password. It is serialized:
// concurrent calls run one after the other. The JSON-RPC write is never
// retried.
func (m *Manager) Complete(ctx context.Context, token, newPassword string) error {
	m.op.Lock()
	defer m.op.Unlock()

	// 1. Token (constant time).
	active := m.current()
	if active == "" {
		return ErrNoToken
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(active)) != 1 {
		return ErrBadToken
	}
	// Password policy: checked before any RPC, does not consume the token.
	if utf8.RuneCountInString(newPassword) < MinPasswordLen {
		return ErrWeakPassword
	}
	if len(newPassword) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	if strings.IndexByte(newPassword, 0) >= 0 {
		return ErrPasswordInvalid
	}

	// 2. The server must still have an empty password.
	state, err := m.prober.Probe(ctx)
	switch state {
	case softether.StateEmptyPassword:
	case softether.StatePasswordSet:
		m.cleanup() // the token is moot
		return ErrAlreadyConfigured
	case softether.StateCertMismatch:
		return fmt.Errorf("setup: server certificate check failed: %w", err)
	default:
		return fmt.Errorf("setup: cannot verify server state: %w", rpc.ErrUnreachable)
	}

	// 3. The write. A transport error means the request may or may not have
	// been applied: go straight to the verification probe. No retry.
	err = m.client.SetServerPassword(ctx, rpc.Credential{}, newPassword)
	switch {
	case err == nil, errors.Is(err, rpc.ErrUnreachable):
	default:
		// Refused or not sent (API error, certificate): nothing was applied.
		return fmt.Errorf("setup: set server password: %w", err)
	}

	// 4. Verification.
	if state, _ := m.prober.Probe(ctx); state != softether.StatePasswordSet {
		return ErrUncertain
	}

	// 5. Done: consume the token.
	m.cleanup()
	return nil
}

// cleanup invalidates the token, logging (without the token) a failure to
// delete the file; Refresh(StatePasswordSet) will retry the removal.
func (m *Manager) cleanup() {
	if err := m.invalidate(); err != nil {
		m.logger.Error("cannot remove setup token file", "err", err)
	}
}

// ReadTokenFile returns the token stored in runtimeDir, for the setup-token
// subcommand.
func ReadTokenFile(runtimeDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(runtimeDir, tokenFileName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
