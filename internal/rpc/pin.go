package rpc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Fingerprint returns the SHA-256 of a DER certificate as lowercase hex.
func Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// PinStore persists the fingerprint of the trusted server certificate in a
// single file.
type PinStore struct {
	Path string
}

// normalizeFingerprint trims and lowercases fp and checks it is a SHA-256 hex
// digest.
func normalizeFingerprint(fp string) (string, error) {
	fp = strings.ToLower(strings.TrimSpace(fp))
	if len(fp) != sha256.Size*2 {
		return "", fmt.Errorf("rpc: invalid fingerprint: want %d hex characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", fmt.Errorf("rpc: invalid fingerprint: %w", err)
	}
	return fp, nil
}

// Load returns the pinned fingerprint (lowercase hex). The boolean is false
// when no pin file exists.
func (p PinStore) Load() (string, bool, error) {
	data, err := os.ReadFile(p.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("rpc: read pin: %w", err)
	}
	fp, err := normalizeFingerprint(string(data))
	if err != nil {
		return "", false, fmt.Errorf("rpc: pin file %s: %w", p.Path, err)
	}
	return fp, true, nil
}

// Save atomically writes fp (temp file + rename, mode 0600), creating the
// parent directory (0700) if needed.
func (p PinStore) Save(fp string) error {
	fp, err := normalizeFingerprint(fp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("rpc: create pin directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pin-*")
	if err != nil {
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	if _, err := tmp.WriteString(fp + "\n"); err != nil {
		cleanup()
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	if err := os.Rename(tmpName, p.Path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rpc: write pin: %w", err)
	}
	return nil
}
