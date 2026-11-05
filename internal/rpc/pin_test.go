package rpc

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprint(t *testing.T) {
	der := []byte("some certificate bytes")
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	if got := Fingerprint(der); got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
	if got := Fingerprint(der); got != strings.ToLower(got) || len(got) != 64 {
		t.Fatalf("Fingerprint not 64 lowercase hex chars: %q", got)
	}
}

func TestPinStoreLoadMissing(t *testing.T) {
	p := PinStore{Path: filepath.Join(t.TempDir(), "server-cert.sha256")}
	fp, ok, err := p.Load()
	if err != nil || ok || fp != "" {
		t.Fatalf("Load on missing file = (%q, %v, %v), want (\"\", false, nil)", fp, ok, err)
	}
}

func TestPinStoreSaveLoadCreatesDirAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "nested")
	p := PinStore{Path: filepath.Join(dir, "server-cert.sha256")}
	fp := strings.Repeat("ab", 32)
	if err := p.Save(fp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := p.Load()
	if err != nil || !ok || got != fp {
		t.Fatalf("Load = (%q, %v, %v), want (%q, true, nil)", got, ok, err, fp)
	}
	st, err := os.Stat(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m != 0o600 {
		t.Errorf("pin file mode = %o, want 600", m)
	}
	dst, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m := dst.Mode().Perm(); m != 0o700 {
		t.Errorf("pin dir mode = %o, want 700", m)
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory has %d entries, want 1", len(entries))
	}
}

func TestPinStoreSaveOverwritesAndNormalizes(t *testing.T) {
	p := PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := p.Save(strings.Repeat("00", 32)); err != nil {
		t.Fatal(err)
	}
	if err := p.Save(strings.Repeat("AB", 32)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := p.Load()
	if err != nil || !ok || got != strings.Repeat("ab", 32) {
		t.Fatalf("Load = (%q, %v, %v)", got, ok, err)
	}
}

func TestPinStoreSaveRejectsInvalid(t *testing.T) {
	p := PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	for _, bad := range []string{"", "abc", strings.Repeat("zz", 32), strings.Repeat("ab", 31)} {
		if err := p.Save(bad); err == nil {
			t.Errorf("Save(%q) succeeded, want error", bad)
		}
	}
	if _, err := os.Stat(p.Path); !os.IsNotExist(err) {
		t.Errorf("pin file exists after rejected saves: %v", err)
	}
}

func TestPinStoreLoadCorrupt(t *testing.T) {
	p := PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := os.WriteFile(p.Path, []byte("not a fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Load(); err == nil {
		t.Fatal("Load of corrupt pin succeeded, want error")
	}
}

func TestPinStoreLoadTrimsWhitespace(t *testing.T) {
	p := PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	fp := strings.Repeat("0f", 32)
	if err := os.WriteFile(p.Path, []byte(strings.ToUpper(fp)+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := p.Load()
	if err != nil || !ok || got != fp {
		t.Fatalf("Load = (%q, %v, %v), want (%q, true, nil)", got, ok, err, fp)
	}
}
