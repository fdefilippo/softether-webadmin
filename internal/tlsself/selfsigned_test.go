package tlsself

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: not a CERTIFICATE PEM", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnsureSelfSignedCreatesOnce(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	hosts := []string{"vpn.example.org", "192.0.2.7", "localhost", "127.0.0.1", "::1", "127.0.0.1"}

	created, err := EnsureSelfSigned(certPath, keyPath, hosts, now)
	if err != nil || !created {
		t.Fatalf("first call: created=%v err=%v", created, err)
	}
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	created, err = EnsureSelfSigned(certPath, keyPath, hosts, now.Add(time.Hour))
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v", created, err)
	}
	after, _ := os.ReadFile(certPath)
	if string(before) != string(after) {
		t.Error("existing certificate was overwritten")
	}

	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", st.Mode().Perm())
	}

	c := readCert(t, certPath)
	foundLoop := false
	for _, ip := range c.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundLoop = true
		}
	}
	if !foundLoop {
		t.Errorf("IP SANs %v lack 127.0.0.1", c.IPAddresses)
	}
	if len(c.IPAddresses) != 3 { // 192.0.2.7, 127.0.0.1, ::1 (duplicates removed)
		t.Errorf("IP SANs = %v, want 3 distinct", c.IPAddresses)
	}
	dns := map[string]bool{}
	for _, d := range c.DNSNames {
		dns[d] = true
	}
	if !dns["vpn.example.org"] || !dns["localhost"] || len(c.DNSNames) != 2 {
		t.Errorf("DNS SANs = %v", c.DNSNames)
	}
	if c.Subject.CommonName != "softether-webadmin" {
		t.Errorf("CN = %q", c.Subject.CommonName)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got != 825*24*time.Hour {
		t.Errorf("validity = %v, want 825 days", got)
	}
	if !c.NotBefore.Equal(now) {
		t.Errorf("NotBefore = %v, want %v", c.NotBefore, now)
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Errorf("public key = %T, want ECDSA P-256", c.PublicKey)
	}
	if c.IsCA {
		t.Error("certificate must not be a CA")
	}
	// The pair must be loadable by crypto/tls.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("LoadX509KeyPair: %v", err)
	}
}

func TestEnsureSelfSignedRejectsHalfPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if created, err := EnsureSelfSigned(certPath, keyPath, []string{"localhost"}, time.Now()); err == nil || created {
		t.Errorf("created=%v err=%v, want an error for a lone key", created, err)
	}
	if got, _ := os.ReadFile(keyPath); string(got) != "x" {
		t.Error("lone key was modified")
	}
}

func TestEnsureSelfSignedCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "tls")
	created, err := EnsureSelfSigned(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), []string{"localhost"}, time.Now())
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
}
