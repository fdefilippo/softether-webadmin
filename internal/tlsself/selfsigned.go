// Package tlsself creates the self-signed certificate the daemon uses for its
// own HTTPS listener when none is configured.
package tlsself

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// validity of a generated certificate.
const validity = 825 * 24 * time.Hour

// EnsureSelfSigned creates an ECDSA P-256 self-signed certificate valid for
// 825 days from now, with hosts as subject alternative names (IP addresses as
// IP SANs, anything else as DNS SANs), and writes it to certPath and the key
// to keyPath (mode 0600), creating their directories (0700) if needed.
//
// Existing files are never overwritten: if both exist nothing is done and
// created is false; if only one of them exists an error is returned, because
// the pair is unusable and replacing either file could destroy operator data.
func EnsureSelfSigned(certPath, keyPath string, hosts []string, now time.Time) (created bool, err error) {
	certExists, err := exists(certPath)
	if err != nil {
		return false, err
	}
	keyExists, err := exists(keyPath)
	if err != nil {
		return false, err
	}
	switch {
	case certExists && keyExists:
		return false, nil
	case certExists != keyExists:
		return false, fmt.Errorf("tlsself: %s and %s must exist together; remove the remaining one to regenerate the pair", certPath, keyPath)
	}

	certPEM, keyPEM, err := generate(hosts, now)
	if err != nil {
		return false, err
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return false, fmt.Errorf("tlsself: %w", err)
		}
	}
	// Write both files under temporary names, then publish them with two
	// renames so that a crash leaves no truncated file under the final names.
	keyTmp, err := writeTemp(keyPath, keyPEM)
	if err != nil {
		return false, err
	}
	certTmp, err := writeTemp(certPath, certPEM)
	if err != nil {
		os.Remove(keyTmp)
		return false, err
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		os.Remove(keyTmp)
		os.Remove(certTmp)
		return false, fmt.Errorf("tlsself: %w", err)
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		os.Remove(certTmp)
		os.Remove(keyPath)
		return false, fmt.Errorf("tlsself: %w", err)
	}
	return true, nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("tlsself: %w", err)
	}
	return true, nil
}

// writeTemp writes data with mode 0600 to a new temporary file next to path
// and returns its name.
func writeTemp(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tls-*")
	if err != nil {
		return "", fmt.Errorf("tlsself: %w", err)
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("tlsself: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("tlsself: %w", err)
	}
	return name, nil
}

func generate(hosts []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsself: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("tlsself: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "softether-webadmin"},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsself: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsself: marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
