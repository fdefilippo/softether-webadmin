package softether

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Isolation is the result of classifying SoftEther's adminip.txt, which
// restricts the source addresses allowed to administer the VPN server.
type Isolation struct {
	// Missing is true when the file does not exist (no restriction at all).
	Missing bool
	// Isolated is true when the file exists and no valid entry lets a
	// non-loopback host administer the server.
	Isolated bool
	// Offending lists the original text (comment stripped, trimmed) of every
	// valid entry whose effective network is not entirely inside
	// 127.0.0.0/8 or ::1/128.
	Offending []string
	// Ignored lists the non-empty lines SoftEther ignores because they are
	// not valid "ip/mask" specs; they never match any host.
	Ignored []string
}

// ClassifyAdminIP reads path and classifies it the way SoftEther parses it
// (Cedar/Admin.c CheckAdminSourceAddress, Mayaqua/Network.c ParseIpAndMask46):
// comments start at the first "#" or "//", fields are separated by spaces or
// tabs, the first field must be "ip/mask" (mask dotted or a prefix length of
// the same address family) and an optional second field names a Hub. An entry
// matches a host when (host & mask) == (ip & mask).
func ClassifyAdminIP(path string) (Isolation, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Isolation{Missing: true}, nil
	}
	if err != nil {
		return Isolation{}, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	var iso Isolation
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		e, ok := parseEntry(fields[0])
		switch {
		case !ok:
			iso.Ignored = append(iso.Ignored, line)
		case !e.insideLoopback():
			iso.Offending = append(iso.Offending, line)
		}
	}
	iso.Isolated = len(iso.Offending) == 0
	return iso, nil
}

// entry is a valid adminip.txt address spec in 16-byte form. For IPv4 only
// the last four bytes of ip and mask are meaningful.
type entry struct {
	v4   bool
	ip   [16]byte
	mask [16]byte
}

// parseEntry parses "ip/mask" with exactly one slash. The mask is either a
// decimal prefix length or a dotted/IPv6 mask of the same family as ip.
func parseEntry(spec string) (entry, bool) {
	ipStr, maskStr, found := strings.Cut(spec, "/")
	if !found || strings.Contains(maskStr, "/") {
		return entry{}, false
	}
	a, err := netip.ParseAddr(ipStr)
	if err != nil || a.Zone() != "" {
		return entry{}, false
	}
	e := entry{v4: a.Is4()}
	if isDecimal(maskStr) {
		n, err := strconv.Atoi(maskStr)
		if err != nil || n > a.BitLen() {
			return entry{}, false
		}
		base := 0
		if e.v4 {
			base = 12
		}
		for i := 0; i < n; i++ {
			e.mask[base+i/8] |= 0x80 >> (i % 8)
		}
	} else {
		m, err := netip.ParseAddr(maskStr)
		if err != nil || m.Zone() != "" || m.Is4() != e.v4 {
			return entry{}, false
		}
		e.mask = to16(m)
	}
	e.ip = to16(a)
	return e, true
}

func to16(a netip.Addr) [16]byte {
	if a.Is4() {
		b := a.As4()
		var out [16]byte
		copy(out[12:], b[:])
		return out
	}
	return a.As16()
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// insideLoopback reports whether every host matching the entry, i.e. every
// address x with x&mask == ip&mask, lies in 127.0.0.0/8 (IPv4) or is exactly
// ::1 (IPv6).
func (e entry) insideLoopback() bool {
	if e.v4 {
		return e.mask[12] == 0xff && e.ip[12] == 127
	}
	for _, b := range e.mask {
		if b != 0xff {
			return false
		}
	}
	return e.ip == [16]byte{15: 1}
}

// RestrictToLoopback rewrites path so that only loopback hosts may administer
// the server. An existing file is first copied to <path>.bak-YYYYmmdd-HHMMSS
// (returned as backup; empty when there was no file). The new file is written
// to a temporary file in the same directory and renamed into place, mode 0600.
func RestrictToLoopback(path string, now time.Time) (backup string, err error) {
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		backup = path + ".bak-" + now.Format("20060102-150405")
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", err
	}

	content := fmt.Sprintf("# Restricted to loopback by softether-webadmin on %s\n127.0.0.1/32\n::1/128\n",
		now.Format(time.RFC3339))
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return backup, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return backup, err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return backup, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return backup, err
	}
	if err := tmp.Close(); err != nil {
		return backup, err
	}
	return backup, os.Rename(tmp.Name(), path)
}
