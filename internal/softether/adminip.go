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
// The semantics mirror Cedar/Admin.c CheckAdminSourceAddress.
type Isolation struct {
	// Missing is true when the file does not exist (no restriction at all).
	Missing bool
	// Isolated is true when the file exists and no entry can let a
	// non-loopback host administer the server.
	Isolated bool
	// Offending lists the original text (comment stripped, trimmed) of every
	// entry that lets, or may let, a host outside 127.0.0.0/8 and ::1
	// administer the server: a valid entry whose effective network is not
	// entirely loopback, a bare non-loopback IP, the "*" wildcard, and any
	// unparseable spec that looks like an address (see ClassifyAdminIP).
	Offending []string
	// Ignored lists the non-empty lines SoftEther ignores because their
	// address spec is neither an address nor an "*"; they never match a host.
	Ignored []string
}

// ClassifyAdminIP reads path and classifies it the way SoftEther parses it
// (Cedar/Admin.c CheckAdminSourceAddress):
//
//   - comments start at the first "#" or "//"; "\n", "\r\n" and a lone "\r"
//     end a line; fields are separated by spaces or tabs; an optional second
//     field names a Hub (the line then applies to that Hub's administrators
//     but still lets a remote host administer it, so it counts);
//   - the first field is split on "/" dropping empty parts (as SoftEther's
//     ParseToken does): two parts are "ip/mask", with a dotted/IPv6 mask of
//     the same family or a decimal prefix length, and match a host when
//     (host & mask) == (ip & mask); a single part is a bare IP, an exact
//     host entry (/32 or /128);
//   - "*" allows everyone;
//   - a spec we cannot parse but that SoftEther's lenient StrToIP might
//     accept (it starts with a digit or contains ':') is reported as
//     Offending, because we cannot prove it is not an allow; any other
//     garbage is Ignored.
func ClassifyAdminIP(path string) (Isolation, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Isolation{Missing: true}, nil
	}
	if err != nil {
		return Isolation{}, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	text := strings.ReplaceAll(string(data), "\r", "\n")

	var iso Isolation
	for _, line := range strings.Split(text, "\n") {
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
		switch classifySpec(fields[0]) {
		case specIgnored:
			iso.Ignored = append(iso.Ignored, line)
		case specOffending:
			iso.Offending = append(iso.Offending, line)
		}
	}
	iso.Isolated = len(iso.Offending) == 0
	return iso, nil
}

type specClass int

const (
	specLoopback specClass = iota
	specOffending
	specIgnored
)

func classifySpec(spec string) specClass {
	if spec == "*" {
		return specOffending
	}
	if e, ok := parseEntry(spec); ok {
		if e.insideLoopback() {
			return specLoopback
		}
		return specOffending
	}
	if spec != "" && (spec[0] >= '0' && spec[0] <= '9' || strings.Contains(spec, ":")) {
		return specOffending
	}
	return specIgnored
}

// entry is a valid adminip.txt address spec in 16-byte form. For IPv4 only
// the last four bytes of ip and mask are meaningful.
type entry struct {
	v4   bool
	ip   [16]byte
	mask [16]byte
}

// parseEntry parses an address spec: "ip/mask" or a bare IP (host entry).
// Empty parts between slashes are dropped.
func parseEntry(spec string) (entry, bool) {
	var parts []string
	for _, p := range strings.Split(spec, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) != 1 && len(parts) != 2 {
		return entry{}, false
	}
	a, err := netip.ParseAddr(parts[0])
	if err != nil || a.Zone() != "" {
		return entry{}, false
	}
	e := entry{v4: a.Is4()}
	base := 0
	if e.v4 {
		base = 12
	}
	switch {
	case len(parts) == 1:
		for i := 0; i < a.BitLen(); i++ {
			e.mask[base+i/8] |= 0x80 >> (i % 8)
		}
	case isDecimal(parts[1]):
		n, err := strconv.Atoi(parts[1])
		if err != nil || n > a.BitLen() {
			return entry{}, false
		}
		for i := 0; i < n; i++ {
			e.mask[base+i/8] |= 0x80 >> (i % 8)
		}
	default:
		m, err := netip.ParseAddr(parts[1])
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
