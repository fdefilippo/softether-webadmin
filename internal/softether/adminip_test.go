package softether

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeAdminIP(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "adminip.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClassifyAdminIPMissing(t *testing.T) {
	iso, err := ClassifyAdminIP(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !iso.Missing || iso.Isolated {
		t.Fatalf("got %+v, want Missing && !Isolated", iso)
	}
}

func TestClassifyAdminIP(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		isolated  bool
		offending []string
		ignored   []string
	}{
		{"crlf v4 and v6", "127.0.0.1/32\r\n::1/128\r\n", true, nil, nil},
		{"bom, comments, no mask ignored", "\xef\xbb\xbf# c\n\n127.0.0.1 // locale\n", true, nil, []string{"127.0.0.1"}},
		{"loopback /8", "127.0.0.0/8\n", true, nil, nil},
		{"non loopback with hub", "127.0.0.1/32\n192.168.1.0/24 HUB1\n", false, []string{"192.168.1.0/24 HUB1"}, nil},
		{"any v4", "0.0.0.0/0\n", false, []string{"0.0.0.0/0"}, nil},
		{"mask escapes loopback", "127.0.0.1/0\n", false, []string{"127.0.0.1/0"}, nil},
		{"garbage ignored", "spazzatura\n", true, nil, []string{"spazzatura"}},
		{"dotted mask", "127.0.0.1/255.0.0.0\n", true, nil, nil},
		{"dotted mask too wide", "127.0.0.1/255.0.0.0\n10.1.2.3/255.0.0.0\n", false, []string{"10.1.2.3/255.0.0.0"}, nil},
		{"v6 loopback", "::1/128\n", true, nil, nil},
		{"v6 any", "::/0\n", false, []string{"::/0"}, nil},
		{"v6 wider than loopback", "::1/127\n", false, []string{"::1/127"}, nil},
		{"hub entry still counts", "10.0.0.1/8 HUB1 # c\n", false, []string{"10.0.0.1/8 HUB1"}, nil},
		{"tab separated hub", "10.0.0.0/8\tHUB1\n", false, []string{"10.0.0.0/8\tHUB1"}, nil},
		{"prefix 33 ignored", "127.0.0.1/33\n", true, nil, []string{"127.0.0.1/33"}},
		{"family mismatch ignored", "127.0.0.1/ffff::\n::1/255.0.0.0\n", true, nil, []string{"127.0.0.1/ffff::", "::1/255.0.0.0"}},
		{"bad ip ignored", "300.1.1.1/8\n", true, nil, []string{"300.1.1.1/8"}},
		{"two slashes ignored", "127.0.0.1/8/8\n", true, nil, []string{"127.0.0.1/8/8"}},
		{"slash comment mid line", "10.0.0.0/8//x\n", false, []string{"10.0.0.0/8"}, nil},
		{"empty file is isolated", "", true, nil, nil},
		{"only comments", "# a\n// b\n   \n", true, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iso, err := ClassifyAdminIP(writeAdminIP(t, tc.content))
			if err != nil {
				t.Fatal(err)
			}
			if iso.Missing || iso.Isolated != tc.isolated {
				t.Errorf("Missing=%v Isolated=%v, want Isolated=%v", iso.Missing, iso.Isolated, tc.isolated)
			}
			if !reflect.DeepEqual(nz(iso.Offending), nz(tc.offending)) {
				t.Errorf("Offending=%q, want %q", iso.Offending, tc.offending)
			}
			if !reflect.DeepEqual(nz(iso.Ignored), nz(tc.ignored)) {
				t.Errorf("Ignored=%q, want %q", iso.Ignored, tc.ignored)
			}
		})
	}
}

func nz(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func TestRestrictToLoopback(t *testing.T) {
	const orig = "0.0.0.0/0\n"
	p := writeAdminIP(t, orig)
	now := time.Date(2026, 11, 5, 14, 30, 59, 0, time.UTC)

	backup, err := RestrictToLoopback(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := p + ".bak-20261105-143059"; backup != want {
		t.Errorf("backup=%q, want %q", backup, want)
	}
	b, err := os.ReadFile(backup)
	if err != nil || string(b) != orig {
		t.Errorf("backup content=%q err=%v, want %q", b, err, orig)
	}
	iso, err := ClassifyAdminIP(p)
	if err != nil || !iso.Isolated {
		t.Errorf("after restrict: %+v err=%v", iso, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode=%v, want 0600", st.Mode().Perm())
	}
	got, _ := os.ReadFile(p)
	want := "# Restricted to loopback by softether-webadmin on 2026-11-05T14:30:59Z\n127.0.0.1/32\n::1/128\n"
	if string(got) != want {
		t.Errorf("content=%q, want %q", got, want)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestRestrictToLoopbackMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "adminip.txt")
	backup, err := RestrictToLoopback(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if backup != "" {
		t.Errorf("backup=%q, want empty", backup)
	}
	iso, err := ClassifyAdminIP(p)
	if err != nil || !iso.Isolated {
		t.Errorf("%+v err=%v", iso, err)
	}
}
