package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefault(t *testing.T) {
	c := Default()
	if c.Listen != "127.0.0.1:9443" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.SoftEtherURL != "https://127.0.0.1:5555/api/" {
		t.Errorf("SoftEtherURL = %q", c.SoftEtherURL)
	}
	if c.ProbeInterval != 60*time.Second {
		t.Errorf("ProbeInterval = %v", c.ProbeInterval)
	}
	if c.SessionIdle != 30*time.Minute || c.SessionMax != 8*time.Hour {
		t.Errorf("session timeouts = %v / %v", c.SessionIdle, c.SessionMax)
	}
	if c.LoginMaxFailures != 5 || c.LoginWindow != 15*time.Minute {
		t.Errorf("login limits = %d / %v", c.LoginMaxFailures, c.LoginWindow)
	}
	if c.StateDir != "/var/lib/softether-webadmin" || c.RuntimeDir != "/run/softether-webadmin" {
		t.Errorf("dirs = %q / %q", c.StateDir, c.RuntimeDir)
	}
}

func TestLoadOverridesAndKeepsDefaults(t *testing.T) {
	path := writeConfig(t, "listen = \"10.0.0.5:9443\"\nsession_idle = \"10m\"\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "10.0.0.5:9443" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.SessionIdle != 10*time.Minute {
		t.Errorf("SessionIdle = %v", c.SessionIdle)
	}
	if c.AdminIPPath != "/var/lib/softether/adminip.txt" {
		t.Errorf("AdminIPPath = %q", c.AdminIPPath)
	}
	if c.SessionMax != 8*time.Hour {
		t.Errorf("SessionMax = %v", c.SessionMax)
	}
}

func TestLoadAllKeys(t *testing.T) {
	path := writeConfig(t, `
listen = "0.0.0.0:1"
tls_cert = "/c.pem"
tls_key = "/k.pem"
softether_url = "https://h:5555/api/"
adminip_path = "/a.txt"
state_dir = "/s"
runtime_dir = "/r"
session_idle = "1m"
session_max = "2h"
probe_interval = "5s"
login_max_failures = 3
login_window = "1h"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Listen: "0.0.0.0:1", TLSCert: "/c.pem", TLSKey: "/k.pem",
		SoftEtherURL: "https://h:5555/api/", AdminIPPath: "/a.txt",
		StateDir: "/s", RuntimeDir: "/r",
		SessionIdle: time.Minute, SessionMax: 2 * time.Hour, ProbeInterval: 5 * time.Second,
		LoginMaxFailures: 3, LoginWindow: time.Hour,
	}
	if c != want {
		t.Errorf("got %+v, want %+v", c, want)
	}
}

func TestLoadUnknownKey(t *testing.T) {
	path := writeConfig(t, "foo = 1\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "foo") {
		t.Fatalf("err = %v, want error mentioning foo", err)
	}
}

func TestLoadBadDuration(t *testing.T) {
	path := writeConfig(t, "session_idle = \"soon\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("want error for invalid duration")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("want error for missing file")
	}
}

// T1: values that would disable a protection (sessions that never expire, a
// probe loop that spins, a limiter that blocks or allows everything) are
// refused when the file is loaded.
func TestLoadRejectsNonsenseValues(t *testing.T) {
	for name, content := range map[string]string{
		"zero session_idle":          `session_idle = "0s"`,
		"negative session_max":       `session_max = "-1h"`,
		"zero probe_interval":        `probe_interval = "0s"`,
		"negative login_window":      `login_window = "-15m"`,
		"zero login_max_failures":    `login_max_failures = 0`,
		"negative login_max_failure": `login_max_failures = -3`,
		"session_max < session_idle": "session_idle = \"2h\"\nsession_max = \"1h\"",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, content+"\n")); err == nil {
				t.Errorf("Load accepted %q", content)
			}
		})
	}
	// Equal idle and absolute timeouts are fine.
	if _, err := Load(writeConfig(t, "session_idle = \"1h\"\nsession_max = \"1h\"\n")); err != nil {
		t.Errorf("session_idle == session_max refused: %v", err)
	}
}
