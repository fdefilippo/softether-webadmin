package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

const shippedConfig = "../../packaging/config.toml"

// The config file shipped in the packages must load cleanly and change nothing.
func TestShippedConfigEqualsDefault(t *testing.T) {
	c, err := Load(shippedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Errorf("shipped config = %+v, want defaults %+v", c, Default())
	}
}

// Every commented-out example in the shipped file must be valid and must show
// the real default, so the documentation cannot drift from Default().
func TestShippedConfigExamplesMatchDefault(t *testing.T) {
	raw, err := os.ReadFile(shippedConfig)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^#([a-z_]+ = .*)$`)
	uncommented := re.ReplaceAll(raw, []byte("$1"))
	if string(uncommented) == string(raw) {
		t.Fatal("no commented examples found")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, uncommented, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Errorf("uncommented config = %+v, want defaults %+v", c, Default())
	}
}
