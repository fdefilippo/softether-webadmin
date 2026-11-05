package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := out.String(); got != "softether-webadmin dev\n" {
		t.Errorf("stdout = %q", got)
	}
}

func TestRunNotImplemented(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"serve"},
		{"--config", "/x.toml"},
		{"setup-token", "--config", "/x.toml"},
		{"trust-server-cert"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("run(%v) exit = %d, want 2", args, code)
		}
		if !strings.Contains(errb.String(), "not implemented") {
			t.Errorf("run(%v) stderr = %q", args, errb.String())
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
