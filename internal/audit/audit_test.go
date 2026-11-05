package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLogWritesJSONWithFixedFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log(context.Background(), Event{
		Action: "login_failed", Role: "server_admin", Hub: "DEFAULT",
		RemoteIP: "192.0.2.7", Method: "Test", Result: "unauthorized",
	})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	for k, want := range map[string]string{
		"action": "login_failed", "role": "server_admin", "hub": "DEFAULT",
		"remote_ip": "192.0.2.7", "method": "Test", "result": "unauthorized",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %q", k, m[k], want)
		}
	}
}

func TestLogOmitsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Log(context.Background(), Event{Action: "logout"})
	s := buf.String()
	for _, k := range []string{`"hub"`, `"method"`, `"role"`, `"remote_ip"`, `"result"`} {
		if strings.Contains(s, k) {
			t.Errorf("empty field %s present: %s", k, s)
		}
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	l.Log(context.Background(), Event{Action: "x"})
	l.Slog().Error("x") // must not panic
}

func TestSlogSharesStream(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Slog().Error("template error", "page", "dashboard")
	if !strings.Contains(buf.String(), `"page":"dashboard"`) {
		t.Fatalf("got %s", buf.String())
	}
}
