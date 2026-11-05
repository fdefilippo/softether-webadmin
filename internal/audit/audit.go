// Package audit writes the security-relevant events of the web admin as JSON
// lines through log/slog. An Event has a fixed set of short fields and no
// free-form attributes, so a password, token or session ID cannot be logged
// by accident through it.
package audit

import (
	"context"
	"io"
	"log/slog"
)

// Event is one audit record. Empty fields are omitted.
type Event struct {
	Action   string // e.g. login_failed, setup_completed
	Role     string // e.g. server_admin
	Hub      string // virtual Hub concerned, if any
	RemoteIP string // client address
	Method   string // JSON-RPC method involved, if any
	Result   string // short outcome code, never free text from the user
}

// Logger writes audit events. A nil *Logger is valid and discards everything.
type Logger struct {
	l *slog.Logger
}

// New returns a Logger writing JSON lines to w (os.Stderr in production).
func New(w io.Writer) *Logger {
	return &Logger{l: slog.New(slog.NewJSONHandler(w, nil))}
}

// Log records e.
func (l *Logger) Log(ctx context.Context, e Event) {
	if l == nil {
		return
	}
	attrs := make([]slog.Attr, 0, 6)
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	add("action", e.Action)
	add("role", e.Role)
	add("hub", e.Hub)
	add("remote_ip", e.RemoteIP)
	add("method", e.Method)
	add("result", e.Result)
	l.l.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

// Slog returns the underlying logger, for operational messages (template
// errors, probe failures) that share the audit stream. Callers must never put
// passwords, tokens or form values in its attributes. On a nil Logger it
// returns a logger that discards everything.
func (l *Logger) Slog() *slog.Logger {
	if l == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return l.l
}
