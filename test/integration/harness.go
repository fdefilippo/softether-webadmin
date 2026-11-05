//go:build integration

// Package integration holds tests that run the web admin against a real
// SoftEther VPN Server in a container. They are only built with the
// "integration" tag, so that a plain `go test ./...` never needs a container
// engine.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
)

const (
	// vpnserverImage is pinned to the exact release the project is built
	// and documented against.
	vpnserverImage = "docker.io/softethervpn/vpnserver:5.2.5189"
	// readyTimeout bounds the wait for a fresh vpnserver to answer.
	readyTimeout = 60 * time.Second
)

var hostPortRe = regexp.MustCompile(`127\.0\.0\.1:(\d+)`)

// engine returns the container engine command: $CONTAINER_ENGINE or docker.
// The test is skipped when it is not installed (CI always has docker).
func engine(t *testing.T) string {
	t.Helper()
	e := os.Getenv("CONTAINER_ENGINE")
	if e == "" {
		e = "docker"
	}
	if _, err := exec.LookPath(e); err != nil {
		t.Skipf("container engine %q not found (set CONTAINER_ENGINE=podman|docker): integration test skipped", e)
	}
	return e
}

// run executes the container engine and returns its trimmed stdout. The
// stderr text is part of the error, so a failure explains itself.
func run(ctx context.Context, eng string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, eng, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", eng, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// StartVPNServer starts a fresh, empty-password vpnserver container, waits
// until it answers the probe with StateEmptyPassword and returns the JSON-RPC
// URL and a stop function. The container is also removed by t.Cleanup, so
// stop is optional (and idempotent).
//
// Every test gets its own container: the tests change the administrator
// password, and the server certificate is generated at first start, so
// nothing is shared between tests.
func StartVPNServer(t *testing.T) (apiURL string, stop func()) {
	t.Helper()
	eng := engine(t)

	// Pulling the image on a cold runner can take a while.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	id, err := run(ctx, eng, "run", "-d", "--rm", "-p", "127.0.0.1::5555", vpnserverImage)
	if err != nil {
		t.Fatalf("start vpnserver container: %v", err)
	}

	removed := false
	stop = func() {
		if removed {
			return
		}
		removed = true
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		if _, err := run(rctx, eng, "rm", "-f", id); err != nil {
			t.Logf("remove container %s: %v", id, err)
		}
	}
	t.Cleanup(func() {
		if t.Failed() {
			lctx, lcancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer lcancel()
			// Best effort: with --rm the logs are gone if the container died.
			if logs, err := run(lctx, eng, "logs", "--tail", "50", id); err == nil {
				t.Logf("vpnserver container log (tail):\n%s", logs)
			}
		}
		stop()
	})

	port, err := run(ctx, eng, "port", id, "5555")
	if err != nil {
		t.Fatalf("find mapped port: %v", err)
	}
	m := hostPortRe.FindStringSubmatch(port)
	if m == nil {
		t.Fatalf("cannot parse mapped port from %q", port)
	}
	apiURL = "https://127.0.0.1:" + m[1] + "/api/"

	waitEmptyPassword(t, apiURL)
	return apiURL, stop
}

// waitEmptyPassword polls until a probe reports StateEmptyPassword. It uses
// its own throwaway pin store, so the pin of the system under test is only
// ever created by the daemon's own trust on first use.
func waitEmptyPassword(t *testing.T, apiURL string) {
	t.Helper()
	pins := rpc.PinStore{Path: filepath.Join(t.TempDir(), "ready-pin")}
	prober := softether.Prober{Client: rpc.NewClient(apiURL, pins, true)}

	deadline := time.Now().Add(readyTimeout)
	var last softether.State
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		last, lastErr = prober.Probe(ctx)
		cancel()
		if last == softether.StateEmptyPassword {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("vpnserver at %s not ready after %s: last state %v, error %v", apiURL, readyTimeout, last, lastErr)
}
