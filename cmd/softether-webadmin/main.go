// Command softether-webadmin is a web administration daemon for SoftEther VPN Server.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// pinFileName is the name, inside StateDir, of the file holding the pinned
// fingerprint of the SoftEther server certificate.
const pinFileName = "server-cert.sha256"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = "usage: softether-webadmin [serve|setup-token|trust-server-cert|version] [--config path]\n"

// run dispatches the subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve", "setup-token", "trust-server-cert", "version":
	default:
		fmt.Fprintf(stderr, "softether-webadmin: unknown command %q\n%s", cmd, usageText)
		return exitUsage
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path of the configuration file")
	var fingerprint *string
	if cmd == "trust-server-cert" {
		fingerprint = fs.String("fingerprint", "", "expected SHA-256 fingerprint of the server certificate (hex, optionally colon-separated)")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "softether-webadmin %s: unexpected argument %q\n%s", cmd, fs.Arg(0), usageText)
		return exitUsage
	}

	if cmd == "version" {
		fmt.Fprintf(stdout, "softether-webadmin %s\n", version)
		return exitOK
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "softether-webadmin %s: %v\n", cmd, err)
		return exitFail
	}

	switch cmd {
	case "setup-token":
		return runSetupToken(cfg, stdout, stderr)
	case "trust-server-cert":
		return runTrustServerCert(cfg, *fingerprint, stdout, stderr)
	default: // serve
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := serve(ctx, cfg, stderr, nil); err != nil {
			fmt.Fprintf(stderr, "softether-webadmin serve: %v\n", err)
			return exitFail
		}
		return exitOK
	}
}

// runSetupToken prints the active setup token, and nothing else, on stdout.
func runSetupToken(cfg config.Config, stdout, stderr io.Writer) int {
	tok, err := setup.ReadTokenFile(cfg.RuntimeDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "softether-webadmin setup-token: %v\n", err)
		return exitFail
	}
	if err != nil || tok == "" {
		fmt.Fprintln(stderr, "no active setup token (server already configured or daemon not running)")
		return exitFail
	}
	fmt.Fprintln(stdout, tok)
	return exitOK
}

// runTrustServerCert pins the certificate presented by the SoftEther server
// (TLS handshake only, no credentials are sent) and prints its fingerprint.
func runTrustServerCert(cfg config.Config, expected string, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "softether-webadmin trust-server-cert: "+format+"\n", a...)
		return exitFail
	}
	if expected != "" {
		var err error
		if expected, err = parseFingerprint(expected); err != nil {
			return fail("invalid --fingerprint: %v", err)
		}
	}
	if err := validateSoftEtherURL(cfg.SoftEtherURL); err != nil {
		return fail("%v", err)
	}
	pins := rpc.PinStore{Path: filepath.Join(cfg.StateDir, pinFileName)}
	fp, err := rpc.TrustServerCert(context.Background(), cfg.SoftEtherURL, pins, expected)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Fprintln(stdout, fp)
	return exitOK
}

// parseFingerprint accepts a SHA-256 fingerprint as plain hex or as printed
// by "openssl x509 -fingerprint -sha256" (colon-separated, any case) and
// returns it as lowercase plain hex.
func parseFingerprint(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", errors.New("not a hexadecimal string")
	}
	if len(b) != sha256.Size {
		return "", fmt.Errorf("want a SHA-256 fingerprint (%d hex digits), got %d", sha256.Size*2, len(s))
	}
	return strings.ToLower(s), nil
}

// validateSoftEtherURL checks that raw is an https URL with a host.
func validateSoftEtherURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("softether_url %q: %v", raw, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("softether_url %q: must be an https URL with a host, e.g. https://127.0.0.1:5555/api/", raw)
	}
	return nil
}
