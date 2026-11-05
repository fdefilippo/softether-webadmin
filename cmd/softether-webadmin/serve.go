package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fdefilippo/softether-webadmin/internal/audit"
	"github.com/fdefilippo/softether-webadmin/internal/config"
	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/setup"
	"github.com/fdefilippo/softether-webadmin/internal/softether"
	"github.com/fdefilippo/softether-webadmin/internal/tlsself"
	"github.com/fdefilippo/softether-webadmin/internal/web"
)

const shutdownTimeout = 10 * time.Second

// syncWriter serializes writes, so that the operational and the audit logger
// can share one stream.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// serve runs the web admin until ctx is done, then shuts down in an orderly
// way and returns nil. Operational and audit logs are JSON lines on logOut.
// ready, if not nil, is called with the listening address once the daemon
// accepts connections.
func serve(ctx context.Context, cfg config.Config, logOut io.Writer, ready func(net.Addr)) error {
	if err := validateSoftEtherURL(cfg.SoftEtherURL); err != nil {
		return err
	}
	out := &syncWriter{w: logOut}
	logger := slog.New(slog.NewJSONHandler(out, nil))

	for _, d := range []string{cfg.StateDir, filepath.Join(cfg.StateDir, "tls")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create state directory: %w", err)
		}
	}

	cert, err := loadCertificate(cfg)
	if err != nil {
		return err
	}
	certFP := rpc.Fingerprint(cert.Certificate[0])

	// The one and only client of the process: it is shared by the prober, the
	// setup manager and the handlers, so that trust on first use cannot race.
	pins := rpc.PinStore{Path: filepath.Join(cfg.StateDir, pinFileName)}
	logAdminIPIsolation(logger, cfg.AdminIPPath)
	client := rpc.NewClient(cfg.SoftEtherURL, pins, true)
	prober := softether.Prober{Client: client}
	aud := audit.New(out)
	handler := web.NewServer(web.Deps{
		Cfg:      cfg,
		Client:   client,
		Prober:   prober,
		Setup:    setup.NewManager(cfg.RuntimeDir, client, prober, logger),
		Sessions: web.NewSessionStore(cfg.SessionIdle, cfg.SessionMax, time.Now),
		Audit:    aud,
	})

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	probeCtx, stopProbe := context.WithCancel(ctx)
	var probeDone sync.WaitGroup
	probeDone.Add(1)
	go func() {
		defer probeDone.Done()
		handler.RunProbeLoop(probeCtx)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()

	logger.Info("listening",
		"addr", ln.Addr().String(),
		"softether_url", cfg.SoftEtherURL,
		"cert_sha256", certFP)
	if ready != nil {
		ready(ln.Addr())
	}

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		if err := srv.Shutdown(shCtx); err != nil {
			runErr = fmt.Errorf("shutdown: %w", err)
			srv.Close()
		}
		cancel()
		<-serveErr // ServeTLS returns ErrServerClosed right after Shutdown
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve: %w", err)
		}
	}
	stopProbe()
	probeDone.Wait()
	return runErr
}

// logAdminIPIsolation classifies adminip.txt and writes the result to the
// journal (design 5.1): a warning, with the entries concerned, when the VPN
// server can be administered from addresses other than loopback or when the
// file cannot be read.
func logAdminIPIsolation(logger *slog.Logger, path string) {
	iso, err := softether.ClassifyAdminIP(path)
	switch {
	case err != nil:
		logger.Warn("cannot read adminip.txt: isolation of the administration unknown", "path", path, "err", err.Error())
	case iso.Missing:
		logger.Warn("adminip.txt missing: any address may administer the VPN server", "path", path, "missing", true)
	case !iso.Isolated:
		logger.Warn("adminip.txt allows administration from non-loopback addresses", "path", path, "offending", iso.Offending, "ignored", iso.Ignored)
	default:
		logger.Info("adminip.txt restricts administration to loopback", "path", path, "ignored", iso.Ignored)
	}
}

// loadCertificate returns the configured HTTPS certificate, or the
// self-signed one kept in StateDir/tls, creating it on first use.
func loadCertificate(cfg config.Config) (tls.Certificate, error) {
	certPath, keyPath := cfg.TLSCert, cfg.TLSKey
	switch {
	case certPath != "" && keyPath != "":
		// configured by the operator
	case certPath != "" || keyPath != "":
		return tls.Certificate{}, errors.New("tls_cert and tls_key must be set together")
	default:
		certPath = filepath.Join(cfg.StateDir, "tls", "cert.pem")
		keyPath = filepath.Join(cfg.StateDir, "tls", "key.pem")
		hosts, err := selfSignedHosts(cfg.Listen)
		if err != nil {
			return tls.Certificate{}, err
		}
		if _, err := tlsself.EnsureSelfSigned(certPath, keyPath, hosts, time.Now()); err != nil {
			return tls.Certificate{}, err
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load HTTPS certificate: %w", err)
	}
	return cert, nil
}

// selfSignedHosts lists the names of the self-signed certificate: the host of
// listen (unless it is a wildcard), then the loopback names.
func selfSignedHosts(listen string) ([]string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", listen, err)
	}
	var hosts []string
	if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
		hosts = append(hosts, host)
	}
	return append(hosts, "localhost", "127.0.0.1", "::1"), nil
}
