// Package rpc implements the JSON-RPC transport to the SoftEther VPN Server
// management API, with the server TLS certificate pinned by fingerprint.
package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	callTimeout      = 15 * time.Second
	maxResponseBytes = 16 << 20
)

// Credential holds the credentials of one call. An empty Username means the
// server administrator. It is never logged or persisted: String and GoString
// redact the password.
type Credential struct {
	Username, Password string
}

func (c Credential) String() string {
	return "Credential{Username:" + strconv.Quote(c.Username) + ", Password:<redacted>}"
}
func (c Credential) GoString() string { return c.String() }

// pinStoreError marks a failure of the pin store during the TLS handshake; it
// is not a network error.
type pinStoreError struct{ err error }

func (e *pinStoreError) Error() string { return "rpc: pin store: " + e.err.Error() }
func (e *pinStoreError) Unwrap() error { return e.err }

// Client calls the SoftEther JSON-RPC API. The server certificate is verified
// during the TLS handshake against the pinned fingerprint, so a mismatch
// aborts the connection before any HTTP request (and Authorization header) is
// sent.
type Client struct {
	url       string
	pins      PinStore
	allowTOFU bool
	http      *http.Client
	nextID    atomic.Uint64

	mu       sync.Mutex // serializes pin verification, guards observed
	observed string
}

// NewClient returns a client for the API at baseURL. When no pin exists and
// allowTOFU is true, the first certificate presented is trusted and saved.
func NewClient(baseURL string, pins PinStore, allowTOFU bool) *Client {
	c := &Client{url: baseURL, pins: pins, allowTOFU: allowTOFU}
	// Every client has its own transport: no sharing with http.DefaultTransport,
	// no proxy from the environment (credentials must go straight to the
	// server), and no connection reuse, so that every call is verified against
	// the current pin during a fresh handshake.
	tr := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			// The certificate is self-signed; trust comes from the pin,
			// checked in VerifyConnection.
			InsecureSkipVerify: true,
			VerifyConnection:   c.verifyConnection,
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: callTimeout,
	}
	c.http = &http.Client{
		Transport: tr,
		// Never follow redirects: credentials must not leave the pinned host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

func (c *Client) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("rpc: server presented no certificate")
	}
	presented := Fingerprint(cs.PeerCertificates[0].Raw)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed = presented

	pinned, ok, err := c.pins.Load()
	if err != nil {
		return &pinStoreError{err}
	}
	if ok {
		if pinned != presented {
			return &CertMismatchError{Pinned: pinned, Presented: presented}
		}
		return nil
	}
	if !c.allowTOFU {
		return &CertMismatchError{Presented: presented}
	}
	if err := c.pins.Save(presented); err != nil {
		return &pinStoreError{err}
	}
	return nil
}

// ObservedFingerprint returns the fingerprint of the last certificate seen,
// or "" if none yet.
func (c *Client) ObservedFingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observed
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *APIError       `json:"error"`
}

// Call invokes method with params and decodes the result into result (which
// may be nil). It times out after 15 seconds and is never retried.
func (c *Client) Call(ctx context.Context, cred Credential, method string, params, result any) error {
	if params == nil {
		params = struct{}{}
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      strconv.FormatUint(c.nextID.Add(1), 10),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("rpc: encode request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rpc: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cred.Username, cred.Password) // raw UTF-8 bytes, no escaping

	resp, err := c.http.Do(req)
	if err != nil {
		return classifyTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc: unexpected HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	if len(data) > maxResponseBytes {
		return errors.New("rpc: response too large")
	}
	var out rpcResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("rpc: decode response: %w", err)
	}
	if out.Error != nil {
		return out.Error
	}
	if result == nil {
		return nil
	}
	if len(out.Result) == 0 {
		return errors.New("rpc: response has no result")
	}
	if err := json.Unmarshal(out.Result, result); err != nil {
		return fmt.Errorf("rpc: decode result: %w", err)
	}
	return nil
}

// classifyTransportError maps a transport failure: certificate and pin store
// errors are returned as such, everything else is ErrUnreachable.
func classifyTransportError(err error) error {
	var mm *CertMismatchError
	if errors.As(err, &mm) {
		return mm
	}
	var pe *pinStoreError
	if errors.As(err, &pe) {
		return pe
	}
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}

// TrustServerCert performs only a TLS handshake against the host:port of
// apiURL (no HTTP request, no credentials) and saves the fingerprint of the
// presented leaf certificate in pins. If expected is not empty it must match
// (case-insensitively), otherwise a *CertMismatchError is returned and
// nothing is saved. It returns the saved fingerprint.
func TrustServerCert(ctx context.Context, apiURL string, pins PinStore, expected string) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("rpc: invalid URL: %w", err)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // trust is established by the caller via `expected`
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("rpc: server presented no certificate")
	}
	fp := Fingerprint(certs[0].Raw)

	if expected != "" && !strings.EqualFold(strings.TrimSpace(expected), fp) {
		return "", &CertMismatchError{Pinned: strings.ToLower(strings.TrimSpace(expected)), Presented: fp}
	}
	if err := pins.Save(fp); err != nil {
		return "", err
	}
	return fp, nil
}
