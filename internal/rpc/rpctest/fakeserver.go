// Package rpctest provides a fake SoftEther VPN Server JSON-RPC endpoint for
// tests. It deliberately does not import the rpc package.
package rpctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// FakeServer imitates the /api/ endpoint of vpnserver: HTTP Basic
// authentication (HTTP 401 without body on failure), JSON-RPC errors in an
// HTTP 200 response. Stop and Start keep the same address and the same TLS
// certificate. It is safe for concurrent use.
type FakeServer struct {
	cert tls.Certificate
	leaf *x509.Certificate
	addr string // host:port, fixed at creation

	mu           sync.Mutex
	password     string
	requests     int
	methods      map[string]int
	stopOn       string       // method after which the server stops, "" for none
	dropOn       string       // method after which the connection is dropped, "" for none
	dropBeforeOn string       // method whose connection is dropped without applying it
	srv          *http.Server // nil while stopped
}

// New starts a TLS fake server on 127.0.0.1 with an empty administrator
// password. It is stopped automatically when the test ends.
func New(t testing.TB) *FakeServer {
	t.Helper()
	cert, leaf := newCert(t)
	f := &FakeServer{cert: cert, leaf: leaf}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rpctest: listen: %v", err)
	}
	f.addr = ln.Addr().String()
	f.serve(ln)
	t.Cleanup(f.Stop)
	return f
}

func newCert(t testing.TB) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("rpctest: key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rpctest fake vpnserver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("rpctest: certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("rpctest: parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// serve starts an http.Server on ln. f.mu must not be held.
func (f *FakeServer) serve(ln net.Listener) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(f.handle),
		ErrorLog:          log.New(io.Discard, "", 0), // silence TLS handshake noise
		ReadHeaderTimeout: 10 * time.Second,
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
	f.mu.Lock()
	f.srv = srv
	f.mu.Unlock()
	go srv.Serve(tlsLn)
}

// Stop closes the listener and all connections. Calling it twice is a no-op.
func (f *FakeServer) Stop() {
	f.mu.Lock()
	srv := f.srv
	f.srv = nil
	f.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// Start restarts a stopped server on the same address with the same
// certificate. It is a no-op if the server is running. The password and the
// request counter are kept.
func (f *FakeServer) Start() {
	f.mu.Lock()
	running := f.srv != nil
	f.mu.Unlock()
	if running {
		return
	}
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ { // the port may linger briefly after Close
		if ln, err = net.Listen("tcp", f.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		panic("rpctest: cannot re-listen on " + f.addr + ": " + err.Error())
	}
	f.serve(ln)
}

// SetPassword sets the server administrator password; "" means empty, in
// which case any credential is accepted.
func (f *FakeServer) SetPassword(p string) {
	f.mu.Lock()
	f.password = p
	f.mu.Unlock()
}

// StopAfter arms a one-shot hook: when the server receives method it applies
// it, then stops (as by Stop) and aborts the connection without writing a
// response. This simulates "request possibly applied, response lost, server
// gone". Call Start to bring the server back.
func (f *FakeServer) StopAfter(method string) {
	f.mu.Lock()
	f.stopOn = method
	f.mu.Unlock()
}

// DropAfter arms a one-shot hook: when the server receives method it applies
// it and aborts the connection without writing a response, but keeps running.
func (f *FakeServer) DropAfter(method string) {
	f.mu.Lock()
	f.dropOn = method
	f.mu.Unlock()
}

// DropBefore arms a one-shot hook: when the (authenticated) server receives
// method it does NOT apply it and aborts the connection without a response;
// the server keeps running. A (forbidden) retry of the method would therefore
// reach the server and be applied.
func (f *FakeServer) DropBefore(method string) {
	f.mu.Lock()
	f.dropBeforeOn = method
	f.mu.Unlock()
}

// MethodCount returns how many times a JSON-RPC method was received, counting
// every well-formed request, including those refused with HTTP 401.
func (f *FakeServer) MethodCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.methods[method]
}

// Requests returns the number of HTTP requests received, including refused
// ones.
func (f *FakeServer) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// URL returns the complete API URL (https://127.0.0.1:port/api/), ready to be
// passed to rpc.NewClient.
func (f *FakeServer) URL() string { return "https://" + f.addr + "/api/" }

// Cert returns the (constant) server certificate.
func (f *FakeServer) Cert() *x509.Certificate { return f.leaf }

func (f *FakeServer) authorized(r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.password == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok || (user != "" && user != "administrator") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(f.password)) == 1
}

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func (f *FakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()

	// Parse first so that every request is counted by method, including
	// those refused by the authentication check below.
	var req request
	decodeErr := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	if decodeErr == nil {
		f.mu.Lock()
		if f.methods == nil {
			f.methods = map[string]int{}
		}
		f.methods[req.Method]++
		f.mu.Unlock()
	}

	if !f.authorized(r) {
		w.WriteHeader(http.StatusUnauthorized) // no JSON body, like vpnserver
		return
	}
	if decodeErr != nil {
		reply(w, nil, nil, 1, "parse error")
		return
	}
	f.mu.Lock()
	stop, drop, dropBefore := f.stopOn == req.Method, f.dropOn == req.Method, f.dropBeforeOn == req.Method
	if stop {
		f.stopOn = ""
	}
	if drop {
		f.dropOn = ""
	}
	if dropBefore {
		f.dropBeforeOn = ""
	}
	f.mu.Unlock()
	if dropBefore {
		panic(http.ErrAbortHandler) // not applied, connection killed
	}
	if stop || drop {
		// Apply the method, discard the response, kill the connection.
		f.dispatch(httptest.NewRecorder(), req)
		if stop {
			f.Stop()
		}
		panic(http.ErrAbortHandler)
	}
	f.dispatch(w, req)
}

func (f *FakeServer) dispatch(w http.ResponseWriter, req request) {
	switch req.Method {
	case "Test":
		var p struct {
			IntValue uint32 `json:"IntValue_u32"`
		}
		_ = json.Unmarshal(req.Params, &p)
		reply(w, req.ID, map[string]any{"IntValue_u32": p.IntValue}, 0, "")
	case "GetServerInfo":
		reply(w, req.ID, map[string]any{
			"ServerProductName_str":     "SoftEther VPN Server (Fake)",
			"ServerVersionString_str":   "Version 5.02 Build 5189 (English)",
			"ServerBuildInfoString_str": "Compiled 2024/08/01 by fake",
			"ServerHostName_str":        "fake-vpnserver",
			"ServerType_u32":            0,
			"OsProductName_str":         "Linux (fake)",
		}, 0, "")
	case "GetServerStatus":
		now := time.Now().UTC().Format("2006-01-02T15:04:05.000")
		reply(w, req.ID, map[string]any{
			"NumSessionsTotal_u32": 0,
			"NumHubTotal_u32":      1,
			"StartTime_dt":         now,
			"CurrentTime_dt":       now,
		}, 0, "")
	case "SetServerPassword":
		var p struct {
			Password string `json:"PlainTextPassword_str"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			reply(w, req.ID, nil, 1, "invalid parameters")
			return
		}
		f.SetPassword(p.Password)
		reply(w, req.ID, map[string]any{"PlainTextPassword_str": p.Password}, 0, "")
	default:
		reply(w, req.ID, nil, 1, "not supported")
	}
}

// reply writes a JSON-RPC response; code != 0 makes it an error response.
// Both are HTTP 200, like vpnserver.
func reply(w http.ResponseWriter, id json.RawMessage, result any, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if code != 0 {
		resp["error"] = map[string]any{"code": code, "message": msg}
	} else {
		resp["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
