package rpc

import (
	"errors"
	"fmt"
)

var (
	// ErrUnauthorized is returned when the server answers HTTP 401.
	ErrUnauthorized = errors.New("rpc: unauthorized")

	// ErrUnreachable wraps network and timeout errors: the server could not be
	// contacted or did not answer in time.
	ErrUnreachable = errors.New("rpc: server unreachable")
)

// CertMismatchError reports that the certificate presented by the server does
// not match the pinned one. Pinned is empty when no pin exists and trusting on
// first use is not allowed. No request (and so no credentials) is sent when
// this error is returned.
type CertMismatchError struct {
	Pinned    string
	Presented string
}

func (e *CertMismatchError) Error() string {
	if e.Pinned == "" {
		return fmt.Sprintf("rpc: no pinned server certificate (presented %s)", e.Presented)
	}
	return fmt.Sprintf("rpc: server certificate mismatch (pinned %s, presented %s)", e.Pinned, e.Presented)
}

// APIError is the "error" member of a JSON-RPC response.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("rpc: API error %d: %s", e.Code, e.Message)
}
