// Package softether holds SoftEther-specific logic built on the rpc package.
package softether

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
)

// State is the observed state of the VPN server's administrator access.
type State int

const (
	// StateEmptyPassword: the server accepts any credential, i.e. the
	// administrator password is still empty (first access).
	StateEmptyPassword State = iota
	// StatePasswordSet: the server refused the probe credential.
	StatePasswordSet
	// StateUnreachable: the server could not be contacted or probed.
	StateUnreachable
	// StateCertMismatch: the server certificate differs from the pinned one.
	StateCertMismatch
)

func (s State) String() string {
	switch s {
	case StateEmptyPassword:
		return "empty-password"
	case StatePasswordSet:
		return "password-set"
	case StateUnreachable:
		return "unreachable"
	case StateCertMismatch:
		return "cert-mismatch"
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// Prober determines the State of the server.
type Prober struct {
	Client *rpc.Client
}

// Probe calls Test with an empty user name and a random password (32 random
// bytes, hex). A server with an empty administrator password accepts any
// credential; one with a password set refuses it. Only a certificate mismatch
// and unexpected errors are returned as errors.
func (p Prober) Probe(ctx context.Context) (State, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return StateUnreachable, fmt.Errorf("softether: probe password: %w", err)
	}
	err := p.Client.Test(ctx, rpc.Credential{Username: "", Password: hex.EncodeToString(b[:])})

	var mm *rpc.CertMismatchError
	switch {
	case err == nil:
		return StateEmptyPassword, nil
	case errors.Is(err, rpc.ErrUnauthorized):
		return StatePasswordSet, nil
	case errors.As(err, &mm):
		return StateCertMismatch, err
	case errors.Is(err, rpc.ErrUnreachable):
		return StateUnreachable, nil
	default:
		return StateUnreachable, err
	}
}
