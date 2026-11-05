package rpc_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/rpc/rpctest"
)

func setup(t *testing.T) (*rpctest.FakeServer, *rpc.Client) {
	t.Helper()
	fake := rpctest.New(t)
	pins := rpc.PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := pins.Save(rpc.Fingerprint(fake.Cert().Raw)); err != nil {
		t.Fatal(err)
	}
	return fake, rpc.NewClient(fake.URL(), pins, false)
}

func TestGetServerInfoDecodes(t *testing.T) {
	_, c := setup(t)
	info, err := c.GetServerInfo(context.Background(), rpc.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Version == "" || info.ProductName == "" || info.Build == "" || info.Hostname == "" || info.OsName == "" {
		t.Errorf("incomplete ServerInfo: %+v", info)
	}
}

func TestGetServerStatusDecodes(t *testing.T) {
	_, c := setup(t)
	st, err := c.GetServerStatus(context.Background(), rpc.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	if st.StartTime == "" || st.CurrentTime == "" {
		t.Errorf("incomplete ServerStatus: %+v", st)
	}
}

func TestTestMethod(t *testing.T) {
	fake, c := setup(t)
	if err := c.Test(context.Background(), rpc.Credential{}); err != nil {
		t.Fatal(err)
	}
	fake.SetPassword("x")
	err := c.Test(context.Background(), rpc.Credential{Username: "", Password: "wrong"})
	if !errors.Is(err, rpc.ErrUnauthorized) {
		t.Fatalf("wrong password: err = %v; want ErrUnauthorized", err)
	}
	if err := c.Test(context.Background(), rpc.Credential{Username: "administrator", Password: "x"}); err != nil {
		t.Fatalf("administrator: %v", err)
	}
	if err := c.Test(context.Background(), rpc.Credential{Username: "", Password: "x"}); err != nil {
		t.Fatalf("empty user: %v", err)
	}
	err = c.Test(context.Background(), rpc.Credential{Username: "bob", Password: "x"})
	if !errors.Is(err, rpc.ErrUnauthorized) {
		t.Fatalf("other user: err = %v; want ErrUnauthorized", err)
	}
}

func TestSetServerPasswordChangesCredentials(t *testing.T) {
	fake, c := setup(t)
	ctx := context.Background()
	if err := c.SetServerPassword(ctx, rpc.Credential{}, "n3w:pä ss"); err != nil {
		t.Fatal(err)
	}
	if err := c.Test(ctx, rpc.Credential{Password: "n3w:pä ss"}); err != nil {
		t.Fatalf("new password refused: %v", err)
	}
	if err := c.Test(ctx, rpc.Credential{}); !errors.Is(err, rpc.ErrUnauthorized) {
		t.Fatalf("old (empty) password: err = %v", err)
	}
	if got := fake.Requests(); got != 3 {
		t.Errorf("Requests = %d; want 3", got)
	}
}

func TestUnknownMethodIsAPIError(t *testing.T) {
	_, c := setup(t)
	err := c.Call(context.Background(), rpc.Credential{}, "NoSuchMethod", nil, nil)
	var ae *rpc.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v; want *APIError", err)
	}
}

func TestFakeServerRestartKeepsAddressAndCert(t *testing.T) {
	fake, c := setup(t)
	url := fake.URL()
	fake.Stop()
	if err := c.Test(context.Background(), rpc.Credential{}); !errors.Is(err, rpc.ErrUnreachable) {
		t.Fatalf("stopped: err = %v; want ErrUnreachable", err)
	}
	fake.Start()
	if fake.URL() != url {
		t.Errorf("URL changed: %s -> %s", url, fake.URL())
	}
	if err := c.Test(context.Background(), rpc.Credential{}); err != nil {
		t.Fatalf("restarted: %v", err)
	}
}
