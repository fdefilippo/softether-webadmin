package softether

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/fdefilippo/softether-webadmin/internal/rpc"
	"github.com/fdefilippo/softether-webadmin/internal/rpc/rpctest"
)

// setup returns a fake server and a client pinned to its certificate.
func setup(t *testing.T) (*rpctest.FakeServer, *rpc.Client) {
	t.Helper()
	fake := rpctest.New(t)
	pins := rpc.PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := pins.Save(rpc.Fingerprint(fake.Cert().Raw)); err != nil {
		t.Fatal(err)
	}
	return fake, rpc.NewClient(fake.URL(), pins, false)
}

func TestProbeEmptyPassword(t *testing.T) {
	_, c := setup(t)
	st, err := Prober{Client: c}.Probe(context.Background())
	if err != nil || st != StateEmptyPassword {
		t.Fatalf("Probe = %v, %v; want StateEmptyPassword", st, err)
	}
}

func TestProbePasswordSet(t *testing.T) {
	fake, c := setup(t)
	fake.SetPassword("x")
	st, err := Prober{Client: c}.Probe(context.Background())
	if err != nil || st != StatePasswordSet {
		t.Fatalf("Probe = %v, %v; want StatePasswordSet", st, err)
	}
}

func TestProbeUnreachable(t *testing.T) {
	fake, c := setup(t)
	fake.Stop()
	st, err := Prober{Client: c}.Probe(context.Background())
	if st != StateUnreachable {
		t.Fatalf("Probe = %v, %v; want StateUnreachable", st, err)
	}
}

func TestProbeCertMismatch(t *testing.T) {
	fake, _ := setup(t)
	pins := rpc.PinStore{Path: filepath.Join(t.TempDir(), "pin")}
	if err := pins.Save("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	c := rpc.NewClient(fake.URL(), pins, false)
	st, err := Prober{Client: c}.Probe(context.Background())
	var mm *rpc.CertMismatchError
	if st != StateCertMismatch || !errors.As(err, &mm) {
		t.Fatalf("Probe = %v, %v; want StateCertMismatch with *CertMismatchError", st, err)
	}
	if fake.Requests() != 0 {
		t.Errorf("server saw %d requests despite pin mismatch", fake.Requests())
	}
}

func TestProbeRecoversAfterRestart(t *testing.T) {
	fake, c := setup(t)
	p := Prober{Client: c}
	fake.Stop()
	if st, _ := p.Probe(context.Background()); st != StateUnreachable {
		t.Fatalf("stopped: state = %v", st)
	}
	fake.Start()
	if st, err := p.Probe(context.Background()); st != StateEmptyPassword || err != nil {
		t.Fatalf("restarted: Probe = %v, %v", st, err)
	}
}

func TestSetServerPasswordThenProbe(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	p := Prober{Client: c}
	if st, _ := p.Probe(ctx); st != StateEmptyPassword {
		t.Fatalf("before: state = %v", st)
	}
	if err := c.SetServerPassword(ctx, rpc.Credential{}, "pa:ss è"); err != nil {
		t.Fatal(err)
	}
	if st, err := p.Probe(ctx); st != StatePasswordSet || err != nil {
		t.Fatalf("after: Probe = %v, %v", st, err)
	}
}
