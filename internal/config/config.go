// Package config loads the softether-webadmin daemon configuration.
package config

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is where the daemon looks for its configuration file.
const DefaultPath = "/etc/softether-webadmin/config.toml"

// Config holds the daemon settings. Durations are written in the TOML file as
// Go duration strings such as "30m".
type Config struct {
	Listen        string        `toml:"listen"`
	TLSCert       string        `toml:"tls_cert"`
	TLSKey        string        `toml:"tls_key"`
	SoftEtherURL  string        `toml:"softether_url"`
	AdminIPPath   string        `toml:"adminip_path"`
	StateDir      string        `toml:"state_dir"`
	RuntimeDir    string        `toml:"runtime_dir"`
	SessionIdle   time.Duration `toml:"session_idle"`
	SessionMax    time.Duration `toml:"session_max"`
	ProbeInterval time.Duration `toml:"probe_interval"`

	LoginMaxFailures int           `toml:"login_max_failures"`
	LoginWindow      time.Duration `toml:"login_window"`
}

// Default returns the configuration used when no file overrides a key.
// TLSCert and TLSKey are empty: the daemon then uses a self-signed certificate
// kept under StateDir.
func Default() Config {
	return Config{
		Listen:           "127.0.0.1:9443",
		SoftEtherURL:     "https://127.0.0.1:5555/api/",
		AdminIPPath:      "/var/lib/softether/adminip.txt",
		StateDir:         "/var/lib/softether-webadmin",
		RuntimeDir:       "/run/softether-webadmin",
		SessionIdle:      30 * time.Minute,
		SessionMax:       8 * time.Hour,
		ProbeInterval:    60 * time.Second,
		LoginMaxFailures: 5,
		LoginWindow:      15 * time.Minute,
	}
}

// Load reads the TOML file at path on top of Default. Missing keys keep their
// default; a missing file or an unknown key is an error.
func Load(path string) (Config, error) {
	c := Default()
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return Config{}, fmt.Errorf("config %s: unknown key(s): %s", path, strings.Join(keys, ", "))
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// validate rejects values that would disable a protection: sessions that
// never expire, a probe loop that spins, a login limiter that is off.
func (c Config) validate() error {
	for _, d := range []struct {
		key string
		v   time.Duration
	}{
		{"session_idle", c.SessionIdle},
		{"session_max", c.SessionMax},
		{"probe_interval", c.ProbeInterval},
		{"login_window", c.LoginWindow},
	} {
		if d.v <= 0 {
			return fmt.Errorf("%s must be positive, got %v", d.key, d.v)
		}
	}
	if c.LoginMaxFailures <= 0 {
		return fmt.Errorf("login_max_failures must be positive, got %d", c.LoginMaxFailures)
	}
	if c.SessionMax < c.SessionIdle {
		return fmt.Errorf("session_max (%v) must not be shorter than session_idle (%v)", c.SessionMax, c.SessionIdle)
	}
	return nil
}
