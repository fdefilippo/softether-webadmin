// Command softether-webadmin is a web administration daemon for SoftEther VPN Server.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fdefilippo/softether-webadmin/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK    = 0
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	_ = configPath // used by the subcommands once they are implemented

	switch cmd {
	case "version":
		fmt.Fprintf(stdout, "softether-webadmin %s\n", version)
		return exitOK
	case "serve", "setup-token", "trust-server-cert":
		fmt.Fprintf(stderr, "softether-webadmin %s: not implemented\n", cmd)
		return exitUsage
	default:
		fmt.Fprintf(stderr, "softether-webadmin: unknown command %q\n"+
			"usage: softether-webadmin [serve|setup-token|trust-server-cert|version] [--config path]\n", cmd)
		return exitUsage
	}
}
