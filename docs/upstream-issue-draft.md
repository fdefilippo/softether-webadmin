**Title:** Proposal: web administration console as a separate daemon (Go + htmx) on top of the JSON-RPC API

Hi all,

I'd like to propose a web-based administration console for SoftEther VPN Server. Before writing much code I want to know whether the project would welcome it and where it should live.

### Motivation

- Administering a server today means installing and updating the Windows Server Manager on every admin workstation, or using `vpncmd`.
- A server installed from packages (see #2327) starts unconfigured. The first steps (certificate, listeners, protocols, clustering) need one of those two tools.
- The built-in `/admin/` HTML5 console is a small sample that is still under construction.

### What I found

- The JSON-RPC API (`/api/`) goes through the same `AdminDispatch` as the native admin protocol. All 148 admin RPCs are reachable, and they cover every call made by the Server Manager and by `vpncmd`.
  - I ran a set of 47 write operations through JSON-RPC against a real server, covering hubs, users, policies, access lists, SecureNAT, certificates, IPsec, OpenVPN, cascades and L3 switches. All of them worked, except local bridge, which the test container couldn't support.
- `adminip.txt` (`CheckAdminSourceAddress()`) can restrict administration to `127.0.0.1` and `::1`. The VPN listeners stay public, so only a local component can administer the server.
- 15 RPCs are missing from `developer_tools/vpnserver-jsonrpc-clients/README.md`: WireGuard keys, `Get/SetProtoOptions`, `Get/SetPortsUDP`, `GetServerCipherList`, `EnumEthVLan`/`SetEnableEthVLan`, license and `Debug`. I'm happy to document them.

### Proposal

- **Separate daemon:** a single static Go binary, one per VPN server. It serves an HTTPS web UI (server-rendered HTML and htmx, with no Node toolchain) and talks only to the local JSON-RPC API.
- **Security model:**
  - the daemon listens on localhost or the management network only, never on the internet by default;
  - `adminip.txt` limits SoftEther administration to localhost;
  - no SoftEther password is stored: users log in with the server admin password or with a hub name and hub password, and the server enforces its own permissions;
  - sessions use secure cookies, with CSRF protection and an audit log.
- **Roles:** server administrator, and hub administrator limited to their own hub.
- **Scope:**
  - phase 1 sets up a fresh server: listeners, certificate and ciphers, IPsec/L2TP/EtherIP, OpenVPN/SSTP, WireGuard, cascades, local bridge, L3 switches, clustering, DDNS/VPN Azure, syslog, logs, and config backup and restore;
  - phase 2 covers day-to-day hub management: users, groups, access lists, SecureNAT/DHCP, sessions and statistics.
- **i18n:** English and Italian from the start, with message catalogs so more languages can be added.
- **Packaging:** `softether-webadmin` deb/rpm with a systemd unit, built by CI like the server packages.
- **Go client:** a typed Go client is generated inside the webadmin repository for now. Extending `vpnserver-jsonrpc-codegen` to emit Go, and documenting the 15 missing RPCs, would follow as separate contributions.

### Where the work happens

Development starts in a separate repository, https://github.com/fdefilippo/softether-webadmin. Its design document is currently in Italian and will be translated. I'm happy to move the code wherever you prefer.

The design also covers:
- a one-time setup token for the first access, because a server with an empty admin password accepts any credentials;
- pinning the vpnserver certificate fingerprint on the loopback connection, with a rotation procedure;
- guards against operations that would cut the daemon off from the server.

### Questions for maintainers

1. Would you accept this into the project? If so, where should it live: a directory in this repository (for example `src/webadmin` or `developer_tools/`), or a separate repository under the SoftEtherVPN organization?
2. Is Go acceptable as the language for this component?
3. Would you prefer the phase-1 work as one PR, or split into several smaller ones?

Thanks!
