#!/bin/sh
# Install-test a softether-webadmin .deb or .rpm. Meant to run as root inside a
# throw-away container (see packaging/test-in-container.sh):
#
#   packaging/test-install.sh /dist/softether-webadmin_1.2.3_amd64.deb
#
# Checks: install, "version", unit file, systemd-analyze verify, adminip.txt
# creation (0600) when /var/lib/softether pre-exists, an existing adminip.txt
# left byte-identical on reinstall, and clean removal.
set -eu

pkg=${1:?usage: test-install.sh <package-file>}
[ -f "$pkg" ] || { echo "FAIL: package file not found: $pkg" >&2; exit 1; }

unit=/usr/lib/systemd/system/softether-webadmin.service
adminip_dir=/var/lib/softether
adminip=$adminip_dir/adminip.txt
out=$(mktemp)
trap 'rm -f "$out"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok: $*"; }

case $pkg in
*.deb)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	pkg_install()   { apt-get install -y -qq "$pkg"; }
	pkg_reinstall() { apt-get install -y -qq --reinstall "$pkg"; }
	pkg_remove()    { apt-get remove -y -qq softether-webadmin; }
	pkg_get_systemd() { apt-get install -y -qq systemd >/dev/null; }
	;;
*.rpm)
	pkg_install()   { dnf install -y "$pkg"; }
	pkg_reinstall() { dnf reinstall -y "$pkg"; }
	pkg_remove()    { dnf remove -y -q softether-webadmin; }
	pkg_get_systemd() { dnf install -y -q systemd >/dev/null; }
	;;
*) fail "unsupported package type: $pkg" ;;
esac

mode_of() { stat -c %a "$1"; }

# Scenario A: /var/lib/softether does not exist -> nothing must be created there.
rm -rf "$adminip_dir"
pkg_install >"$out" 2>&1 || { cat "$out"; fail "install (no vpnserver dir)"; }
cat "$out"
[ ! -e "$adminip_dir" ] || fail "$adminip_dir was created although it did not exist"
ok "install without $adminip_dir leaves it alone"
grep -q 'systemctl enable --now softether-webadmin' "$out" \
	|| fail "postinstall did not print the 'systemctl enable --now' hint"
ok "postinstall prints the enable hint"

softether-webadmin version | grep -q '^softether-webadmin ' || fail "version output"
ok "softether-webadmin version: $(softether-webadmin version)"
[ -f "$unit" ] || fail "unit file missing: $unit"
ok "unit file present"
[ -f /etc/softether-webadmin/config.toml ] || fail "config.toml missing"
ok "config.toml present"

# systemd-analyze verify (install systemd if the image lacks it).
if ! command -v systemd-analyze >/dev/null 2>&1; then
	pkg_get_systemd >/dev/null 2>&1 || true
fi
if command -v systemd-analyze >/dev/null 2>&1; then
	if systemd-analyze verify "$unit" >"$out" 2>&1; then
		ok "systemd-analyze verify"
	else
		cat "$out"
		fail "systemd-analyze verify reported problems"
	fi
	[ ! -s "$out" ] || { echo "systemd-analyze output:"; cat "$out"; }
else
	echo "SKIP: systemd-analyze not available on this distribution (verify check only)"
fi

pkg_remove >/dev/null 2>&1 || fail "remove"
[ ! -e /usr/bin/softether-webadmin ] || fail "binary left after remove"
[ ! -e "$unit" ] || fail "unit left after remove"
ok "remove"

# Scenario B: /var/lib/softether pre-exists (0700 root, like vpnserver) -> adminip.txt created 0600.
mkdir -p "$adminip_dir"
chmod 0700 "$adminip_dir"
pkg_install >"$out" 2>&1 || { cat "$out"; fail "install (with vpnserver dir)"; }
cat "$out"
[ -f "$adminip" ] || fail "adminip.txt was not created"
[ "$(mode_of "$adminip")" = 600 ] || fail "adminip.txt mode is $(mode_of "$adminip"), want 600"
grep -qx '127.0.0.1/32' "$adminip" || fail "adminip.txt lacks 127.0.0.1/32"
grep -qx '::1/128' "$adminip" || fail "adminip.txt lacks ::1/128"
[ "$(grep -cv '^#' "$adminip")" = 2 ] || fail "adminip.txt has unexpected non-comment lines"
[ "$(mode_of "$adminip_dir")" = 700 ] || fail "$adminip_dir mode changed"
ok "adminip.txt created with mode 0600 and loopback entries"

# Scenario C: pre-existing, hand-edited adminip.txt must stay byte-identical,
# also across a reinstall and across removal.
printf '# hand edited\r\n10.1.2.3/24\r\n' >"$adminip"
chmod 0640 "$adminip"
sum_before=$(sha256sum "$adminip")
pkg_reinstall >"$out" 2>&1 || { cat "$out"; fail "reinstall"; }
cat "$out"
[ "$(sha256sum "$adminip")" = "$sum_before" ] || fail "adminip.txt changed on reinstall"
[ "$(mode_of "$adminip")" = 640 ] || fail "adminip.txt mode changed on reinstall"
grep -q 'existing adminip.txt kept unchanged' "$out" || fail "missing 'kept unchanged' note"
ok "existing adminip.txt kept byte-identical on reinstall"

pkg_remove >/dev/null 2>&1 || fail "second remove"
[ "$(sha256sum "$adminip")" = "$sum_before" ] || fail "adminip.txt changed on remove"
ok "existing adminip.txt untouched by remove"

# Scenario D: with a (stubbed) running systemd, scriptlets must reload, must never
# enable/start on install, and must "disable --now" only on real removal.
mkdir -p /run/systemd/system
calls=$(mktemp)
# Install the stub where maintainer scripts find it (dpkg resets PATH); keep a real systemctl aside.
sysctl_path=/usr/bin/systemctl
if [ -e "$sysctl_path" ]; then mv "$sysctl_path" "$sysctl_path.real"; fi
restore_systemctl() {
	rm -f "$sysctl_path"
	if [ -e "$sysctl_path.real" ]; then mv "$sysctl_path.real" "$sysctl_path"; fi
	rmdir /run/systemd/system 2>/dev/null || true
}
cat >"$sysctl_path" <<STUB
#!/bin/sh
echo "\$*" >>$calls
STUB
chmod +x "$sysctl_path"
trap 'rm -f "$out" "$calls"; restore_systemctl' EXIT

pkg_install >"$out" 2>&1 || { cat "$out"; fail "install with stub systemctl"; }
if grep -E '^(enable|disable|start|stop|restart)( |$)' "$calls" >/dev/null; then
	cat "$calls"; fail "fresh install enabled, started or stopped the service"
fi
ok "fresh install does not enable or start the service"
: >"$calls"
pkg_reinstall >"$out" 2>&1 || { cat "$out"; fail "reinstall with stub systemctl"; }
grep -qx 'daemon-reload' "$calls" || fail "postinstall did not daemon-reload"
if grep -E '^(enable|disable|start|stop|restart)( |$)' "$calls" >/dev/null; then
	cat "$calls"; fail "upgrade/reinstall enabled, started or stopped the service"
fi
ok "upgrade never enables, starts or stops the service (daemon-reload, try-restart only)"

: >"$calls"
pkg_remove >"$out" 2>&1 || { cat "$out"; fail "remove with stub systemctl"; }
grep -qx 'disable --now softether-webadmin.service' "$calls" || { cat "$calls"; fail "removal did not disable --now"; }
grep -qx 'daemon-reload' "$calls" || fail "postremove did not daemon-reload"
ok "removal disables --now and reloads"

restore_systemctl
echo "PASS: $pkg"
