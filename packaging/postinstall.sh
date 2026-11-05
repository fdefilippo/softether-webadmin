#!/bin/sh
# deb: $1 = configure ($2 = previously configured version, empty on first install)
#      or abort-upgrade | abort-remove | abort-deconfigure
# rpm: $1 = number of instances installed after this operation (1 = install, 2 = upgrade)
set -e

adminip_dir=/var/lib/softether
adminip=$adminip_dir/adminip.txt

case "$1" in
abort-upgrade | abort-remove | abort-deconfigure)
	exit 0
	;;
esac

# Fresh install: deb has no old version in $2, rpm passes 1.
fresh=no
case "$1" in
1) fresh=yes ;;
configure) [ -z "${2:-}" ] && fresh=yes ;;
esac

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# On upgrade, pick up the new binary if the service is already running.
	if [ "$fresh" = no ]; then
		systemctl try-restart softether-webadmin.service >/dev/null 2>&1 || true
	fi
fi

# Restrict SoftEther remote administration to loopback if nobody has an
# adminip.txt yet. An existing file (or symlink) is never touched.
#
# The FHS vpnserver unit (StateDirectory=softether) creates its state dir only
# on its first start: when that unit is installed, create the dir now (0700
# root) so that adminip.txt is in place before the VPN server ever starts.
# Without that unit the dir is never created here: SoftEther may live
# elsewhere (see adminip_path in /etc/softether-webadmin/config.toml).
fhs_unit=/usr/lib/systemd/system/softether-vpnserver.service
if [ ! -d "$adminip_dir" ] && [ -f "$fhs_unit" ] &&
	grep -Eq '^[[:space:]]*StateDirectory=(.*[[:space:]])?softether([[:space:]]|$)' "$fhs_unit"; then
	if (umask 077 && mkdir "$adminip_dir") 2>/dev/null; then
		chmod 0700 "$adminip_dir" || true
	fi
fi

kept_note="NOTE: existing adminip.txt kept unchanged; the web UI will warn if it is not loopback-only"
if [ -d "$adminip_dir" ]; then
	if [ -e "$adminip" ] || [ -L "$adminip" ]; then
		echo "$kept_note"
	# noclobber (O_EXCL) so a concurrently created file is not overwritten.
	elif (
		umask 077
		set -C
		cat >"$adminip" <<'ADMINIP'
# Created by the softether-webadmin package.
# SoftEther accepts remote administration only from the addresses listed here.
127.0.0.1/32
::1/128
ADMINIP
	) 2>/dev/null; then
		chmod 0600 "$adminip" || true
		echo "NOTE: created $adminip allowing remote administration from loopback only (127.0.0.1/32, ::1/128)."
		echo "      Edit it to allow other addresses, e.g. for the SoftEther VPN Server Manager."
	elif [ -e "$adminip" ] || [ -L "$adminip" ]; then
		echo "$kept_note" # created by somebody else in the meantime
	else
		cat <<NOTE
WARNING: could not create $adminip: until it exists, SoftEther accepts
         remote administration from any address. Create it (loopback only):
           printf '127.0.0.1/32\\n::1/128\\n' >$adminip && chmod 0600 $adminip
         or use "Restrict to loopback" on the softether-webadmin dashboard.
NOTE
	fi
else
	cat <<NOTE
NOTE: $adminip_dir does not exist, so $adminip was not created and,
      until it exists, SoftEther accepts remote administration from any address.
      After the first start of softether-vpnserver, create it (loopback only):
        printf '127.0.0.1/32\\n::1/128\\n' >$adminip && chmod 0600 $adminip
      or restart softether-webadmin and use "Restrict to loopback" on its
      dashboard. If SoftEther keeps its data elsewhere, set adminip_path in
      /etc/softether-webadmin/config.toml.
NOTE
fi

if [ "$fresh" = yes ]; then
	echo "softether-webadmin is installed but not started. To enable and start it, run:"
	echo "  systemctl enable --now softether-webadmin"
fi

exit 0
