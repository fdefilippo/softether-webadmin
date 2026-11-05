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

# Restrict SoftEther remote administration to loopback, but only when the
# VPN server is installed (its state dir exists) and only if nobody has an
# adminip.txt yet. An existing file (or symlink) is never touched.
if [ -d "$adminip_dir" ]; then
	if [ -e "$adminip" ] || [ -L "$adminip" ]; then
		echo "NOTE: existing adminip.txt kept unchanged; the web UI will warn if it is not loopback-only"
	else
		# noclobber (O_EXCL) so a concurrently created file is not overwritten.
		if (
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
		else
			echo "NOTE: existing adminip.txt kept unchanged; the web UI will warn if it is not loopback-only"
		fi
	fi
fi

if [ "$fresh" = yes ]; then
	echo "softether-webadmin is installed but not started. To enable and start it, run:"
	echo "  systemctl enable --now softether-webadmin"
fi

exit 0
