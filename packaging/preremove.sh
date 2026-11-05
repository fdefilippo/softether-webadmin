#!/bin/sh
# deb: $1 = remove | upgrade | deconfigure | failed-upgrade
# rpm: $1 = number of instances left after this operation (0 = real removal)
set -e

case "$1" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now softether-webadmin.service >/dev/null 2>&1 || true
	fi
	;;
esac

exit 0
