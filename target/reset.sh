#!/bin/sh
# Returns an OpenBSD firewall to how it was installed: the opposite of
# install.sh, and of every deployment since. Run as root:
#
#   sh reset.sh
#
# It removes the fccdeploy account with its key, the helper and the gate, the
# lines in /etc/doas.conf and /etc/rc.local, and everything the helper kept. It
# replaces
# /etc/pf.conf with the rules OpenBSD is installed with, /etc/examples/pf.conf,
# and loads them. It removes /etc/dhcpd.conf, and stops and disables dhcpd.
#
# The rules OpenBSD is installed with pass everything and do no NAT: networks
# behind the firewall lose their way out, and nothing is filtered any more.
# Connections that are already open, such as yours, stay open.
#
# The network is left as it is: /etc/hostname.*, /etc/sysctl.conf and
# /etc/mygate stay, because taking them away could leave the machine with no
# address to reach it on.
#
# Safe to run again.
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

RULE='permit nopass fccdeploy as root cmd /usr/local/sbin/fcc-pfctl'
BOOT='[ ! -x /usr/local/sbin/fcc-pfctl ] || /usr/local/sbin/fcc-pfctl boot'
FACTORY=/etc/examples/pf.conf

[ "$(id -u)" -eq 0 ] || { echo "run this as root, for example with doas" >&2; exit 1; }
[ "$(uname -s)" = OpenBSD ] || { echo "this is not OpenBSD" >&2; exit 1; }
[ -f "$FACTORY" ] || { echo "$FACTORY is not there, so there are no rules to go back to" >&2; exit 1; }

# A watchdog that is still waiting would load rules again later, and then look
# forever for the folders removed below.
pkill -f '/usr/local/sbin/fcc-pfctl watchdog' || true

# The account goes first, so that a deployer still running cannot get in
# halfway through.
if id fccdeploy >/dev/null 2>&1; then
	pkill -u fccdeploy || true
	userdel -r fccdeploy
fi
! grep -q '^fccdeploy:' /etc/group || groupdel fccdeploy

if [ -f /etc/doas.conf ]; then
	# Copied first, so the new file has the owner and mode of the old one.
	cp -p /etc/doas.conf /etc/doas.conf.fcc-reset
	# grep answers 1 when it prints nothing, which is not a failure here.
	grep -vxF "$RULE" /etc/doas.conf >/etc/doas.conf.fcc-reset || [ "$?" -eq 1 ]
	if [ -s /etc/doas.conf.fcc-reset ]; then
		doas -C /etc/doas.conf.fcc-reset
		mv -f /etc/doas.conf.fcc-reset /etc/doas.conf
	else
		# It held nothing but that line, so install.sh made it.
		rm -f /etc/doas.conf.fcc-reset /etc/doas.conf
	fi
fi

if [ -f /etc/rc.local ]; then
	cp -p /etc/rc.local /etc/rc.local.fcc-reset
	grep -vxF "$BOOT" /etc/rc.local >/etc/rc.local.fcc-reset || [ "$?" -eq 1 ]
	if [ -s /etc/rc.local.fcc-reset ]; then
		mv -f /etc/rc.local.fcc-reset /etc/rc.local
	else
		rm -f /etc/rc.local.fcc-reset /etc/rc.local
	fi
fi

# A network change that was never confirmed is undone, while the helper that
# can do it is still here.
[ ! -x /usr/local/sbin/fcc-pfctl ] || /usr/local/sbin/fcc-pfctl boot || true

rm -f /usr/local/sbin/fcc-pfctl /usr/local/sbin/fcc-gate

install -o root -g wheel -m 0600 "$FACTORY" /etc/pf.conf.fcc-reset
pfctl -nf /etc/pf.conf.fcc-reset
# A rename within /etc, so /etc/pf.conf is always a complete file.
mv -f /etc/pf.conf.fcc-reset /etc/pf.conf
# States are left alone: flushing them would cut the connection running this.
pfctl -f /etc/pf.conf
rm -f /etc/pf.conf.fcc-previous /etc/pf.conf.fcc-new

if [ -f /etc/dhcpd.conf ]; then
	if rcctl check dhcpd >/dev/null 2>&1; then
		rcctl stop dhcpd >/dev/null
	fi
	rcctl disable dhcpd
fi
rm -f /etc/dhcpd.conf /etc/dhcpd.conf.fcc-previous /etc/dhcpd.conf.fcc-new

rm -rf /var/db/fcc /var/run/fcc

echo "Removed openbsd-gitops; PF is running the rules from $FACTORY"
pfctl -si | head -1
