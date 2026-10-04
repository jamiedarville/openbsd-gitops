#!/bin/sh
# Prepares an OpenBSD firewall for openbsd-gitops. Run as root, from the folder
# holding fcc-pfctl and fcc-gate, with the deployment key's public half as the
# argument:
#
#   sh install.sh 'ssh-ed25519 AAAA... comment'
#
# Safe to run again, for example to install a newer fcc-pfctl; the argument can
# be left out then. It does not change any PF rules.
set -eu

RULE='permit nopass fccdeploy as root cmd /usr/local/sbin/fcc-pfctl'
GATE=/usr/local/sbin/fcc-gate
KEYS=/home/fccdeploy/.ssh/authorized_keys
# "restrict" stops the key being used for forwarding or a terminal, and
# "command" makes sshd run the gate whatever the connection asks for.
OPTIONS="restrict,command=\"$GATE\""
here=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run this as root, for example with doas" >&2; exit 1; }
[ -f "$here/fcc-pfctl" ] && [ -f "$here/fcc-gate" ] || { echo "fcc-pfctl and fcc-gate must be beside this script" >&2; exit 1; }

id fccdeploy >/dev/null 2>&1 || useradd -m -s /bin/ksh fccdeploy
install -d -o fccdeploy -g fccdeploy -m 0700 /home/fccdeploy/.ssh

# The gate goes in before any key names it.
install -o root -g wheel -m 0555 "$here/fcc-gate" "$GATE"
install -o root -g wheel -m 0555 "$here/fcc-pfctl" /usr/local/sbin/fcc-pfctl

if [ "$#" -ge 1 ]; then
	case "$1" in
	ssh-ed25519\ * | ssh-rsa\ * | ecdsa-sha2-*\ *) ;;
	*) echo "the argument must be an SSH public key" >&2; exit 1 ;;
	esac
	echo "$OPTIONS $1" >"$KEYS"
elif [ -f "$KEYS" ]; then
	# A key installed by an earlier version of this script could run any
	# command as fccdeploy. Confine it to the gate as well.
	sed "s|^restrict |$OPTIONS |" "$KEYS" >"$KEYS.new"
	mv -f "$KEYS.new" "$KEYS"
fi
if [ -f "$KEYS" ]; then
	chown fccdeploy:fccdeploy "$KEYS"
	chmod 600 "$KEYS"
fi

grep -qxF "$RULE" /etc/doas.conf 2>/dev/null || echo "$RULE" >>/etc/doas.conf
doas -C /etc/doas.conf

echo "Installed fcc-pfctl $(sha256 -q /usr/local/sbin/fcc-pfctl)"
pfctl -si | head -1
