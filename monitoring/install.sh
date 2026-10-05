#!/bin/sh
# Prepares a Linux server for the monitoring deployer. Run as root, with the
# monitoring key's public half and the address that key may be used from:
#
#   sh install.sh 'ssh-ed25519 AAAA... comment' 192.0.2.5
#
# It creates the fccmon account, installs the key for it, and lets that account
# become root without a password: the deployer installs packages and runs
# Docker there, which amounts to root anyway. Safe to run again.
set -eu

KEYS=/home/fccmon/.ssh/authorized_keys

[ "$(id -u)" -eq 0 ] || { echo "run this as root, for example with sudo" >&2; exit 1; }
[ "$#" -eq 2 ] || { echo "usage: sh install.sh 'public key' address" >&2; exit 64; }
case "$1" in
ssh-ed25519\ * | ssh-rsa\ * | ecdsa-sha2-*\ *) ;;
*) echo "the first argument must be an SSH public key" >&2; exit 1 ;;
esac
# What from= in authorized_keys takes: addresses, networks and patterns.
case "$2" in
'' | *[!0-9A-Fa-f.:/,*?!]*) echo "the second argument must be an address, a network or a pattern" >&2; exit 1 ;;
esac

# Ansible runs on the server's own Python, and becomes root with sudo.
if ! command -v python3 >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
	apt-get update -q
	apt-get install -y -q python3 sudo
fi

id fccmon >/dev/null 2>&1 || useradd -m -s /bin/sh fccmon
install -d -o fccmon -g fccmon -m 0700 /home/fccmon/.ssh
# "restrict" leaves the key nothing but running commands, and "pty" gives back
# the terminal that Ansible asks for.
echo "from=\"$2\",restrict,pty $1" >"$KEYS"
chown fccmon:fccmon "$KEYS"
chmod 600 "$KEYS"

# sudo ignores a file with a dot in its name, so the rule only takes effect
# once it has been checked.
echo 'fccmon ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/fccmon.new
chmod 440 /etc/sudoers.d/fccmon.new
visudo -cqf /etc/sudoers.d/fccmon.new
mv -f /etc/sudoers.d/fccmon.new /etc/sudoers.d/fccmon

echo "Installed the monitoring key for fccmon, usable from $2"
