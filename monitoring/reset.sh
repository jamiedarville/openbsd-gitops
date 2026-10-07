#!/bin/sh
# Takes the monitoring deployer and all it installed off a Linux server: the
# opposite of install.sh, and of every deployment since. Run as root:
#
#   sh reset.sh [-d]
#
# It removes the fccmon account with its key and its sudo rule, the monitoring
# stack with its data and /opt/monitoring, the host firewall, and the Docker
# daemon's configuration. With -d it removes Docker as well, and with it
# every container, image and volume on the server, not only the stack's.
#
# The packages nftables, unattended-upgrades, python3 and sudo stay.
#
# Safe to run again.
set -eu

STACK=/opt/monitoring
PROJECT=com.docker.compose.project=monitoring

docker_too=0
while getopts d option; do
	case "$option" in
	d) docker_too=1 ;;
	*) echo "usage: sh reset.sh [-d]" >&2; exit 64 ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "run this as root, for example with sudo" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "this is not Linux" >&2; exit 1; }

# The account goes first, so that a deployer still running cannot put back
# what is removed below.
rm -f /etc/sudoers.d/fccmon /etc/sudoers.d/fccmon.new
if id fccmon >/dev/null 2>&1; then
	pkill -KILL -u fccmon || true
	# Forced, because userdel may still see the processes killed above.
	userdel -f -r fccmon 2>/dev/null
fi

# By the label compose gives everything in the project, so the stack goes even
# if its compose file already has.
if docker info >/dev/null 2>&1; then
	containers=$(docker ps -aq --filter "label=$PROJECT")
	if [ -n "$containers" ]; then
		# shellcheck disable=SC2086
		images=$(docker inspect -f '{{.Image}}' $containers | sort -u)
		# shellcheck disable=SC2086
		docker rm -f $containers >/dev/null
		# An image that something else on the server uses stays.
		# shellcheck disable=SC2086
		docker rmi $images >/dev/null 2>&1 || true
	fi
	volumes=$(docker volume ls -q --filter "label=$PROJECT")
	# shellcheck disable=SC2086
	[ -z "$volumes" ] || docker volume rm $volumes >/dev/null
elif [ "$docker_too" -eq 0 ] && command -v docker >/dev/null 2>&1; then
	echo "Docker is not running, so the stack's containers and data were left. Start Docker and run this again." >&2
fi
rm -rf "$STACK"

if [ "$docker_too" -eq 1 ]; then
	packages=$(dpkg-query -W -f '${Package}\n' docker-ce docker-ce-cli containerd.io \
		docker-compose-plugin docker-buildx-plugin docker-ce-rootless-extras 2>/dev/null || true)
	# shellcheck disable=SC2086
	[ -z "$packages" ] || DEBIAN_FRONTEND=noninteractive apt-get purge -y -q $packages
	rm -rf /var/lib/docker /var/lib/containerd /etc/docker
	rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
elif [ -f /etc/docker/daemon.json ]; then
	rm -f /etc/docker/daemon.json
	! systemctl is-active --quiet docker || systemctl restart docker
fi

if command -v nft >/dev/null 2>&1 && nft list table inet fcc_host >/dev/null 2>&1; then
	nft delete table inet fcc_host
fi
# Only a file the deployer wrote is replaced, by the one Ubuntu installs.
if grep -q 'written by openbsd-gitops' /etc/nftables.conf 2>/dev/null; then
	cat >/etc/nftables.conf.new <<'NFT'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter;
	}
	chain forward {
		type filter hook forward priority filter;
	}
	chain output {
		type filter hook output priority filter;
	}
}
NFT
	chmod 755 /etc/nftables.conf.new
	mv -f /etc/nftables.conf.new /etc/nftables.conf
	# Disabled, as Ubuntu installs it, but not stopped: stopping it flushes
	# every rule, including the ones of a Docker that is still here.
	systemctl disable --quiet nftables
fi

echo "Removed openbsd-gitops from this server"
if [ "$docker_too" -eq 1 ]; then
	echo "Restart the server to clear the network rules and interfaces Docker left behind."
fi
