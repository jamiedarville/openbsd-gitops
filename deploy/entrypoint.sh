#!/bin/sh
# Keeps the firewall in step with a Git branch.
#
# Every INTERVAL seconds: fetch the branch, and if it has a commit that has not
# been tried yet, deploy it. A commit that failed is not retried, so a bad
# change cannot lock the firewall out over and over; push a fix or a revert.
# A commit that succeeded is re-applied on every pass, which is a no-op unless
# someone changed the rules on the firewall by hand, whether the ones it is
# running or its /etc/pf.conf, in which case they are put back.
#
# The monitoring deployer (the monitoring-deployer service in compose.yaml)
# runs this same loop with PLAYBOOK pointing at its own playbook and
# RETRY_POLICY=always: nothing it does can lock anyone out of the firewall, so
# every failure is retried. Left unset, both keep the behaviour described above.
set -eu

: "${REPO_URL:?REPO_URL is not set}"
BRANCH=${BRANCH:-main}
INTERVAL=${INTERVAL:-60}
PLAYBOOK=${PLAYBOOK:-deploy/playbook.yml}
RETRY_POLICY=${RETRY_POLICY:-firewall}
case "$RETRY_POLICY" in
firewall | always) ;;
*)
	echo "RETRY_POLICY must be 'firewall' or 'always', not '$RETRY_POLICY'" >&2
	exit 64
	;;
esac
STATE=${STATE_DIR:-/state}
CHECKOUT=$STATE/checkout
export FW_WORK_DIR=$STATE
export ANSIBLE_LOCAL_TEMP=$STATE/.ansible/tmp
export ANSIBLE_NOCOLOR=1

# ssh refuses to run for a user ID that has no passwd entry, and the container
# runs as whichever user owns the key files. Give that ID a name without
# making /etc/passwd writable.
if ! id -un >/dev/null 2>&1; then
	echo "deployer:x:$(id -u):$(id -g):deployer:$STATE:/bin/sh" >"$STATE/passwd"
	export NSS_WRAPPER_PASSWD=$STATE/passwd NSS_WRAPPER_GROUP=/etc/group
	export LD_PRELOAD=libnss_wrapper.so
fi

log() {
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

# Writes a small status file that a later GUI, or a person, can read.
record() {
	cat >"$STATE/status.json.new" <<EOF
{"commit": "$1", "result": "$2", "at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "log": "last-deploy.log"}
EOF
	mv "$STATE/status.json.new" "$STATE/status.json"
}

# A key mounted here is used to clone a private repository over SSH. The Git
# server's host key is pinned, never accepted on sight: it comes from the file
# mounted beside the key, or from what an earlier version of this container
# recorded on first contact.
if [ -s /keys/git_key ]; then
	if [ -s /keys/git_known_hosts ]; then
		git_known_hosts=/keys/git_known_hosts
	elif [ -s "$STATE/git_known_hosts" ]; then
		git_known_hosts=$STATE/git_known_hosts
	else
		log "no host key is pinned for the Git server. Set GIT_KNOWN_HOSTS_FILE in .env; see the README."
		exit 78
	fi
	export GIT_SSH_COMMAND="ssh -i /keys/git_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$git_known_hosts -o GlobalKnownHostsFile=/dev/null"
fi
git config --global --add safe.directory '*'

if [ ! -d "$CHECKOUT/.git" ]; then
	log "cloning $REPO_URL"
	git clone --quiet --branch "$BRANCH" "$REPO_URL" "$CHECKOUT"
fi

log "watching $REPO_URL ($BRANCH) every $INTERVAL seconds"
while :; do
	if git -C "$CHECKOUT" fetch --quiet origin "$BRANCH"; then
		commit=$(git -C "$CHECKOUT" rev-parse --short "origin/$BRANCH")
		tried=$(cat "$STATE/tried" 2>/dev/null || echo "")
		failed=$(cat "$STATE/failed" 2>/dev/null || echo "")

		if [ "$commit" = "$failed" ]; then
			: # Waiting for a new commit.
		else
			[ "$commit" = "$tried" ] || log "deploying $commit: $(git -C "$CHECKOUT" log -1 --format=%s "origin/$BRANCH")"
			git -C "$CHECKOUT" reset --quiet --hard "origin/$BRANCH"
			# The firewall's playbook creates the first file just before it
			# loads rules, and the second if only the DHCP configuration fails.
			rm -f "$STATE/rules-were-loaded" "$STATE/dhcp-failed"
			if ansible-playbook -i localhost, "$CHECKOUT/$PLAYBOOK" >"$STATE/last-deploy.log" 2>&1; then
				if grep -q 'changed=[1-9]' "$STATE/last-deploy.log"; then
					log "deployed $commit"
				fi
				rm -f "$STATE/failed"
				record "$commit" ok
			elif [ "$RETRY_POLICY" = always ]; then
				[ "$commit" = "$tried" ] || {
					log "could not deploy $commit. Retrying every $INTERVAL seconds."
					grep -m1 -o -E '"msg": "[^"]+"|"stderr": "[^"{][^"]*"|^ERROR! .*' "$STATE/last-deploy.log" | head -n 2
				}
				record "$commit" retrying
			elif [ -f "$STATE/dhcp-failed" ]; then
				# The rules are live and saved; only the DHCP configuration is
				# not. Installing it cannot lock anyone out, so keep trying.
				[ "$commit" = "$tried" ] || {
					log "the rules of $commit are deployed, but its DHCP configuration could not be installed. Retrying every $INTERVAL seconds."
					sed -n '/Report the failed DHCP deployment/,$p' "$STATE/last-deploy.log" | grep -m1 '"msg"' || true
				}
				record "$commit" retrying
			elif [ -f "$STATE/rules-were-loaded" ]; then
				log "DEPLOYMENT OF $commit FAILED after its rules were loaded; it will not be retried. Push a fix or a revert."
				sed -n '/Report the failed deployment/,$p' "$STATE/last-deploy.log" | grep -m1 '"msg"' || true
				echo "$commit" >"$STATE/failed"
				record "$commit" failed
			else
				# Nothing was loaded: the firewall was unreachable or refused
				# the rules outright. Trying again is harmless.
				[ "$commit" = "$tried" ] || {
					log "could not deploy $commit; nothing on the firewall was changed. Retrying every $INTERVAL seconds."
					grep -m1 -o '"stderr": "[^"]*"' "$STATE/last-deploy.log" || true
				}
				record "$commit" retrying
			fi
			echo "$commit" >"$STATE/tried"
		fi
	else
		log "could not fetch $REPO_URL"
	fi
	sleep "$INTERVAL"
done
