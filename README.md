# openbsd-gitops

Firewall configuration for an OpenBSD firewall, kept as plain text in Git.

- **The files in this repository are the configuration.** Read them, edit them
  by hand, or use the `./fw` editor to build rules for you.
- **Every change is a commit.** Git is the history, the review, and the undo.
- **A small container deploys each new commit** to the firewall. If a change
  locks the deployment out, the firewall restores its previous rules by itself.

```
 you ── ./fw or a text editor ──> Git ──> deployer container ── SSH ──> OpenBSD firewall
```

## Layout

| Path                         | What it holds                                                                 |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `firewall/10-settings.conf`  | PF options, macros, and tables. Loaded first.                                  |
| `nat/20-nat.conf`            | NAT and port forwards.                                                         |
| `firewall/30-rules.conf`     | Filter rules.                                                                  |
| `dhcp/dhcpd.conf`            | DHCP server configuration. Ignored while it holds only comments.               |
| `firewall.json`              | Which firewall this repository is for.                                         |
| `deploy/`                    | The Ansible playbook and the container that runs it.                           |
| `target/fcc-pfctl`           | The helper installed on the firewall.                                          |
| `target/fcc-gate`            | The only command the deployment key may run on the firewall.                   |
| `tui/`                       | The `./fw` editor.                                                             |
| `setup`                      | Prepares a firewall and this machine in one step. See Setting it up.           |
| `monitoring.json`            | Which monitoring server this repository is for. See Monitoring.                |
| `monitoring/`                | The monitoring stack's files, and the script that prepares its server.         |
| `setup-monitoring`           | Prepares a monitoring server and this machine in one step.                     |
| `factory-reset`              | Takes all of this off a firewall or a monitoring server again. See Factory reset. |

On OpenBSD, NAT is part of `pf.conf`, not a separate service. Every `*.conf`
file in `firewall/` and `nat/` is joined in file-name order into one `pf.conf`,
which is why the names start with numbers. Add more files if you like, for
example `firewall/40-guests.conf`. `./fw assemble` prints the joined result.

## Changing the rules

```sh
./fw
```

| Menu entry                 | What it does                                                             |
| -------------------------- | ------------------------------------------------------------------------ |
| Firewall rules             | Create a rule with a guided form, or list, edit, reorder, and delete them. |
| NAT and port forwards      | The same, with a guide for outbound NAT and port forwards.                |
| DHCP                       | The same, with a guide for networks and fixed addresses.                  |
| Review changes             | Shows what you changed since the last commit.                             |
| Check rules on the firewall | Has the firewall's own `pfctl` parse the rules. Changes nothing.         |
| Save and deploy            | Commits your changes, and pushes them if you agree.                       |
| Status                     | Compares this folder with what the firewall is running.                   |

In a list: `a` adds a line with a guided form, `e` or Enter edits the line as
text, `d` deletes it, `u` and `n` move it up and down, Esc goes back. Order
matters in PF: the last matching rule wins unless a rule says `quick`.

The editor only ever writes one line at a time into these files. Anything it
cannot express, write by hand; it will leave your lines alone.

Without the menus:

```sh
./fw assemble   # print pf.conf exactly as it will be deployed
./fw check      # have the firewall parse the rules; changes nothing
./fw status     # compare this folder with the firewall
```

Undo a change with `git revert <commit>` and push.

## How a deployment works

For each new commit on the branch, the deployer:

1. joins the files into `pf.conf` and asks the firewall to parse it;
2. arms a watchdog on the firewall;
3. loads the rules into the running firewall only;
4. reconnects over SSH to prove the new rules still let it in;
5. saves the rules as `/etc/pf.conf` and disarms the watchdog.

If step 4 fails, or the deployer disappears, the watchdog reloads the previous
`/etc/pf.conf` when the grace period (`graceSeconds` in `firewall.json`) ends.
A reboot does the same.

A commit whose rules were loaded and then failed is **not retried**, so a bad
change cannot lock the firewall out repeatedly. Push a fix or a revert. A
commit that never got as far as loading rules, because the firewall was
unreachable or its `pfctl` rejected them, is retried on every pass, since
nothing was changed. A commit that succeeded is re-applied on every pass, which
puts back rules changed on the firewall by hand, whether in the running
firewall or in `/etc/pf.conf`. The firewall is asked what it is running; the
contents of tables and anchors are not compared.

If the rules deploy but the DHCP configuration cannot be installed, the rules
stay in place and the DHCP configuration is tried again on every pass.

## Setting it up

You need an account on the firewall that can log in over SSH and use `doas`.

### 1. GitHub

Skip this if the repository is already there.

```sh
gh repo create openbsd-gitops --private --source . --push
```

### 2. The firewall and this machine

```sh
./setup admin@firewall.example.net
```

Name the firewall the way you would to `ssh`: an address, a name, or a `Host`
from your `ssh_config`. `-p` gives a port. Everything on the firewall happens
over one connection as that account, so `ssh` asks for a password at most once,
and so does `doas`. The script:

1. creates the deployment key, `~/fcc-runner/id_ed25519`, unless it exists;
2. copies `target/` to the firewall and runs `install.sh` there as root;
3. reads the firewall's SSH host key over that connection and pins it in
   `~/fcc-runner/known_hosts`;
4. writes the firewall's address into `firewall.json`, and writes
   `.fw-local.json` and `.env`, which are not committed;
5. runs `./fw status` with the deployment key, to prove the key works.

It does not change any PF rules and does not start the deployer. Run it again
to install a newer `target/` on a firewall that is already set up. Set
`FW_KEY_DIR` to keep the keys somewhere other than `~/fcc-runner`.

That connection is checked against your own `known_hosts`, like any other. If
you have never connected to the firewall, `ssh` shows its fingerprint and asks;
compare it with the one shown on the firewall's console by
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.

`install.sh` creates the `fccdeploy` account, installs the helper as
`/usr/local/sbin/fcc-pfctl`, and adds one line to `/etc/doas.conf` that lets
that account run that one command as root. It installs
`/usr/local/sbin/fcc-gate` and ties the key to it, so the key can do nothing
but call the helper.

The deployer reads the firewall's address from `firewall.json`, so commit that
file and push it.

### 3. A private repository

Skip this if the repository is public. Give the deployer a read-only deploy
key:

```sh
ssh-keygen -t ed25519 -N '' -C openbsd-gitops-deployer -f ~/.ssh/openbsd-gitops-deploy-key
gh repo deploy-key add ~/.ssh/openbsd-gitops-deploy-key.pub --title deployer
```

The deployer only clones over SSH from a server whose host key it was given.
Fetch GitHub's, over HTTPS:

```sh
gh api meta --jq '.ssh_keys[] | "github.com " + .' > ~/fcc-runner/git_known_hosts
```

In `.env`, `REPO_URL` must be the SSH address, `git@github.com:NAME/REPO.git`,
and the two `GIT_` lines must not start with `#`.

### 4. The deployer

`./setup` wrote `.env`; `.env.example` explains each line. The first deployment
replaces the rules the firewall has now with the ones in this repository, so
read `./fw assemble` first. Then:

```sh
docker compose up -d --build
docker compose logs -f deployer
```

It needs to reach GitHub and the firewall. Nothing needs to reach it.

What it last did is in its state volume:

```sh
docker compose exec deployer cat /state/status.json
docker compose exec deployer cat /state/last-deploy.log
```

### Without `./setup`

Step 2 by hand. Create the deployment key:

```sh
mkdir -p -m 700 ~/fcc-runner
ssh-keygen -t ed25519 -N '' -C openbsd-gitops-deploy -f ~/fcc-runner/id_ed25519
```

Copy `target/fcc-pfctl`, `target/fcc-gate` and `target/install.sh` to the
firewall, then as root, with the public half of that key as the argument:

```sh
sh install.sh 'ssh-ed25519 AAAA... openbsd-gitops-deploy'
```

To update a firewall that is already set up, copy the three files again and
run `sh install.sh` without an argument. That installs the newer helper and
ties a key installed by an earlier version to the gate.

Put the firewall's address in `firewall.json`, and create `.fw-local.json` for
the editor's Check and Status:

```json
{
  "identity": "~/fcc-runner/id_ed25519",
  "knownHosts": "~/fcc-runner/known_hosts"
}
```

`knownHosts` is a file holding the firewall's SSH host key. Create it with
`ssh-keyscan -t ed25519 FIREWALL > known_hosts` and compare the fingerprint
(`ssh-keygen -lf known_hosts`) with the one shown on the firewall's console by
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.

Then copy `.env.example` to `.env` and fill it in.

## Recovering by hand

`/etc/pf.conf` on the firewall always holds the last rules that were confirmed
working. At the firewall's console:

```sh
doas pfctl -f /etc/pf.conf                 # reload the confirmed rules
doas /usr/local/sbin/fcc-pfctl status      # is a rollback still pending?
doas cp /etc/pf.conf.fcc-previous /etc/pf.conf && doas pfctl -f /etc/pf.conf   # go back one deployment
```

## Factory reset

To take everything this repository put on a server off it again:

```sh
./factory-reset firewall admin@firewall.example.net
./factory-reset monitoring admin@monitor.example.net
```

Name the server the way you would to `ssh`; `-p` gives a port. It needs the
same account as `./setup` or `./setup-monitoring`, because the deployment keys
cannot do any of this. It lists what it is about to do and asks you to type
`reset`; `-y` answers for you. It stops that server's deployer on this machine
first, and leaves the keys, `.env` and the repository alone, so running
`./setup` or `./setup-monitoring` again puts everything back.

On the firewall, `target/reset.sh`:

- removes the `fccdeploy` account with its key, `fcc-pfctl`, `fcc-gate`, the
  line in `/etc/doas.conf`, and what the helper kept in `/var/db/fcc`;
- replaces `/etc/pf.conf` with the rules OpenBSD is installed with,
  `/etc/examples/pf.conf`, and loads them;
- removes `/etc/dhcpd.conf`, and stops and disables `dhcpd`.

**The rules OpenBSD is installed with pass everything and do no NAT.** Networks
behind the firewall lose their way out, and the firewall filters nothing, until
you load rules of your own. Connections that are already open stay open.
`/etc/dhcpd.conf` is removed even if you wrote it by hand and never deployed
one from here.

On the monitoring server, `monitoring/reset.sh`:

- removes the `fccmon` account with its key and its `sudo` rule;
- removes the stack's containers, images and data, and `/opt/monitoring`;
- removes the host firewall and puts back the `/etc/nftables.conf` Ubuntu
  installs, leaving the server with no host firewall;
- removes `/etc/docker/daemon.json` and restarts Docker.

Docker itself stays, unless you add `-d`, which removes it with **every**
container, image and volume on the server, not only the stack's. The packages
`nftables`, `unattended-upgrades`, `python3` and `sudo` stay either way.

Both scripts can be copied to the server and run there as root instead, for
example at the firewall's console: `sh reset.sh`. Both are safe to run again.

Neither has been run on a real server. Each was run in an Ubuntu 24.04
container: `monitoring/reset.sh` after `install.sh`, with stand-ins for
`systemctl` and `nft` and without Docker, and `target/reset.sh` with stand-ins
for `uname`, `pfctl`, `rcctl` and `doas`. `./factory-reset` itself has not been
run against a server at all.

## What the helper allows

The deployment account can run exactly one command as root, `fcc-pfctl`, with
these operations: `status`, `validate`, `backup`, `arm <seconds>`, `apply`,
`commit`, `rollback`, and `dhcpd-apply`. Every path in it is fixed, and rules
are refused unless the watchdog is armed.

The deployment key is tied to `fcc-gate`, which runs
`doas /usr/local/sbin/fcc-pfctl` with one of those operations and refuses
everything else. The key cannot run a shell or any other command, as root or
as `fccdeploy`.

The deployer runs the playbook from the repository it clones, so whoever can
push to the branch decides what the deployer does with the deployment key.
Protect the branch accordingly.

The PF operations were proven on OpenBSD 7.9, including recovery from a
deliberate lockout. `dhcpd-apply` has not been run on OpenBSD yet. Neither have
`fcc-gate`, the check of the running rules in `status`, or the watchdog taking
over a stuck lock: those were only run against stand-ins for `pfctl` and
`doas` on Linux. `./setup` has not been run against OpenBSD either: it was
run against a Linux container with OpenSSH's `sshd` and the portable `doas`,
and stand-ins for `pfctl`, `sha256`, `uname` and `useradd`.

## Monitoring

Optional. A second deployer keeps a Linux server running Prometheus and
Grafana, from this same repository and in the same way: the files are the
configuration, and every change is a commit.

So far the stack watches the monitoring server itself, with Prometheus, Grafana
and node_exporter. It does not scrape the firewall yet.

| Path                    | What it holds                                                        |
| ----------------------- | -------------------------------------------------------------------- |
| `monitoring.json`       | The server, how many days of data to keep, and each program's version. |
| `monitoring/stack/`     | The stack: its compose file, the Prometheus configuration, and Grafana's data sources and dashboards. |
| `monitoring/install.sh` | The script that prepares the server for the deployer.                |
| `deploy/monitoring.yml` | The playbook, with its roles in `deploy/roles/`.                     |

### Setting it up

You need a server running Ubuntu 24.04, and an account on it that can log in
over SSH and use `sudo`. Set up the firewall first; this adds to its `.env`.

```sh
./setup-monitoring admin@monitor.example.net
```

Name the server the way you would to `ssh`; `-p` gives a port. Over one
connection as that account, the script:

1. creates the monitoring key, `~/fcc-runner/monitoring_ed25519`, unless it
   exists;
2. runs `monitoring/install.sh` on the server as root, which creates the
   `fccmon` account, installs the key for it, and lets it use `sudo` without a
   password;
3. reads the server's SSH host key over that connection and pins it in
   `~/fcc-runner/monitoring_known_hosts`;
4. writes the server's address into `monitoring.json`, adds three lines to
   `.env`, and writes `~/fcc-runner/monitoring-secrets.yml` with a new password
   for Grafana, unless that file exists;
5. logs in with the monitoring key and becomes root, to prove the key works.

The key is accepted from one address only: this machine's, as the server sees
it. If that address can change, name a network with `-a`, for example
`-a 192.168.1.0/24`. Run the script again to change it.

Commit `monitoring.json` and push it. Then start its deployer beside the
firewall's:

```sh
docker compose --profile monitoring up -d --build
docker compose logs -f monitoring-deployer
```

On the server, the deployer:

- installs `nftables` and `unattended-upgrades`, and a host firewall that lets
  in SSH and ping and nothing else, replacing `/etc/nftables.conf`;
- installs Docker from Docker's own package repository, replacing
  `/etc/docker/daemon.json`;
- puts the stack in `/opt/monitoring` and starts it.

Everything in the stack listens on `127.0.0.1` only. Reach Grafana through an
SSH tunnel, as `admin` with the password from `monitoring-secrets.yml`:

```sh
ssh -L 3000:127.0.0.1:3000 admin@monitor.example.net
```

and open `http://127.0.0.1:3000`. Grafana reads that password only when it
first starts; after that, change it in Grafana.

### Changing it

Edit `monitoring.json` or the files in `monitoring/stack/`, commit, and push.
The deployer looks for a new commit every `MON_INTERVAL` seconds (300 unless
`.env` says otherwise), and on every pass puts back what was changed on the
server by hand.

- A file is checked by the program that will read it before it replaces the
  one in use, so a commit with a broken Prometheus configuration leaves the
  running one alone.
- A deployment that fails is tried again on every pass, unlike a firewall
  deployment: nothing here can lock anyone out of the firewall.
- The versions in `monitoring.json` are exact, so an upgrade is a commit.
- Dashboards cannot be changed in Grafana. Edit the file in
  `monitoring/stack/grafana/dashboards/`; a file removed there is removed from
  Grafana.

Undo a change with `git revert <commit>` and push.

### What the monitoring key allows

Unlike the firewall's key, the monitoring key is not confined to one command:
`fccmon` can become root on the monitoring server, because the deployer
installs packages and runs Docker there. It is accepted from one address, and
whoever can push to the branch decides what runs as root on that server.
Protect the branch accordingly.

The monitoring deployer is never given the firewall's key, and the monitoring
server has no access to the firewall.

All of this was run against a container standing in for an Ubuntu 24.04 server,
with systemd, `sshd`, `sudo` and Docker inside it. It has not been run against
a real server yet.

## Tests

```sh
cd tui && PYTHONPATH=. python3 -m unittest discover -s tests
```

They cover the rule builders and drive the editor through a real terminal.
They need only Python 3.
