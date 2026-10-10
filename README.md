# openbsd-gitops

Configuration for an OpenBSD firewall and router, kept as plain text in Git:
its PF rules, NAT, interfaces and VLANs, routing, DHCP, and DNS resolver.

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
| `network/`                   | Interfaces, VLANs, routing and the default route. See Networks.                |
| `dhcp/dhcpd.conf`            | DHCP server configuration. Ignored while it holds only comments.               |
| `dns/unbound.conf`           | DNS resolver configuration. Ignored while it holds only comments. See DNS.     |
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
| `test/`                      | OpenBSD test machines and the test that deploys to them. See Tests.            |

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
| Networks: VLANs and routing | Add a VLAN with a guided form, switch routing on or off, edit an interface. |
| Firewall rules             | Create a rule with a guided form, or list, edit, reorder, and delete them. |
| NAT and port forwards      | The same, with a guide for outbound NAT and port forwards.                |
| DHCP                       | The same, with a guide for networks and fixed addresses.                  |
| Settings: macros and tables | The same, with a guide for macros and tables.                            |
| Review changes             | Shows what you changed since the last commit.                             |
| Check on the firewall      | Has the firewall check the rules and the network files. Changes nothing.  |
| Save and deploy            | Commits your changes, and pushes them if you agree.                       |
| Status                     | Compares this folder with what the firewall is running.                   |

In a list: `a` adds a line with a guided form, `e` or Enter edits the line as
text, `d` deletes it, `u` and `n` move it up and down, Esc goes back. Order
matters in PF: the last matching rule wins unless a rule says `quick`.

The editor only ever writes one line at a time into these files. Anything it
cannot express, write by hand; it will leave your lines alone.

Without the menus:

```sh
./fw assemble           # print pf.conf exactly as it will be deployed
./fw assemble-network   # print the network files exactly as they will be sent
./fw check              # have the firewall check both; changes nothing
./fw status             # compare this folder with the firewall
./fw import-opnsense config.xml   # write these files from an OPNsense backup
```

Undo a change with `git revert <commit>` and push.

## Networks

The files in `network/` are installed in `/etc` on the firewall under the same
names, and are the files OpenBSD itself uses:

| File                      | What it holds                                                    |
| ------------------------- | ---------------------------------------------------------------- |
| `network/hostname.em1`    | One interface, as in `hostname.if(5)`. One file per interface.   |
| `network/hostname.vlan10` | A VLAN. The firewall creates it, and removes it with its file.   |
| `network/sysctl.conf`     | Routing on or off. Ignored while it holds only comments.         |
| `network/mygate`          | A fixed default route, as one IPv4 address. Leave it out when the outside port gets its address by DHCP. |

A VLAN with number 10 on the port `em1` is two files:

```
# network/hostname.em1
up

# network/hostname.vlan10
parent em1 vnetid 10
inet 192.168.10.1 255.255.255.0
up
```

**Add a VLAN** in `./fw` writes these for you. If you ask it to, it also adds
the DHCP network, the outbound NAT rule, the rule that lets the network out,
and switches routing on. A new network can reach nothing, and nothing can
reach it, until a rule in `firewall/30-rules.conf` says so.

In rules, write a network's addresses as `(vlan10:network)`, in brackets. PF
then looks them up as it goes, so the rule can be checked before the VLAN
exists and follows it when it is renumbered.

What the firewall accepts is deliberately narrow, because OpenBSD runs every
line of an interface file through the shell:

- outside comments, an interface file may hold only letters, digits, spaces
  and `. _ : / -`. A line starting with `!`, which OpenBSD would run as a
  command, is refused;
- the interface must be a VLAN or a port the firewall already has. `lo`, `enc`,
  `pflog` and `pfsync` are refused;
- `sysctl.conf` may set only `net.inet.ip.forwarding` and
  `net.inet6.ip6.forwarding`. A `/etc/sysctl.conf` written by hand that holds
  anything else is not taken over; the deployment stops and says so;
- only the files it installed are ever removed. An interface file that was on
  the firewall before, such as the outside port's, stays until this folder
  holds one of the same name.

Not handled yet: IPv6 addresses in `mygate`, interfaces other than ports and
VLANs, and addresses added to a port as aliases, which stay until a restart
when the file stops naming them.

## DNS

`dns/unbound.conf` is the configuration of Unbound, the resolver OpenBSD comes
with, and is installed as `/var/unbound/etc/unbound.conf`. With a server in
it, `unbound` is switched on and started, and started afresh whenever the file
or the network files change. Emptying the file again stops `unbound`, switches
it off, and puts back the configuration OpenBSD came with.

```
server:
	interface: 127.0.0.1
	interface: 192.168.10.1
	access-control: 192.168.10.0/24 allow
	local-data: "printer.home.arpa. IN A 192.168.10.50"
	local-data-ptr: "192.168.10.50 printer.home.arpa."

forward-zone:
	name: "corp.example."
	forward-addr: 192.168.10.53
```

Three things have to agree for a network to use it: an `interface:` line with
the firewall's address on that network, a rule that lets the network reach
port 53 there, and `option domain-name-servers` with that address in
`dhcp/dhcpd.conf`.

`unbound.conf` can also name files to read and write, the account to run as,
and code to load, so the firewall accepts only what a resolver needs:

- the sections `server:`, `forward-zone:` and `stub-zone:`;
- the settings `interface`, `access-control`, `do-ip4`, `do-ip6`,
  `hide-identity`, `hide-version`, `prefetch`, `qname-minimisation`,
  `cache-min-ttl`, `cache-max-ttl`, `private-address`, `private-domain`,
  `domain-insecure`, `local-zone`, `local-data`, `local-data-ptr`, `name`,
  `forward-addr`, `forward-first`, `forward-tls-upstream` and `stub-addr`, with
  values made of letters, digits, spaces and `. _ : / @ # " * -`;
- `auto-trust-anchor-file: "/var/unbound/db/root.key"`, which switches DNSSEC
  on, and `tls-cert-bundle: "/etc/ssl/cert.pem"`, for forwarding over TLS.
  Neither may name another file.

`./fw check` and `./fw status` do not look at the resolver or at DHCP; the
deployment says so if the firewall turns either down.

## Importing from OPNsense

```sh
./fw import-opnsense -n config.xml    # say what would be written
./fw import-opnsense config.xml       # write it
```

`config.xml` is the backup OPNsense offers under System, Configuration,
Backups, downloaded without a password. It also holds password hashes and
keys: keep it out of this repository. The import copies none of them.

Nothing is deployed by importing. It writes files in this folder and prints a
report; read both, then commit as for any other change.

| From OPNsense | Written as |
| --- | --- |
| Interfaces, VLANs, virtual addresses of the kind "IP alias", MTU and MAC address | `network/hostname.<interface>`, one each; a VLAN with number 10 is `vlan10` |
| A fixed default gateway | `network/mygate` |
| Aliases | `firewall/15-opnsense-aliases.conf`: an address alias is a table, `<name>`; a port alias is a macro, `$name` |
| Port forwards, one-to-one NAT, outbound NAT, automatic or written by hand | `nat/25-opnsense.conf` |
| Firewall rules, floating, of interface groups and of interfaces, in both of OPNsense's formats | `firewall/40-opnsense.conf` |
| The DHCP server, whether ISC, Kea or dnsmasq: networks, ranges, options and fixed addresses | a marked part of `dhcp/dhcpd.conf` |
| Unbound's host overrides and their aliases, domain overrides, forwarding, DNS over TLS, access lists and DNSSEC; or dnsmasq's host and domain overrides | `dns/unbound.conf` |

Routing is switched on in `network/sysctl.conf`.

**Port names.** OPNsense runs on FreeBSD, which names some ports differently:
its `igb0` is OpenBSD's `em0`, its `vtnet0` is `vio0`. The import translates
the driver and keeps the number, and the report lists every name it chose.
That is a guess. Compare it with `ifconfig` on the OpenBSD machine, and say
otherwise where it is wrong:

```sh
./fw import-opnsense --map igb0=em2 --map igb1=em3 config.xml
```

**How the rules are carried over.** OPNsense tries a packet against floating
rules, then the rules of interface groups, then the interface's own, and stops
at the first that matches. The imported rules are in that order and say
`quick`, which makes PF stop in the same way; a floating rule that was not
marked quick is written without. What no rule passes is dropped by the `block
all` in `firewall/30-rules.conf`. `lan net` becomes `(em1:network)`, `lan
address` becomes `(em1)`, and "This Firewall" becomes `(self)`. A rule that was
switched off is written as a comment. A port forward becomes a `match` rule
that only redirects, and the filter rule OPNsense kept beside it is what lets
the connection in.

Three things OPNsense does without being asked are written out: the
anti-lockout rule, as SSH to the firewall from LAN; "block private networks"
on an interface; and automatic outbound NAT, as one rule for each inside
network.

**What is left out is in the report.** A rule or a setting that cannot be
written to mean the same is never written to mean something else: it is left
out, named in the report, and, for a rule, left in the file as a comment
starting `# NOT IMPORTED`. A block rule that is left out is marked as such,
because without it more gets through than did before. Not imported at all:
IPv6 addresses, PPPoE, link aggregation and bridges, VPNs, static routes,
gateway groups, CARP, schedules, traffic shaping, blocklists and aliases that
OPNsense fills from a download (their tables are created empty), names in an
address alias, NAT reflection, and the newer formats of NAT rules.

**Files you wrote are left alone.** The import's files start with a line
saying so, and importing again replaces those and removes the ones no longer
wanted. A file it would write that exists already and was not written by an
import stops it; `--force` replaces such files. `firewall/30-rules.conf` is
never touched. As this repository ships it, it lets SSH and ping in from
anywhere, which OPNsense did not: narrow those once the deployment works.

**The first deployment of an import replaces the firewall's addresses**,
including that of the port the deployment arrives on. If the firewall can no
longer be reached afterwards, it puts back what it had, as for any other
change.

The sample backup `tui/tests/opnsense-config.xml` is imported and deployed to
OpenBSD 7.9 by `test/run`, which checks its DHCP, its rules and its resolver
from a client. The older formats of aliases and of Unbound's settings, Kea and
the newer rule format are covered by the unit tests only, which compare the
lines written; dnsmasq's DHCP, one-to-one NAT and policy routing have not been
run against OPNsense backups from a real installation at all.

## How a deployment works

For each new commit on the branch, the deployer:

1. joins the files into `pf.conf` and asks the firewall to parse it;
2. arms a watchdog on the firewall;
3. if the network files changed, installs them and brings the network up;
4. loads the rules into the running firewall only;
5. reconnects over SSH to prove the firewall still lets it in;
6. saves the rules as `/etc/pf.conf`, keeps the network files, and disarms the
   watchdog.

If step 5 fails, or the deployer disappears, the watchdog reloads the previous
`/etc/pf.conf` and puts the previous network files back when the grace period
(`graceSeconds` in `firewall.json`) ends. A reboot does the same: the rules
were never saved, and a line in `/etc/rc.local` undoes a network change that
was never confirmed. After such a restart the firewall comes up on the new
addresses for a moment before it switches back.

When the network files change, the rules are checked after the network is up
and not before, since they may name an interface that is only then there.

A commit whose rules or network files were tried and then failed is **not
retried**, so a bad change cannot lock the firewall out repeatedly. Push a fix or a revert. A
commit that never got as far as loading rules, because the firewall was
unreachable or its `pfctl` rejected them, is retried on every pass, since
nothing was changed. A commit that succeeded is re-applied on every pass, which
puts back rules changed on the firewall by hand, whether in the running
firewall or in `/etc/pf.conf`, and network files changed in `/etc`. The
firewall is asked what it is running; the contents of tables and anchors are
not compared, and neither are addresses set by hand with `ifconfig`.

A DHCP configuration in `dhcp/dhcpd.conf` switches `dhcpd` on and starts it;
it is started afresh whenever the network files change, because it only listens
on the interfaces it found when it started. Emptying the file again stops
`dhcpd`, switches it off and removes `/etc/dhcpd.conf`, but only if that file
came from here. If the rules deploy but the DHCP configuration cannot be
installed, the rules stay in place and the DHCP configuration is tried again
on every pass. The resolver in `dns/unbound.conf` is handled in the same way,
after DHCP; see DNS.

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
that account run that one command as root, and one to `/etc/rc.local` that
runs the helper at every start. It installs
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
  lines in `/etc/doas.conf` and `/etc/rc.local`, and what the helper kept in
  `/var/db/fcc`;
- replaces `/etc/pf.conf` with the rules OpenBSD is installed with,
  `/etc/examples/pf.conf`, and loads them;
- removes `/etc/dhcpd.conf`, and stops and disables `dhcpd`;
- if a resolver was deployed from here, stops and disables `unbound` and puts
  back the `unbound.conf` OpenBSD came with;
- leaves the network as it is. The interface files, `/etc/sysctl.conf` and
  `/etc/mygate` stay, because taking them away could leave the machine with no
  address to reach it on.

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

`./factory-reset firewall` and `target/reset.sh` are run against OpenBSD 7.9
by `test/run`. `monitoring/reset.sh` has not been run on a real server: it was
run in an Ubuntu 24.04 container after `install.sh`, with stand-ins for
`systemctl` and `nft` and without Docker, and `./factory-reset monitoring` has
not been run against a server at all.

## What the helper allows

The deployment account can run exactly one command as root, `fcc-pfctl`, with
these operations: `status`, `validate`, `backup`, `arm <seconds>`, `apply`,
`commit`, `rollback`, `net-validate`, `net-apply`, `dhcpd-apply`,
`dhcpd-remove`, `unbound-apply`, and `unbound-remove`. Rules and network files are refused unless the watchdog is
armed. Every path in it is fixed, except that network files are installed as
`/etc/hostname.<interface>`, `/etc/sysctl.conf` and `/etc/mygate`, within the
limits listed under Networks.

The deployment key is tied to `fcc-gate`, which runs
`doas /usr/local/sbin/fcc-pfctl` with one of those operations and refuses
everything else. The key cannot run a shell or any other command, as root or
as `fccdeploy`.

The deployer runs the playbook from the repository it clones, so whoever can
push to the branch decides what the deployer does with the deployment key.
Protect the branch accordingly.

All of this is run against OpenBSD 7.9 by `test/run`: `./setup`, `fcc-gate`,
the rules, the network files, DHCP, the resolver, recovery from a deliberate lockout, and
recovery from losing power between trying a change and keeping it. One thing
is not: the watchdog taking over a stuck lock, which was only run against
stand-ins for `pfctl` and `doas` on Linux.

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

The deployment itself is tested against real OpenBSD, in two virtual machines
on this computer: a firewall, and a client on a trunk behind it.

```sh
test/vm build   # once: installs OpenBSD 7.9 under QEMU and keeps a clean copy
test/run        # under ten minutes
```

`test/run` puts both machines back to the clean install, sets the firewall up
with `./setup`, and deploys to it the way the deployer does. It then checks
that a client gets an address by DHCP on two VLANs, reaches the internet
through NAT, and cannot cross from one VLAN to the other; that an imported
OPNsense backup deploys and behaves as its rules say; that the helper turns
down network files that could run commands and resolver settings that could
reach other files; and that the firewall
recovers from a VLAN that cannot come up, from its management port being taken
down, and from losing power halfway through a change.

It needs QEMU with KVM, `socat` and `ansible-playbook`, and no root. Nothing
listens beyond `127.0.0.1`. `test/vm` alone lists its commands, among them
`test/vm ssh firewall` and `test/vm console firewall`. The machines, their
keys and their passwords are kept in `~/fcc-vm`. The installer's image is
checked against the SHA256 published beside it, not against its signature.
