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

## Tests

```sh
cd tui && PYTHONPATH=. python3 -m unittest discover -s tests
```

They cover the rule builders and drive the editor through a real terminal.
They need only Python 3.
