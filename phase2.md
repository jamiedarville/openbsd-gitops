# Phase 2: from a rule deployer to a working router

Phase 1 deploys `pf.conf` safely and can install a `dhcpd.conf`. That is not
yet enough to run a network: nothing in this repository can bring up an
interface, create a VLAN, or switch on routing. This plan lists what is missing
and the order to build it in.

## Where this stands

| Milestone | State |
| --- | --- |
| 0. A real OpenBSD to test against | Done: `test/vm` and `test/run`. |
| 1. Interfaces, VLANs and routing | Done, and proven by `test/run`. |
| 2. NAT and a rule set that routes | Partly. See below. |
| 3. DHCP that can be switched on and off | Done, and proven by `test/run`. |
| 4. DNS for clients | Partly: `dns/unbound.conf` is deployed and proven by `test/run`. The DHCP form does not offer "this firewall" yet, and no default rule opens port 53. |
| 5. Seeing what the firewall does | Not started. |

The MVP below works end to end on OpenBSD 7.9: `test/run` deploys two VLANs
with DHCP and NAT, and a client behind the firewall gets an address, reaches
the internet, and cannot cross between the VLANs.

Milestone 2, what is there: the "Add a VLAN" form writes the NAT rule and the
rule that lets the network out; macros and tables have a list and a form; the
forms accept `$macro` and `(vlan10:network)`. What is not: the forms do not
offer the macros and interfaces that exist, they only accept them; `antispoof`
and SSH from `<admins>` only are commented examples, not the shipped default.

How it was built differs from the plan below in these ways:

- Rules are loaded again whenever the network files change, even if the rules
  did not, so that addresses taken from an interface are worked out afresh.
- With a network change, the rules are checked after the network is up, not
  before. Rules written with `(vlan10:network)` can be checked beforehand.
- `sysctl.conf` and `mygate` are optional, and `mygate` takes IPv4 only.
- A `/etc/sysctl.conf` written by hand with other settings is not taken over.
- The restore also brings back up a port that the change took down. Without
  that, the watchdog restored the files and the firewall stayed unreachable.
- There is no "Networks" comparison of single files in `./fw status`: it says
  whether the network files as a whole are the same.

The four decisions at the end were taken as recommended. The last one, having
`dhcpd-apply` switch the service on, reverses what the helper did before and
was not confirmed first; say so if it should go back.

## What the MVP is

A freshly installed OpenBSD machine with two network ports becomes, from this
repository alone, a router for several VLAN-separated networks:

- the outside port gets its address and default route;
- each inside network is a VLAN with its own address range;
- machines on each VLAN get an address and a DNS server by DHCP;
- they reach the internet through NAT;
- VLANs cannot reach each other unless a rule says so;
- all of it comes back after a reboot;
- a change that cuts off the deployment undoes itself, as PF rules do today.

## Where phase 1 stops

| Area | Today | Missing for the MVP |
| --- | --- | --- |
| Interfaces and VLANs | Nothing. Rules can name `em0` or `vlan10`, but nothing creates or addresses them. | Everything. See milestone 1. |
| Routing | Nothing. | `net.inet.ip.forwarding=1`. Without it NAT rules load and do nothing. |
| Outside connection | Nothing. | DHCP client or a fixed address and gateway on the outside port. |
| NAT | Two commented examples in `nat/20-nat.conf`, and guided forms in `./fw`. | A default rule set that actually routes; see milestone 2. |
| Filter rules | `block all`, SSH in, ping, and the firewall's own traffic out. Nothing lets a packet from an inside network through. | Rules per network, and macros so they are written once. |
| DHCP | `dhcpd-apply` installs the file and restarts `dhcpd` only if it already runs. Never run on OpenBSD. | Enabling the service, removing a configuration, one subnet per VLAN, proof on OpenBSD. |
| DNS for clients | The example hands out `1.1.1.1`. | Optional local resolver; see milestone 4. |
| Seeing what the firewall does | Monitoring watches only its own server. | Firewall metrics and PF logs; see milestone 5. |
| Proof on OpenBSD | PF operations proven on 7.9. `dhcpd-apply`, `fcc-gate`, `./setup` and both reset scripts only against stand-ins. | A repeatable test against a real OpenBSD VM; see milestone 0. |

## Milestones

Build them in this order. Each depends on the one before, apart from 4 and 5.

### 0. A real OpenBSD to test against

Every later milestone changes how the machine is reached, so stand-ins for
`pfctl` are no longer enough.

- A script that boots an OpenBSD VM (QEMU, with `autoinstall`) with one
  outside port, one trunk port, and a client VM or network namespace on a
  tagged VLAN behind it.
- Run what phase 1 left unproven against it: `./setup`, `fcc-gate`,
  `dhcpd-apply`, the stuck-lock takeover, `./factory-reset firewall`.
- Remove the "has not been run on OpenBSD" paragraphs from the README as each
  one passes.

Done when: one command boots the VM, runs `./setup`, deploys this repository,
and reports pass or fail.

### 1. Interfaces, VLANs and routing

The largest piece, and the only one that needs new design.

**In the repository.** A new `network/` folder holding the files OpenBSD
itself uses, unchanged, so they can be read and written by hand like the rest:

| Path | Installed as |
| --- | --- |
| `network/hostname.em0`, `network/hostname.vlan10`, ... | `/etc/hostname.<if>` |
| `network/sysctl.conf` | `/etc/sysctl.conf` |
| `network/mygate` | `/etc/mygate`, only when the outside address is fixed |

A VLAN is then three lines in `network/hostname.vlan10`:

```
parent em1 vnetid 10
inet 192.168.10.1 255.255.255.0
up
```

**On the firewall.** New `fcc-pfctl` operations, `net-validate` and
`net-apply`, with the same shape as the PF ones: check, arm, apply, reconnect,
commit, or roll back. `fcc-gate` allows them. The files travel on standard
input, joined with `# --- name ---` headers as `./fw assemble` joins PF files.

The helper's rule that nothing the caller sends becomes a path has to bend
here, because the file names are the interface names. Keep it narrow:

- a name must match `hostname.<driver><number>` with the driver from a short
  list (`vlan`, plus the physical ports `ifconfig` reports on that machine);
- **a line starting with `!` is refused.** `netstart` runs such lines as root,
  which would turn the deployment key into a root shell;
- sysctl lines are accepted only from a fixed list of names, to start with
  `net.inet.ip.forwarding` and `net.inet6.ip6.forwarding`;
- size limits as for the rules.

**Rollback.** This is harder than PF. PF rules can be loaded without touching
`/etc/pf.conf`, so a reboot restores the old ones. `netstart` reads only
`/etc/hostname.*`, so the new files must be in place before they are tried.
Proposed:

1. `net-apply` copies the current files to `/var/db/fcc/net-previous/`, writes
   a `net-pending` marker beside them, installs the new files, and runs
   `sh /etc/netstart` for each interface that changed.
2. `commit` removes the marker. `rollback` and the watchdog put the copies
   back, destroy VLANs that did not exist before, and run `netstart` again.
3. A line in `/etc/rc.local`, added by `install.sh`, does the same at boot if
   the marker is still there. `/var/run/fcc` is emptied at boot, so the marker
   must live in `/var/db/fcc`.

**In the deployer.** The playbook applies in this order: network, PF rules,
DHCP. PF rules such as `vlan10:network` do not parse until the interface
exists, and `dhcpd` will not serve a subnet no interface is on. One watchdog
covers network and rules together, so a change to both is confirmed or undone
as one.

A network change that fails after loading is not retried, like a rule change.

**In `./fw`.** A "Networks" menu: add a VLAN (parent port, number, address),
set the outside port to DHCP or a fixed address, switch routing on. `status`
compares the digests of the network files too.

Done when: on the test VM, a commit adding `hostname.vlan10` gives the client
a reachable gateway; a commit that renumbers the management port is undone by
the watchdog; pulling the plug between apply and commit comes back on the old
addresses.

### 2. NAT and a rule set that routes

No new mechanism; the files and the editor catch up with milestone 1.

- `firewall/10-settings.conf` gains macros and tables: one macro per network
  (`lan = "vlan10"`), and `<admins>` for who may reach SSH. `./fw` gets a list
  for this file; today it has none.
- Shipped defaults that work once the names are filled in: `antispoof` on each
  inside port, `match out on egress ... nat-to (egress)`, each network may
  reach the internet, no network may reach another, SSH only from `<admins>`.
- The guided forms offer the macros and known interfaces instead of free text,
  and outbound NAT accepts `vlan10:network` as well as a typed range.
  `check_address` refuses that form today.
- `keeps_ssh_open` learns about `<admins>`, so it does not cry wolf.
- `status` does not compare the contents of tables. Decide whether tables stay
  inline in `10-settings.conf`, which needs nothing new, or move to files,
  which needs another helper operation. Recommended: inline for the MVP.

Done when: the client on VLAN 10 reaches the internet through the test VM, and
cannot reach a client on VLAN 20.

### 3. DHCP that can be switched on and off

- `dhcpd-apply` enables and starts `dhcpd` when a configuration is deployed.
  Today it leaves that to the administrator, which means a first deployment
  installs a file and serves nothing. This reverses a choice the helper's
  comments record as deliberate; confirm before building.
- A new `dhcpd-remove`: when `dhcp/dhcpd.conf` goes back to comments only, stop
  and disable `dhcpd` and remove `/etc/dhcpd.conf`. Today the old
  configuration stays in service for good.
- `./fw`: the network form offers the VLANs from milestone 1 and fills in the
  router address; fixed addresses are checked against the subnets in the file.
- `status` reports whether `dhcpd` is running, not only the file's digest.

Done when: the client gets a lease on VLAN 10 with the right router and DNS
server; emptying the file stops the service.

### 4. DNS for clients

Can be skipped for a first MVP by handing out a public resolver, as the
example does. Worth having because it is what makes local names work.

- `dns/unbound.conf`, checked with `unbound-checkconf`, installed by a
  `unbound-apply` operation shaped like `dhcpd-apply`.
- Listens on the inside addresses only; the default rules allow port 53 to the
  firewall from inside networks.
- The DHCP form offers "this firewall" as the DNS server.

### 5. Seeing what the firewall does

Not needed to route packets; needed before trusting it with a real network.

- `node_exporter` on the firewall, from packages, listening on the management
  address, with a PF rule admitting only the monitoring server. This ends the
  README's "the monitoring server has no access to the firewall"; say so there.
- A Prometheus scrape job and a dashboard: interface traffic, PF state count,
  packets blocked.
- `log` on the default `block` rule, and the deployer's `status.json` exported
  so a failed deployment raises an alert.

## Left for later

Each is useful, none is needed for the MVP above.

| Feature | Why it waits |
| --- | --- |
| IPv6 (`rad`, prefix delegation, `inet6` rules) | Doubles the work of milestones 1 to 3. The default `block all` already covers it safely. |
| WireGuard and other VPNs | Needs a way to keep private keys out of Git, which nothing here has yet. |
| PPPoE on the outside port | Same secrets problem; DHCP and fixed addresses cover most connections. |
| Two firewalls with CARP and `pfsync` | Changes the deployer from one target to several. |
| Link aggregation, bridges | Same mechanism as VLANs; add the drivers to the helper's list when wanted. |
| Traffic shaping (`queue`) | Already expressible by hand in the PF files. |
| NTP, remote syslog, `relayd`, DHCP relay | One more `*-apply` operation each, once the pattern from milestone 4 exists. |
| Several firewalls from one repository | `firewall.json` describes exactly one. |

## Decisions needed before milestone 1

1. **`network/hostname.*` files as OpenBSD writes them, or one file of our
   own?** Recommended: OpenBSD's own. It keeps "the files are the
   configuration" true and needs no translator, at the cost of the `!` check.
2. **One watchdog for network and rules, or one each?** Recommended: one. Two
   can leave new addresses running with old rules.
3. **Restore at boot through `rc.local`?** It runs after `netstart`, so the
   machine comes up briefly on the unconfirmed addresses and then switches
   back. The alternative, restoring before `netstart`, means editing `/etc/rc`,
   which `sysmerge` will fight at every upgrade.
4. **Should `dhcpd-apply` enable the service?** See milestone 3.
