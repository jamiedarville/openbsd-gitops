"""Turns an OPNsense configuration backup (config.xml) into this repository's files.

What is read: interfaces and VLANs, the default route, aliases, filter rules,
outbound NAT, port forwards and one-to-one NAT, the DHCP server (ISC, Kea and
dnsmasq) and the resolver (Unbound, or dnsmasq's host and domain overrides).

Nothing from the backup is copied into a file as it stands. Every address,
port, name and protocol is parsed and written out again, and whatever cannot
be written faithfully is left out and listed in the report instead, so that a
rule is never silently made wider than it was.

The files it writes are its own: each starts with MARKER, and importing again
replaces them. The files kept by hand, such as firewall/30-rules.conf, are
left alone.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from . import rules

MARKER = "# Imported from OPNsense by ./fw import-opnsense. Importing again replaces this file."
ALIASES_FILE = Path("firewall/15-opnsense-aliases.conf")
NAT_FILE = Path("nat/25-opnsense.conf")
RULES_FILE = Path("firewall/40-opnsense.conf")
# dhcpd.conf is shared with the editor, so the import keeps to a part of it.
DHCP_BEGIN = "# --- imported from OPNsense: begin ---"
DHCP_END = "# --- imported from OPNsense: end ---"

# FreeBSD names a port after its driver, and so does OpenBSD, but not always
# with the same driver. The number after it usually stays.
_DRIVERS = {"igb": "em", "vtnet": "vio", "mce": "mcx", "hn": "hvn", "xn": "xnf", "bce": "bnx"}
_SAME_DRIVERS = frozenset(
    "em ix ixl ixv igc re bge vmx bnxt alc ale age aq ice msk rl sk fxp dc nfe jme et vr vge "
    "ste stge sis xl axe axen ure cdce iavf vio mcx oce".split()
)
_NOT_BUILT = {
    "lagg": "a link aggregation", "bridge": "a bridge", "wg": "a WireGuard tunnel",
    "ovpns": "an OpenVPN server", "ovpnc": "an OpenVPN client", "openvpn": "the OpenVPN group",
    "wireguard": "the WireGuard group", "tun": "a tunnel", "tap": "a tunnel", "gif": "a tunnel",
    "gre": "a tunnel", "ipsec": "an IPsec tunnel", "enc": "IPsec", "pppoe": "a PPPoE connection",
    "ppp": "a PPP connection", "l2tp": "an L2TP connection", "pptp": "a PPTP connection",
    "zt": "a ZeroTier network", "vxlan": "a VXLAN", "vlan": "a VLAN the backup does not define",
}  # fmt: skip
_PRIVATE = "10.0.0.0/8, 127.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, fc00::/7"
# Words PF reads as part of a rule, which a macro therefore cannot be called.
_PF_WORDS = frozenset(
    "all any in out on from to port proto pass block match quick log inet inet6 tcp udp icmp "
    "icmp6 table set scrub anchor queue label tag tagged user group flags state keep no drop "
    "return self egress include load file const persist max min for binat rdr nat".split()
)
# Options of a rule that have no place in what is written here.
_NOT_CARRIED = {
    "sched": "its schedule", "tag": "the tag it sets", "tagged": "the tag it matches",
    "max": "its state limit", "max-src-nodes": "its source limit", "max-src-conn": "its connection limit",
    "max-src-states": "its state limit per source", "max-src-conn-rate": "its connection rate limit",
    "statetimeout": "its state timeout", "tcpflags1": "its TCP flags", "tcpflags_any": "its TCP flags",
    "os": "its operating system match", "set-prio": "the priority it sets", "prio": "the priority it matches",
    "overload": "its overload table", "categories": "",
}  # fmt: skip
# Parts of a backup this importer does not read, named in the report when used.
_OTHER = (
    ("openvpn/openvpn-server", "OpenVPN"), ("openvpn/openvpn-client", "OpenVPN"),
    ("OPNsense/OpenVPN/Instances/Instance", "OpenVPN"),
    ("OPNsense/wireguard/server/servers/server", "WireGuard"),
    ("ipsec/phase1", "IPsec"), ("OPNsense/Swanctl/Connections/Connection", "IPsec"),
    ("laggs/lagg", "link aggregation"), ("bridges/bridged", "bridges"), ("ppps/ppp", "PPP connections"),
    ("gifs/gif", "GIF tunnels"), ("gres/gre", "GRE tunnels"),
    ("OPNsense/TrafficShaper/pipes/pipe", "traffic shaping"),
    ("OPNsense/captiveportal/zones/zone", "the captive portal"),
    ("OPNsense/Firewall/Filter/snatrules/rule", "source NAT rules made through the API"),
    ("OPNsense/Firewall/Filter/npt/rule", "IPv6 prefix translation"),
    ("OPNsense/Firewall/Filter/onetoone/rule", "one-to-one NAT rules made through the API"),
    ("OPNsense/Firewall/DNat/rule", "destination NAT rules in the new format"),
    ("nat/npt", "IPv6 prefix translation"), ("dhcrelay", "the DHCP relay"),
    ("OPNsense/DHCRelay/relays", "the DHCP relay"), ("dyndns/dyndns", "dynamic DNS"),
)  # fmt: skip

_ALIAS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
_MAC = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_LABEL = r"[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_DOMAIN = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PORT = re.compile(r"^(\d{1,5})(?:[-:](\d{1,5}))?$")
_DEVICE = re.compile(r"^([a-z]+)([0-9]+)$")


class ImportFailed(Exception):
    """The backup cannot be imported at all. The message is for the person."""


class _Unmappable(Exception):
    """One rule or setting cannot be written faithfully. The message says why."""


# ------------------------------------------------------------- reading the XML


def _text(node: ET.Element | None, path: str, default: str = "") -> str:
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None else default


def _isset(node: ET.Element | None, path: str) -> bool:
    """True as OPNsense reads its older settings: there, and not switched off."""
    found = node.find(path) if node is not None else None
    return found is not None and (found.text or "").strip().lower() not in ("0", "no", "false")


def _on(node: ET.Element | None, path: str, default: str = "0") -> bool:
    """True as OPNsense reads its newer settings: exactly 1."""
    return _text(node, path, default) == "1"


def _texts(node: ET.Element | None, path: str) -> list[str]:
    found = node.findall(path) if node is not None else []
    return [value for value in ((item.text or "").strip() for item in found) if value]


def _words(value: str) -> list[str]:
    return [word for word in re.split(r"[\s,]+", value.strip()) if word]


def _comment(value: str, limit: int = 100) -> str:
    """Somebody's description, made safe to put after a # on one line."""
    value = "".join(letter for letter in " ".join(value.split()) if letter.isprintable())
    return value[:limit].rstrip("\\ ")


def _literal(value: str) -> str | None:
    """An address or a network, written out afresh; None for anything else."""
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _ip4(value: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(value.strip())
    except ValueError:
        return None


def _address_range(value: str) -> tuple[ipaddress._BaseAddress, ipaddress._BaseAddress] | None:
    first, dash, last = value.partition("-")
    try:
        start, end = ipaddress.ip_address(first.strip()), ipaddress.ip_address(last.strip())
    except ValueError:
        return None
    return (start, end) if dash and start.version == end.version and start <= end else None


def _braces(items: list[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


# ------------------------------------------------------------------- the parts


@dataclass
class Interface:
    key: str  # what OPNsense calls it in rules: wan, lan, opt1
    label: str  # what the person called it
    device: str  # what FreeBSD called it
    name: str = ""  # what OpenBSD calls it; empty if it cannot be built here
    why: str = ""  # why not
    address: ipaddress.IPv4Interface | None = None
    dhcp: bool = False
    uplink: bool = False
    vlan: tuple[str, int, int] | None = None  # parent, number, priority
    extra: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.name:
            return f"not imported: {self.why}"
        parts = ["DHCP" if self.dhcp else str(self.address) if self.address else "no address"]
        if self.vlan:
            parts.append(f"VLAN {self.vlan[1]} on {self.vlan[0]}")
        return ", ".join(parts)


@dataclass
class Alias:
    name: str
    kind: str  # addresses | ports | other
    content: list[str]
    described: str = ""
    type: str = ""


@dataclass
class Result:
    files: dict[Path, list[str]]  # every file to write, whole
    removed: list[Path]  # files of an earlier import that are no longer wanted
    report: str


class Importer:
    def __init__(self, config: ET.Element, device_map: dict[str, str] | None = None, ssh_port: int = 22):
        self.config = config
        self.device_map = device_map or {}
        self.ssh_port = ssh_port
        self.interfaces: dict[str, Interface] = {}
        self.groups: dict[str, list[str]] = {}
        self.aliases: dict[str, Alias] = {}
        self.gateways: dict[str, str] = {}  # name -> IPv4 address
        self.taken: dict[str, str] = {}  # OpenBSD port -> FreeBSD port
        self.guessed: list[str] = []
        self.parents: set[str] = set()
        self.notes: dict[str, list[str]] = {}
        self.counts: dict[Path, str] = {}
        self.listening: set[str] = set()  # the interfaces a resolver answers on
        self.domain = ""

    def note(self, area: str, message: str) -> None:
        if message not in self.notes.setdefault(area, []):
            self.notes[area].append(message)

    # ---------------------------------------------------------------- interfaces

    def _port(self, device: str) -> str:
        """The OpenBSD name of a port that FreeBSD called `device`."""
        if device in self.device_map:
            name = self.device_map[device]
        else:
            match = _DEVICE.match(device)
            driver = match.group(1) if match else device.split("_")[0].rstrip("0123456789.")
            if driver in _NOT_BUILT or not match:
                kind = _NOT_BUILT.get(driver, "not a port this importer knows")
                raise _Unmappable(f"{device} is {kind}, which is not set up from this repository")
            name = _DRIVERS.get(driver, driver) + match.group(2)
            if driver not in _DRIVERS and driver not in _SAME_DRIVERS and device not in self.guessed:
                self.guessed.append(device)
        owner = self.taken.setdefault(name, device)
        if owner != device:
            raise ImportFailed(
                f"{owner} and {device} would both be called {name} on OpenBSD. "
                f"Say which is which, for example: --map {device}=NAME"
            )
        return name

    def read_interfaces(self) -> None:
        vlans: dict[str, tuple[str, int, int]] = {}
        for node in self.config.findall("vlans/vlan"):
            parent, tag, priority = _text(node, "if"), _text(node, "tag"), _text(node, "pcp")
            if tag.isdigit() and 1 <= int(tag) <= 4094:
                device = _text(node, "vlanif") or f"{parent}_vlan{tag}"
                vlans[device] = (parent, int(tag), int(priority) if priority.isdigit() else 0)

        section = self.config.find("interfaces")
        numbers: set[int] = set()
        for node in section if section is not None else []:
            device = _text(node, "if")
            if not device or device.startswith("lo") or not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", node.tag):
                continue
            entry = Interface(node.tag, _comment(_text(node, "descr"), 40) or node.tag.upper(), device)
            self.interfaces[entry.key] = entry
            if not _isset(node, "enable"):
                entry.why = "it is switched off in OPNsense"
                continue
            try:
                if device in vlans and device not in self.device_map:
                    parent, tag, priority = vlans.pop(device)
                    port = self._port(parent)
                    number = tag
                    while number in numbers:  # the same VLAN number on two ports
                        number += 4094
                    numbers.add(number)
                    entry.vlan, entry.name = (port, tag, priority), f"vlan{number}"
                    self.parents.add(port)
                    if number != tag:
                        self.note("Interfaces", f"{entry.label}: VLAN {tag} exists on two ports, so this one is called {entry.name}.")
                else:
                    entry.name = self._port(device)
            except _Unmappable as why:
                entry.why = str(why)
                continue

            kind, bits = _text(node, "ipaddr"), _text(node, "subnet")
            if kind == "dhcp":
                entry.dhcp = True
            elif _ip4(kind) and bits.isdigit() and int(bits) <= 32:
                entry.address = ipaddress.IPv4Interface(f"{kind}/{bits}")
            elif kind:
                entry.name, entry.why = "", f"it gets its address by {kind}, which is not set up from this repository"
                continue
            entry.uplink = entry.dhcp or bool(_text(node, "gateway"))
            if _text(node, "ipaddrv6"):
                self.note("Interfaces", f"{entry.label}: its IPv6 setting ({_text(node, 'ipaddrv6')}) is not imported. This repository sets up IPv4 only.")
            if _MAC.match(_text(node, "spoofmac")):
                entry.extra.append(f"lladdr {_text(node, 'spoofmac').lower()}")
            if _text(node, "mtu").isdigit():
                entry.extra.append(f"mtu {int(_text(node, 'mtu'))}")

        for device, (parent, tag, _) in vlans.items():
            self.note("Interfaces", f"VLAN {tag} on {parent} ({device}) is not assigned to an interface in OPNsense, and was left out.")

        for node in self.config.findall("ifgroups/ifgroupentry"):
            name = _text(node, "ifname")
            if name:
                self.groups[name] = _words(_text(node, "members"))

        for node in self.config.findall("virtualip/vip"):
            entry = self.interfaces.get(_text(node, "interface"))
            address, bits, mode = _ip4(_text(node, "subnet")), _text(node, "subnet_bits"), _text(node, "mode")
            if mode == "ipalias" and entry and entry.name and address and bits.isdigit() and int(bits) <= 32:
                mask = ipaddress.IPv4Network(f"0.0.0.0/{bits}").netmask
                entry.extra.append(f"inet alias {address} {mask}")
            else:
                self.note("Interfaces", f"Virtual address {_text(node, 'subnet') or '?'} ({mode or 'unknown kind'}) is not imported.")

    def read_gateways(self) -> None:
        chosen: list[tuple[int, str]] = []
        nodes = self.config.findall("gateways/gateway_item") + self.config.findall("OPNsense/Gateways/gateway_item")
        for node in nodes:
            address, name = _ip4(_text(node, "gateway")), _text(node, "name")
            if _isset(node, "disabled") or address is None or not name:
                continue
            self.gateways[name] = str(address)
            # The default route is the gateway marked as such, or failing
            # that the one an outside interface was given.
            entry = self.interfaces.get(_text(node, "interface"))
            if entry and entry.name and entry.address and (_isset(node, "defaultgw") or entry.uplink):
                chosen.append((0 if _isset(node, "defaultgw") else 1, str(address)))
        self.default_gateway = min(chosen)[1] if chosen else ""
        if len(self.gateways) > 1:
            self.note("Routing", f"There are {len(self.gateways)} gateways. Only one default route is imported; failover and balancing between them are not.")
        for node in self.config.findall("staticroutes/route"):
            network, gateway = _literal(_text(node, "network")), self.gateways.get(_text(node, "gateway"))
            if not _isset(node, "disabled"):
                where = f"{network} by way of {gateway}" if network and gateway else _text(node, "network") or "?"
                self.note("Routing", f"The static route to {where} is not imported: the firewall refuses the line that would add it. Add it on the firewall by hand.")

    def device(self, key: str) -> str:
        entry = self.interfaces.get(key)
        if entry is None:
            raise _Unmappable(f"there is no interface {key!r} in the backup")
        if not entry.name:
            raise _Unmappable(f"the interface {entry.label} was not imported")
        return entry.name

    def devices(self, value: str) -> list[str]:
        """The OpenBSD interfaces behind a rule's interface, group or list."""
        names: list[str] = []
        for key in _words(value):
            for member in self.groups.get(key, [key]):
                name = self.device(member)
                if name not in names:
                    names.append(name)
        return names

    def network_files(self) -> dict[Path, list[str]]:
        files: dict[Path, list[str]] = {}
        for entry in self.interfaces.values():
            if not entry.name:
                self.note("Interfaces", f"{entry.label} ({entry.device}) was not imported: {entry.why}.")
                continue
            lines = [MARKER, f"# {entry.label}: {entry.key} in OPNsense, where the port was {entry.device}"]
            if entry.vlan:
                parent, number, priority = entry.vlan
                lines.append(f"parent {parent} vnetid {number}" + (f" txprio {priority}" if priority else ""))
            lines += [line for line in entry.extra if not line.startswith("inet")]
            if entry.dhcp:
                lines.append("inet autoconf")
            elif entry.address:
                lines.append(f"inet {entry.address.ip} {entry.address.network.netmask}")
            lines += [line for line in entry.extra if line.startswith("inet")]
            files[rules.NETWORK_FOLDER / f"hostname.{entry.name}"] = [*lines, "up"]
        for port in sorted(self.parents):
            path = rules.NETWORK_FOLDER / f"hostname.{port}"
            if path not in files:
                files[path] = [MARKER, "# Carries VLANs, and has no address of its own", "up"]
        if self.default_gateway:
            files[rules.NETWORK_FOLDER / "mygate"] = [MARKER, self.default_gateway]
        return files

    # ------------------------------------------------------------------- aliases

    def read_aliases(self) -> None:
        found = []
        for node in self.config.findall("OPNsense/Firewall/Alias/aliases/alias"):
            if _on(node, "enabled", "1"):
                found.append((node, re.split(r"[\n,]+", _text(node, "content")), _text(node, "description")))
        for node in self.config.findall("aliases/alias"):
            found.append((node, _text(node, "address").split(), _text(node, "descr")))
        for node, content, described in found:
            name, kind = _text(node, "name"), _text(node, "type")
            if not _ALIAS_NAME.match(name) or name in self.aliases:
                continue
            group = {"host": "addresses", "network": "addresses", "networkgroup": "addresses", "port": "ports"}
            content = [item.strip() for item in content if item.strip()]
            self.aliases[name] = Alias(name, group.get(kind, "other"), content, _comment(described, 60), kind)

    def _table(self, name: str) -> str:
        return name[:31]

    def _macro(self, name: str) -> str:
        return f"{name}_ports" if name.lower() in _PF_WORDS else name

    def alias_addresses(self, name: str, seen: tuple[str, ...] = ()) -> list[str]:
        members: list[str] = []
        for item in self.aliases[name].content:
            negated, value = item.startswith("!"), item.lstrip("!")
            nested = self.aliases.get(value)
            spread = _address_range(value)
            if nested is not None and nested.kind == "addresses" and value not in seen and not negated:
                found = self.alias_addresses(value, (*seen, name))
            elif _literal(value):
                found = [("!" if negated else "") + _literal(value)]
            elif spread and not negated:
                found = [str(network) for network in ipaddress.summarize_address_range(*spread)]
            else:
                # A name here would be looked up when the rules are loaded,
                # and the rules would fail to load whenever that lookup did.
                self.note("Aliases", f"{name}: {_comment(item, 60)!r} is not an address or a network, and was left out of the table. A table cannot hold a name that needs looking up.")
                continue
            members += [member for member in found if member not in members]
        return members

    def alias_ports(self, name: str, seen: tuple[str, ...] = ()) -> list[str]:
        ports: list[str] = []
        for item in self.aliases[name].content:
            nested = self.aliases.get(item)
            if nested is not None and nested.kind == "ports" and item not in seen:
                ports += self.alias_ports(item, (*seen, name))
            elif self._port_range(item):
                ports.append(self._port_range(item))
            else:
                self.note("Aliases", f"{name}: {_comment(item, 60)!r} is not a port, and was left out.")
        return list(dict.fromkeys(ports))

    def alias_lines(self) -> list[str]:
        lines: list[str] = []
        tables = {}
        count: dict[str, int] = {}
        for alias in self.aliases.values():
            comment = f"  # {alias.described}" if alias.described else ""
            if alias.kind == "ports":
                ports = self.alias_ports(alias.name)
                if ports:
                    count["port list"] = count.get("port list", 0) + 1
                    value = ports[0] if len(ports) == 1 else "{ " + ", ".join(ports) + " }"
                    lines.append(f'{self._macro(alias.name)} = "{value}"{comment}')
                continue
            table = self._table(alias.name)
            if tables.setdefault(table, alias.name) != alias.name:
                self.note("Aliases", f"{alias.name} and {tables[table]} have the same first 31 letters, which is all a table name may have. Rename one.")
                continue
            members = self.alias_addresses(alias.name) if alias.kind == "addresses" else []
            if alias.kind == "other":
                self.note("Aliases", f"{alias.name} is of the kind {alias.type or 'unknown'}, which is filled in by OPNsense itself. Its table <{table}> is empty here, so rules that use it match nothing until you fill it.")
            count["table"] = count.get("table", 0) + 1
            if members:
                lines.append(f"table <{table}> {{ {', '.join(members)} }}{comment}")
            else:
                lines.append(f"table <{table}> persist{comment}")
        if not lines:
            return []
        self.counts[ALIASES_FILE] = ", ".join(f"{number} {noun}{'' if number == 1 else 's'}" for noun, number in count.items())
        return [MARKER, "# Aliases: an address alias is a table, used as <name>; a port alias is a macro, used as $name.", "", *lines]

    # ------------------------------------------------- addresses, ports, protocols

    def _port_range(self, value: str) -> str:
        match = _PORT.match(value)
        if not match:
            return ""
        numbers = [int(number) for number in match.groups() if number is not None]
        if any(not 1 <= number <= 65535 for number in numbers):
            return ""
        return ":".join(str(number) for number in numbers)

    def ports(self, value: str) -> str:
        """A rule's ports as PF writes them, or nothing for any port."""
        items = [item for item in _words(value) if item != "any"]
        if len(items) == 1 and items[0] in self.aliases and self.aliases[items[0]].kind == "ports":
            if not self.alias_ports(items[0]):
                raise _Unmappable(f"the port alias {items[0]} holds no ports")
            return "$" + self._macro(items[0])
        found: list[str] = []
        for item in items:
            alias = self.aliases.get(item)
            if alias is not None and alias.kind == "ports":
                found += self.alias_ports(item)
            elif self._port_range(item):
                found.append(self._port_range(item))
            else:
                raise _Unmappable(f"{_comment(item, 40)!r} is not a port or a port alias")
        return _braces(found) if found else ""

    def address(self, value: str) -> str:
        """A rule's source or destination as PF writes it."""
        found = [self._one_address(item) for item in value.split(",") if item.strip()]
        return _braces(found) if found else "any"

    def _one_address(self, value: str) -> str:
        value = value.strip()
        if value == "any":
            return "any"
        if value == "(self)":
            return "(self)"
        if value in self.interfaces:
            return f"({self.device(value)}:network)"
        if value.endswith("ip") and value[:-2] in self.interfaces:
            return f"({self.device(value[:-2])})"
        if _literal(value):
            return _literal(value)
        spread = _address_range(value)
        if spread:
            return f"{spread[0]} - {spread[1]}"
        alias = self.aliases.get(value)
        if alias is not None and alias.kind != "ports":
            return f"<{self._table(value)}>"
        raise _Unmappable(f"{_comment(value, 40)!r} is not an address, a network or an alias in the backup")

    def endpoint(self, node: ET.Element | None, ports: bool, port_field: str = "port") -> tuple[str, str]:
        """The address and the ports of a <source> or <destination>."""
        if node is None or node.find("any") is not None:
            address = "any"
        else:
            address = self.address(_text(node, "network") or _text(node, "address") or "any")
        if _isset(node, "not"):
            address = self.negate(address)
        return address, self.ports(_text(node, port_field)) if ports else ""

    @staticmethod
    def negate(address: str) -> str:
        if address == "any" or address.startswith("{") or " - " in address:
            raise _Unmappable(f"\"not {address}\" cannot be written as one PF rule")
        return f"! {address}"

    def protocol(self, value: str, family: str) -> tuple[str, list[str]]:
        """The address family and the protocols of a rule."""
        family = {"inet": "inet", "inet6": "inet6"}.get(family or "inet", "")
        value = value.lower()
        if value in ("", "any"):
            return family, []
        if value == "tcp/udp":
            return family, ["tcp", "udp"]
        if value == "icmp":
            return "inet", ["icmp"]
        if value in ("ipv6-icmp", "icmp6", "icmpv6"):
            return "inet6", ["icmp6"]
        if not re.match(r"^[a-z][a-z0-9-]{0,15}$", value):
            raise _Unmappable(f"{_comment(value, 20)!r} is not a protocol")
        return family, [value]

    # -------------------------------------------------------------- filter rules

    def _rule(self, spec: dict) -> str:
        """One filter rule, from what read_rule or read_new_rule found."""
        family, protocols = self.protocol(spec["protocol"], spec["family"])
        with_ports = bool(protocols) and set(protocols) <= {"tcp", "udp"}
        if (spec["source_port"] or spec["destination_port"]) and not with_ports:
            raise _Unmappable("it names ports without being TCP or UDP")
        source, destination = self.address(spec["source"]), self.address(spec["destination"])
        if spec["source_not"]:
            source = self.negate(source)
        if spec["destination_not"]:
            destination = self.negate(destination)

        action = {"pass": "pass", "block": "block", "reject": "block return"}.get(spec["action"])
        if action is None:
            raise _Unmappable(f"{_comment(spec['action'], 20)!r} is not something a rule can do")
        parts = [action]
        if spec["direction"] in ("in", "out"):
            parts.append(spec["direction"])
        if spec["log"]:
            parts.append("log")
        if spec["quick"]:
            parts.append("quick")
        names = self.devices(spec["interface"])
        if names:
            parts += ["on", _braces(names)]
        if family:
            parts.append(family)
        if protocols:
            parts += ["proto", _braces(protocols)]
        parts += ["from", source]
        if spec["source_port"]:
            parts += ["port", self.ports(spec["source_port"])]
        parts += ["to", destination]
        if spec["destination_port"]:
            parts += ["port", self.ports(spec["destination_port"])]
        types = [kind for kind in _words(spec["icmp"]) if kind != "any"]
        if types and protocols in (["icmp"], ["icmp6"]):
            if any(not re.match(r"^[a-z0-9]{1,16}$", kind) for kind in types):
                raise _Unmappable("its ICMP type is not one PF knows")
            parts += ["icmp-type" if protocols == ["icmp"] else "icmp6-type", _braces(types)]
        if spec["gateway"] and action == "pass":
            if spec["gateway"] in self.gateways:
                parts += ["route-to", self.gateways[spec["gateway"]]]
            else:
                self.note("Firewall rules", f"{spec['what']}: it sent traffic by way of the gateway {_comment(spec['gateway'], 30)}, which has no fixed address in the backup. The rule is imported without that, and follows the default route.")
        state = {"sloppy state": "keep state (sloppy)", "synproxy state": "synproxy state", "modulate state": "modulate state", "none": "no state"}
        if action == "pass" and spec["state"] in state:
            parts.append(state[spec["state"]])
        return " ".join(parts)

    def _emit(self, lines: list[str], spec: dict, build) -> str:
        """Adds one rule to the lines, or says why not. Returns what became of it."""
        comment = f"  # {spec['comment']}" if spec["comment"] else ""
        try:
            line = build(spec)
        except _Unmappable as why:
            if spec["disabled"]:
                return "skipped"
            lines.append(f"# NOT IMPORTED, {why}" + (f": {spec['comment']}" if spec["comment"] else ""))
            loud = "A BLOCK RULE IS MISSING. " if spec.get("action") in ("block", "reject") else ""
            self.note(spec["area"], f"{loud}{spec['what']} was not imported: {why}.")
            return "left out"
        if spec["disabled"]:
            lines.append(f"# switched off in OPNsense: {line}{comment}")
            return "switched off"
        lines.append(line + comment)
        return "imported"

    def _what(self, kind: str, node: ET.Element, comment: str, interface: str) -> str:
        where = ", ".join(self.interfaces[key].label if key in self.interfaces else key for key in _words(interface))
        named = f'"{comment}"' if comment else "without a description"
        return f"The {kind} {named}" + (f" on {where}" if where else "")

    def read_rule(self, node: ET.Element) -> dict:
        floating = _isset(node, "floating")
        source, destination = node.find("source"), node.find("destination")
        comment, interface = _comment(_text(node, "descr")), _text(node, "interface")

        def side(part: ET.Element | None) -> str:
            if part is None or part.find("any") is not None:
                return "any"
            return _text(part, "network") or _text(part, "address") or "any"

        spec = {
            "area": "Firewall rules", "what": self._what("rule", node, comment, interface),
            "action": _text(node, "type", "pass"), "interface": interface,
            "direction": _text(node, "direction", "in") if floating else "in",
            # A rule on an interface stops at the first match unless told not
            # to; a floating rule does so only when told to.
            "quick": _isset(node, "quick") if floating else _text(node, "quick") != "0",
            "log": _isset(node, "log"), "family": _text(node, "ipprotocol", "inet"),
            "protocol": _text(node, "protocol"),
            "source": side(source), "source_not": _isset(source, "not"), "source_port": _text(source, "port"),
            "destination": side(destination), "destination_not": _isset(destination, "not"),
            "destination_port": _text(destination, "port"),
            "icmp": _text(node, "icmptype") or _text(node, "icmp6-type"),
            "gateway": _text(node, "gateway"), "state": _text(node, "statetype"),
            "comment": comment, "disabled": _isset(node, "disabled"),
        }  # fmt: skip
        lost = [words for tag, words in _NOT_CARRIED.items() if words and _text(node, tag)]
        if lost and not spec["disabled"]:
            self.note("Firewall rules", f"{spec['what']}: {', '.join(dict.fromkeys(lost))} did not come across. The rule is imported without.")
        return spec

    def read_new_rule(self, node: ET.Element) -> dict:
        comment, interface = _comment(_text(node, "description")), _text(node, "interface")
        return {
            "area": "Firewall rules", "what": self._what("rule", node, comment, interface),
            "action": _text(node, "action", "pass"), "interface": interface,
            "direction": _text(node, "direction", "in"), "quick": _on(node, "quick", "1"),
            "log": _on(node, "log"), "family": _text(node, "ipprotocol", "inet"),
            "protocol": _text(node, "protocol"),
            "source": _text(node, "source_net", "any"), "source_not": _on(node, "source_not"),
            "source_port": _text(node, "source_port"),
            "destination": _text(node, "destination_net", "any"), "destination_not": _on(node, "destination_not"),
            "destination_port": _text(node, "destination_port"),
            "icmp": _text(node, "icmptype"), "gateway": _text(node, "gateway"),
            "state": _text(node, "statetype"), "comment": comment, "disabled": not _on(node, "enabled", "1"),
        }  # fmt: skip

    def rule_lines(self) -> list[str]:
        lines: list[str] = []
        tally: dict[str, int] = {}

        # What OPNsense adds by itself, ahead of the rules a person wrote.
        inside = next((entry for key, entry in self.interfaces.items() if key == "lan" and entry.name), None)
        if inside and not _isset(self.config, "system/webgui/noantilockout"):
            lines.append(f"pass in quick on {inside.name} proto tcp from any to (self) port {self.ssh_port}  # Anti-lockout: SSH from {inside.label} always works")
        section = self.config.find("interfaces")
        for node in section if section is not None else []:
            entry = self.interfaces.get(node.tag)
            if entry is None or not entry.name:
                continue
            if _isset(node, "blockpriv"):
                lines.append(f"block in quick on {entry.name} from {{ {_PRIVATE} }} to any  # Private networks may not arrive on {entry.label}")
            if _isset(node, "blockbogons"):
                self.note("Firewall rules", f"{entry.label} blocked bogon networks, from a list OPNsense downloads. There is no such list here, so that is not imported.")

        tally["imported"] = len(lines)
        legacy = self.config.findall("filter/rule")

        def stage(node: ET.Element) -> int:
            if _isset(node, "floating"):
                return 0
            return 1 if _text(node, "interface") in self.groups else 2

        modern = self.config.findall("OPNsense/Firewall/Filter/rules/rule")
        modern.sort(key=lambda node: int(_text(node, "sequence", "0")) if _text(node, "sequence", "0").isdigit() else 0)
        ordered = [(node, self.read_rule) for node in sorted(legacy, key=stage)]
        # OPNsense reads the rules made in its newer format ahead of the
        # others on an interface, and after the floating ones.
        cut = sum(1 for node in legacy if stage(node) == 0)
        ordered[cut:cut] = [(node, self.read_new_rule) for node in modern]
        if legacy and modern:
            self.note("Firewall rules", "The backup holds rules in both of OPNsense's formats. The newer ones are placed after the floating rules and before the rest; check the order in firewall/40-opnsense.conf against the order OPNsense showed.")

        for node, read in ordered:
            outcome = self._emit(lines, read(node), self._rule)
            tally[outcome] = tally.get(outcome, 0) + 1
        self.counts[RULES_FILE] = self._tally(tally, "rule")
        if not lines:
            return []
        return [
            MARKER,
            "# Filter rules, in the order OPNsense tried them: floating rules, then those of",
            '# interface groups, then each interface\'s own. As there, a rule with "quick"',
            "# settles the matter, and what no rule passes is dropped by the \"block all\" in",
            "# 30-rules.conf.",
            "",
            *lines,
        ]

    @staticmethod
    def _tally(tally: dict[str, int], noun: str) -> str:
        parts = [f"{tally.get('imported', 0)} {noun}{'' if tally.get('imported', 0) == 1 else 's'}"]
        parts += [f"{count} {outcome}" for outcome, count in tally.items() if outcome not in ("imported", "skipped")]
        return ", ".join(parts)

    # ----------------------------------------------------------------------- NAT

    def _translation(self, node: ET.Element, default: str) -> str:
        """What an outbound rule translates to: an address, a table or the interface's own."""
        target = _text(node, "target") or _text(node, "targetip")
        if not target:
            return default
        bits = _text(node, "targetip_subnet")
        if _literal(target) and "/" not in target and bits.isdigit() and int(bits) < 32:
            return _literal(f"{target}/{bits}")
        found = self._one_address(target)
        if found == "any" or found.endswith(":network)"):
            raise _Unmappable(f"{_comment(target, 40)!r} is not an address to translate to")
        return found

    def _one_port(self, value: str) -> str:
        """A single port, or nothing; a port alias counts if it holds just one."""
        alias = self.aliases.get(value.strip())
        found = self.alias_ports(value.strip()) if alias is not None and alias.kind == "ports" else _words(self.ports(value).strip("{ }"))
        if len(found) > 1 or any(":" in port for port in found):
            raise _Unmappable("it names several ports where PF takes one")
        return found[0] if found else ""

    def _outbound(self, name: str):
        def build(spec: dict) -> str:
            node = spec["node"]
            family, protocols = self.protocol(_text(node, "protocol"), _text(node, "ipprotocol", "inet"))
            with_ports = bool(protocols) and set(protocols) <= {"tcp", "udp"}
            source, _ = self.endpoint(node.find("source"), False)
            destination, _ = self.endpoint(node.find("destination"), False)
            source_port = self.ports(_text(node, "sourceport")) if with_ports else ""
            destination_port = self.ports(_text(node, "dstport")) if with_ports else ""
            parts = ["pass out quick" if _isset(node, "nonat") else "match out", "on", name]
            parts += [family] if family else []
            parts += ["proto", _braces(protocols)] if protocols else []
            parts += ["from", source] + (["port", source_port] if source_port else [])
            parts += ["to", destination] + (["port", destination_port] if destination_port else [])
            if _isset(node, "nonat"):
                return " ".join(parts)
            parts += ["nat-to", self._translation(node, f"({name})")]
            fixed = self._one_port(_text(node, "natport")) if with_ports else ""
            if fixed:
                parts += ["port", fixed]
            if _isset(node, "staticnatport"):
                parts.append("static-port")
            return " ".join(parts)

        return build

    def _forward(self, name: str):
        def build(spec: dict) -> str:
            node = spec["node"]
            if _isset(node, "nordr"):
                raise _Unmappable("it is an exception to a port forward (\"no redirect\"), which PF writes differently")
            family, protocols = self.protocol(_text(node, "protocol"), _text(node, "ipprotocol", "inet"))
            with_ports = bool(protocols) and set(protocols) <= {"tcp", "udp"}
            source, source_port = self.endpoint(node.find("source"), with_ports)
            destination, port = self.endpoint(node.find("destination"), with_ports)
            target = self._one_address(_text(node, "target"))
            if target.startswith("(") or target == "any":
                raise _Unmappable("it has no fixed machine to send to")
            inside = self._one_port(_text(node, "local-port")) if with_ports else ""
            # A rule that passes by itself, or one that only redirects and
            # leaves passing to the filter rule OPNsense kept beside it.
            parts = ["pass in quick" if _text(node, "associated-rule-id") == "pass" else "match in"]
            parts += ["log"] if _isset(node, "log") else []
            parts += ["on", name] + ([family] if family else [])
            parts += ["proto", _braces(protocols)] if protocols else []
            parts += ["from", source] + (["port", source_port] if source_port else [])
            parts += ["to", destination] + (["port", port] if port else [])
            parts += ["rdr-to", target]
            if inside and ":" in port and not port.startswith(("{", "$")):
                # A range of ports is sent to as many, starting at this one.
                parts += [] if port.split(":")[0] == inside else ["port", f"{inside}:*"]
            elif inside:
                parts += ["port", inside]
            return " ".join(parts)

        return build

    def _one_to_one(self, name: str):
        def build(spec: dict) -> str:
            node = spec["node"]
            outside = _literal(_text(node, "external"))
            inside, _ = self.endpoint(node.find("source"), False) if node.find("source") is not None else (_literal(_text(node, "internal")) or "", "")
            destination, _ = self.endpoint(node.find("destination"), False)
            if not outside or not _literal(inside) or ":" in outside + inside:
                raise _Unmappable("its inside and outside are not both plain IPv4 addresses or networks")
            if "/" in inside and "/" not in outside:
                outside = _literal(f"{outside}/{inside.split('/')[1]}")
            return f"match on {name} inet from {inside} to {destination} binat-to {outside}"

        return build

    @staticmethod
    def _refuse(reason: str):
        def build(spec: dict) -> str:
            raise _Unmappable(reason)

        return build

    def nat_lines(self) -> list[str]:
        lines: list[str] = []
        tally: dict[str, int] = {}

        def add(node: ET.Element, kind: str, builder) -> None:
            comment, interface = _comment(_text(node, "descr")), _text(node, "interface")
            spec = {
                "area": "NAT", "what": self._what(kind, node, comment, interface), "node": node,
                "comment": comment, "disabled": _isset(node, "disabled"),
            }  # fmt: skip
            try:
                builds = [builder(name) for name in self.devices(interface)] or [self._refuse("it names no interface")]
            except _Unmappable as why:
                builds = [self._refuse(str(why))]
            for build in builds:
                outcome = self._emit(lines, spec, build)
                tally[outcome] = tally.get(outcome, 0) + 1

        for node in self.config.findall("nat/onetoone"):
            add(node, "one-to-one NAT rule", self._one_to_one)
        for node in self.config.findall("nat/rule"):
            add(node, "port forward", self._forward)
            if _text(node, "natreflection") in ("enable", "purenat"):
                self.note("NAT", f"The port forward \"{_comment(_text(node, 'descr'))}\" was also reachable from inside by the outside address (NAT reflection). That is not imported.")

        mode = _text(self.config, "nat/outbound/mode", "automatic")
        if mode in ("hybrid", "advanced"):
            for node in self.config.findall("nat/outbound/rule"):
                add(node, "outbound NAT rule", self._outbound)
        if mode in ("automatic", "hybrid"):
            # What OPNsense works out by itself: every inside network leaves
            # by every outside interface under that interface's address.
            for outside in (entry for entry in self.interfaces.values() if entry.name and entry.uplink):
                for entry in self.interfaces.values():
                    if entry.name and entry.address and not entry.uplink:
                        lines.append(f"match out on {outside.name} inet from ({entry.name}:network) to any nat-to ({outside.name})  # {entry.label} to {outside.label}, as OPNsense did automatically")
                        tally["imported"] = tally.get("imported", 0) + 1
        elif mode == "disabled":
            self.note("NAT", "Outbound NAT was switched off in OPNsense, so none is written.")
        self.counts[NAT_FILE] = self._tally(tally, "rule")
        if not lines:
            return []
        return [
            MARKER,
            "# One-to-one NAT, port forwards, then outbound NAT. A port forward written as",
            '# "match" only redirects: the filter rule OPNsense kept beside it, in',
            "# firewall/40-opnsense.conf, is what lets the connection in.",
            "",
            *lines,
        ]

    # ----------------------------------------------------------------------- DNS

    def _name(self, host: str, domain: str) -> str:
        """A full name with its closing dot, or nothing if it is not one."""
        name = ".".join(part for part in (host.strip().strip("."), domain.strip().strip(".")) if part)
        return name.lower() + "." if _DOMAIN.match(name) else ""

    def dns_lines(self) -> list[str]:
        new = self.config.find("OPNsense/unboundplus")
        old = self.config.find("unbound")
        masq = self.config.find("dnsmasq")
        unbound = _on(new, "general/enabled") if _text(new, "general/enabled") else _isset(old, "enable")
        dnsmasq = _isset(masq, "enable") and _text(masq, "port", "53") != "0" and not unbound
        if not unbound and not dnsmasq:
            return []
        general = new.find("general") if new is not None else None
        servers = [str(_ip4(value)) for value in _texts(self.config, "system/dnsserver") if _ip4(value)]

        port = _text(general, "port") or _text(old, "port")
        if unbound and port not in ("", "53"):
            self.note("DNS", f"Unbound answered on port {port} in OPNsense. Here it answers on 53, the port DHCP clients are sent to.")
        if _on(new, "dnsbl/enabled") or _texts(new, "dnsbl/blocklist/enabled") == ["1"]:
            self.note("DNS", "Unbound's blocklists are downloaded by OPNsense itself, and are not imported.")

        # Where it listens: the inside interfaces OPNsense named, or all of them.
        wanted = _words(_text(general, "active_interface") or _text(old, "active_interface")) if unbound else _words(_text(masq, "interface"))
        listen: list[Interface] = []
        for entry in self.interfaces.values():
            if not entry.name or (wanted and entry.key not in wanted) or (not wanted and entry.uplink):
                continue
            if entry.address:
                listen.append(entry)
            elif wanted:
                self.note("DNS", f"The resolver listened on {entry.label}, whose address is not fixed. It cannot be told to listen there.")

        self.listening = {entry.key for entry in listen}
        data: list[str] = []
        pointers: dict[str, str] = {}
        zones: dict[str, str] = {}

        def record(name: str, kind: str, value: str, pointer: bool = True) -> None:
            if not name:
                return
            if name.startswith("*."):
                zones[name[2:]] = "redirect"
                name = name[2:]
            line = f'local-data: "{name} IN {kind} {value}"'
            if line not in data:
                data.append(line)
            if pointer and kind in ("A", "AAAA") and value not in pointers and zones.get(name) != "redirect":
                pointers[value] = name

        def host(name: str, domain: str, kind: str, value: str, priority: str = "", exchange: str = "") -> list[str]:
            """Adds one host override, and returns its addresses for its aliases."""
            full = "*." + self._name("", domain) if name == "*" and self._name("", domain) else self._name(name, domain)
            if not full:
                self.note("DNS", f"The host override {_comment(name + '.' + domain, 60)!r} is not a name, and was left out.")
                return []
            if kind.upper() == "MX":
                target = self._name(exchange, "")
                if target and priority.isdigit():
                    record(full, "MX", f"{int(priority)} {target}")
                return []
            found = []
            for item in _words(value):
                try:
                    address = ipaddress.ip_address(item)
                except ValueError:
                    self.note("DNS", f"The host override {full} points at {_comment(item, 40)!r}, which is not an address, and was left out.")
                    continue
                record(full, "A" if address.version == 4 else "AAAA", str(address))
                found.append(str(address))
            return found

        forwards: dict[tuple[str, bool], list[str]] = {}

        def forward(domain: str, server: str, port: str = "", tls: bool = False, verify: str = "") -> None:
            zone = self._name("", domain) if domain.strip(". ") else "."
            target, _, extra = server.partition("@")
            port = port or extra
            try:
                address = str(ipaddress.ip_address(target.strip()))
            except ValueError:
                address = ""
            if not zone or not address or (port and not port.isdigit()) or (verify and not _DOMAIN.match(verify)):
                self.note("DNS", f"The forwarding of {_comment(domain, 40) or 'everything'} to {_comment(server, 40)!r} is not an address, and was left out.")
                return
            text = address + (f"@{int(port)}" if port else "@853" if tls and verify else "") + (f"#{verify}" if tls and verify else "")
            forwards.setdefault((zone, tls), [])
            if text not in forwards[(zone, tls)]:
                forwards[(zone, tls)].append(text)

        if unbound:
            by_id: dict[str, tuple[str, list[str]]] = {}
            for node in new.findall("hosts/host") if new is not None else []:
                if _on(node, "enabled", "1"):
                    found = host(_text(node, "hostname"), _text(node, "domain"), _text(node, "rr", "A"), _text(node, "server"), _text(node, "mxprio"), _text(node, "mx"))
                    by_id[node.get("uuid", "")] = (_text(node, "domain"), found)
            for node in new.findall("aliases/alias") if new is not None else []:
                domain, found = by_id.get(_text(node, "host"), ("", []))
                if _on(node, "enabled", "1") and found:
                    host(_text(node, "hostname"), _text(node, "domain") or domain, "A", " ".join(found))
            for node in new.findall("domains/domain") if new is not None else []:
                if _on(node, "enabled", "1"):
                    forward(_text(node, "domain"), _text(node, "server"))
            for node in new.findall("dots/dot") if new is not None else []:
                if _on(node, "enabled", "1"):
                    forward(_text(node, "domain"), _text(node, "server"), _text(node, "port"), _text(node, "type", "dot") == "dot", _text(node, "verify"))
            if _on(new, "forwarding/enabled") or (new is None and _isset(old, "forwarding")):
                for server in servers:
                    forward("", server)
                if not servers:
                    self.note("DNS", "Unbound forwarded to the DNS servers of the connection, which are not in the backup. Here it resolves by itself instead.")
        legacy = old if unbound else masq
        for node in legacy.findall("hosts") if legacy is not None else []:
            if node.find("host") is None and node.find("ip") is None:
                continue
            found = host(_text(node, "host"), _text(node, "domain"), _text(node, "rr", "A"), _text(node, "ip"), _text(node, "mxprio"), _text(node, "mx"))
            for item in node.findall("aliases/item"):
                if found:
                    host(_text(item, "host"), _text(item, "domain") or _text(node, "domain"), "A", " ".join(found))
        for node in legacy.findall("domainoverrides") if legacy is not None else []:
            if _text(node, "domain"):
                forward(_text(node, "domain"), _text(node, "ip"))
        if dnsmasq:
            self.note("DNS", "OPNsense answered DNS with dnsmasq. Its host and domain overrides are imported for Unbound, which is what OpenBSD comes with.")
            for server in servers:
                forward("", server)

        # The firewall's own name, and the fixed DHCP addresses if OPNsense
        # put those in the DNS as well.
        own = self._name(_text(self.config, "system/hostname"), self.domain)
        for entry in listen:
            record(own, "A", str(entry.address.ip))
        if unbound and (_on(general, "regdhcpstatic") or _isset(old, "regdhcpstatic")):
            for name, address in self.fixed_names:
                record(name, "A", address)

        local = self._name("", self.domain)
        if local and any(line.split('"')[1].split(" ")[0].endswith(local) for line in data):
            kind = _text(general, "local_zone_type")
            zones.setdefault(local, kind if kind in ("static", "typetransparent", "refuse", "deny") else "transparent")

        lines = [
            MARKER,
            "# The resolver: Unbound, installed as /var/unbound/etc/unbound.conf.",
            "server:",
            "\tinterface: 127.0.0.1",
            *(f"\tinterface: {entry.address.ip}  # {entry.label}" for entry in listen),
            "\taccess-control: 127.0.0.0/8 allow",
            *(f"\taccess-control: {entry.address.network} allow  # {entry.label}" for entry in listen),
        ]
        for node in new.findall("acls/acl") if unbound and new is not None else []:
            action = _text(node, "action")
            if _on(node, "enabled", "1") and action in ("allow", "deny", "refuse", "allow_snoop", "deny_non_local", "refuse_non_local"):
                for network in _words(_text(node, "networks")):
                    if _literal(network):
                        lines.append(f"\taccess-control: {_literal(network)} {action}  # {_comment(_text(node, 'name'), 40)}")
        lines += ["\tdo-ip6: no", "\thide-identity: yes", "\thide-version: yes"]
        if unbound and (_on(general, "dnssec") or _isset(old, "dnssec")):
            lines.append('\tauto-trust-anchor-file: "/var/unbound/db/root.key"')
        if any(tls for _, tls in forwards):
            lines.append('\ttls-cert-bundle: "/etc/ssl/cert.pem"')
        for (zone, _), _targets in forwards.items():
            # Unbound answers for private reverse zones itself unless told not to.
            if zone.endswith(("in-addr.arpa.", "ip6.arpa.")):
                lines.append(f'\tlocal-zone: "{zone}" nodefault')
            elif zone != ".":
                lines += [f'\tprivate-domain: "{zone}"', f'\tdomain-insecure: "{zone}"']
        lines += [f'\tlocal-zone: "{zone}" {kind}' for zone, kind in zones.items()]
        lines += ["\t" + line for line in data]
        lines += [f'\tlocal-data-ptr: "{address} {name}"' for address, name in pointers.items()]
        for (zone, tls), targets in forwards.items():
            lines += ["", "forward-zone:", f'\tname: "{zone}"']
            lines += ["\tforward-tls-upstream: yes"] if tls else []
            lines += [f"\tforward-addr: {target}" for target in targets]
        if not listen:
            self.note("DNS", "The resolver has no inside interface with a fixed address to listen on, so only the firewall itself can ask it.")
        self.counts[rules.DNS_FILE] = f"{len(data)} name{'' if len(data) == 1 else 's'}, {len(forwards)} forwarded zone{'' if len(forwards) == 1 else 's'}"
        return lines

    # ---------------------------------------------------------------------- DHCP

    def read_dhcp(self) -> None:
        """Collects every DHCP network and fixed address, whichever server held it."""
        self.subnets: dict[str, dict] = {}
        self.fixed: list[tuple[str, str, str, str]] = []  # interface, name, MAC, address
        self.fixed_names: list[tuple[str, str]] = []

        def subnet(key: str, source: str) -> dict | None:
            entry = self.interfaces.get(key)
            if entry is None or not entry.name or entry.address is None:
                label = entry.label if entry else key
                self.note("DHCP", f"The {source} DHCP network on {label} is not imported: that interface has no fixed address here.")
                return None
            if key in self.subnets:
                self.note("DHCP", f"{entry.label} has a DHCP network in more than one of OPNsense's servers. The first is used; the one from {source} is left out.")
                return None
            self.subnets[key] = {"ranges": [], "routers": "", "dns": [], "domain": "", "ntp": [], "times": {}}
            return self.subnets[key]

        def spread(found: dict, key: str, first: str, last: str) -> None:
            network = self.interfaces[key].address.network
            start, end = _ip4(first), _ip4(last)
            if start and end and start in network and end in network and start <= end:
                found["ranges"].append((str(start), str(end)))
            elif first or last:
                self.note("DHCP", f"{self.interfaces[key].label}: the range {_comment(first, 20)} to {_comment(last, 20)} is not inside {network}, and was left out.")

        def fixed(key: str, name: str, mac: str, address: str, domain: str = "") -> None:
            if not _MAC.match(mac) or not _ip4(address):
                if _MAC.match(mac):
                    self.note("DHCP", f"The device {mac.lower()} ({_comment(name, 30) or 'no name'}) was known to OPNsense but had no fixed address. There is nothing to import for it.")
                return
            self.fixed.append((key, name, mac.lower(), str(_ip4(address))))
            full = self._name(name, domain or self.domain) if _HOST.match(name) else ""
            if full:
                self.fixed_names.append((full, str(_ip4(address))))

        section = self.config.find("dhcpd")
        for node in section if section is not None else []:
            if not _isset(node, "enable"):
                continue
            found = subnet(node.tag, "ISC")
            if found is None:
                continue
            for part in [node, *node.findall("pool")]:
                spread(found, node.tag, _text(part, "range/from"), _text(part, "range/to"))
            found.update(routers=_text(node, "gateway"), dns=_texts(node, "dnsserver"), domain=_text(node, "domain"), ntp=_texts(node, "ntpserver"))
            found["times"] = {"default-lease-time": _text(node, "defaultleasetime"), "max-lease-time": _text(node, "maxleasetime")}
            for item in node.findall("staticmap"):
                fixed(node.tag, _text(item, "hostname"), _text(item, "mac"), _text(item, "ipaddr"), _text(node, "domain"))

        kea = self.config.find("OPNsense/Kea/dhcp4")
        if _on(kea, "general/enabled"):
            by_id: dict[str, str] = {}
            for node in kea.findall("subnets/subnet4"):
                network = _literal(_text(node, "subnet"))
                key = next((key for key, entry in self.interfaces.items() if entry.name and entry.address and str(entry.address.network) == network), "")
                found = subnet(key, "Kea") if key else None
                if found is None:
                    if not key:
                        self.note("DHCP", f"The Kea network {_comment(_text(node, 'subnet'), 30)} is not imported: no interface has an address in it.")
                    continue
                by_id[node.get("uuid", "")] = key
                for pool in re.split(r"[\n,]+", _text(node, "pools")):
                    first, dash, last = pool.partition("-")
                    if not dash and _literal(pool.strip()) and "/" in pool:
                        hosts = ipaddress.ip_network(pool.strip(), strict=False)
                        first, last = str(hosts.network_address + 1), str(hosts.broadcast_address - 1)
                    if pool.strip():
                        spread(found, key, first.strip(), last.strip())
                found.update(routers=_text(node, "option_data/routers"), dns=_words(_text(node, "option_data/domain_name_servers")), domain=_text(node, "option_data/domain_name"), ntp=_words(_text(node, "option_data/ntp_servers")))
            for node in kea.findall("reservations/reservation"):
                key = by_id.get(_text(node, "subnet"), "")
                if key:
                    fixed(key, _text(node, "hostname"), _text(node, "hw_address").replace("-", ":"), _text(node, "ip_address"))

        masq = self.config.find("dnsmasq")
        if _isset(masq, "enable"):
            for node in masq.findall("dhcp_ranges"):
                if ":" in _text(node, "start_addr"):
                    continue
                found = subnet(_text(node, "interface"), "dnsmasq")
                if found is not None:
                    spread(found, _text(node, "interface"), _text(node, "start_addr"), _text(node, "end_addr"))
                    found["domain"] = _text(node, "domain")
            for node in masq.findall("hosts"):
                address = next((_ip4(item) for item in _words(_text(node, "ip")) if _ip4(item)), None)
                mac = next(iter(_words(_text(node, "hwaddr"))), "")
                key = next((key for key in self.subnets if address and address in self.interfaces[key].address.network), "")
                if key and mac:
                    fixed(key, _text(node, "host"), mac, str(address), _text(node, "domain"))
            if masq.find("dhcp_options") is not None and self.subnets:
                self.note("DHCP", "dnsmasq's DHCP options are not imported. Clients are sent the firewall as their router, and the DNS servers described below.")

    def dhcp_lines(self) -> list[str]:
        lines: list[str] = []
        servers = [str(_ip4(value)) for value in _texts(self.config, "system/dnsserver") if _ip4(value)]
        for key, found in self.subnets.items():
            entry = self.interfaces[key]
            network = entry.address.network
            parts = [f"range {first} {last};" for first, last in found["ranges"]]
            if found["routers"].lower() != "none":
                router = _ip4(found["routers"]) or entry.address.ip
                parts.append(f"option routers {router};")
            # What OPNsense hands out unless told otherwise: itself when it
            # runs a resolver, and the servers it uses itself when not.
            dns = [str(_ip4(value)) for value in found["dns"] if _ip4(value)]
            dns = dns or ([str(entry.address.ip)] if key in self.listening else servers)
            if dns:
                parts.append(f"option domain-name-servers {', '.join(dns)};")
            else:
                self.note("DHCP", f"{entry.label}: no DNS server is known to hand out. Add \"option domain-name-servers\" to its line in dhcp/dhcpd.conf.")
            domain = next((name for name in (found["domain"], self.domain) if _DOMAIN.match(name)), "")
            if domain:
                parts.append(f'option domain-name "{domain.lower()}";')
            ntp = [str(_ip4(value)) for value in found["ntp"] if _ip4(value)]
            if ntp:
                parts.append(f"option ntp-servers {', '.join(ntp)};")
            parts += [f"{name} {int(value)};" for name, value in found["times"].items() if value.isdigit()]
            if not found["ranges"]:
                self.note("DHCP", f"{entry.label} has no range of addresses to hand out, only fixed ones.")
            lines.append(f"subnet {network.network_address} netmask {network.netmask} {{ {' '.join(parts)} }}  # {entry.label}")

        names: set[str] = set()
        count = 0
        for key, name, mac, address in self.fixed:
            entry = self.interfaces[key]
            if key not in self.subnets or ipaddress.IPv4Address(address) not in entry.address.network:
                self.note("DHCP", f"The fixed address {address} for {mac} is outside the network of {entry.label}, and was left out.")
                continue
            name = name if _HOST.match(name) else "host-" + mac.replace(":", "")
            unique, number = name, 1
            while unique.lower() in names:
                number += 1
                unique = f"{name}-{number}"
            names.add(unique.lower())
            lines.append(f"host {unique} {{ hardware ethernet {mac}; fixed-address {address}; }}")
            count += 1
        if lines:
            self.counts[rules.DHCP_FILE] = f"{len(self.subnets)} network{'' if len(self.subnets) == 1 else 's'}, {count} fixed address{'' if count == 1 else 'es'}"
        return lines

    # ---------------------------------------------------------------- everything

    def run(self) -> dict[Path, list[str]]:
        """Every file the import produces, by path, without the parts kept by hand."""
        self.domain = _text(self.config, "system/domain")
        self.read_interfaces()
        self.read_gateways()
        self.read_aliases()
        files = self.network_files()
        self.read_dhcp()
        produced = {
            ALIASES_FILE: self.alias_lines(),
            # The resolver first: what DHCP hands out depends on there being one.
            rules.DNS_FILE: self.dns_lines(),
            rules.DHCP_FILE: self.dhcp_lines(),
            NAT_FILE: self.nat_lines(),
            RULES_FILE: self.rule_lines(),
        }
        files.update({path: lines for path, lines in produced.items() if lines})
        for path, what in _OTHER:
            if self.config.find(path) is not None and (len(self.config.find(path)) or _text(self.config, path)):
                self.note("Left in OPNsense", f"{what[0].upper() + what[1:]}: not imported.")
        if self.guessed:
            self.note("Interfaces", f"The driver of {', '.join(self.guessed)} is not one this importer knows, so the name was kept. OpenBSD very likely calls it something else.")
        if not any(entry.name for entry in self.interfaces.values()):
            raise ImportFailed("The backup holds no interface that can be imported.")
        return files

    def report(self, written: dict[Path, list[str]], removed: list[Path], dry_run: bool) -> str:
        name = ".".join(part for part in (_text(self.config, "system/hostname"), self.domain) if part)
        out = [f"OPNsense backup of {_comment(name, 80) or 'an unnamed firewall'}", "", "Interfaces"]
        rows = [(entry.label, entry.key, entry.device, entry.name or "-", entry.summary) for entry in self.interfaces.values()]
        widths = [max(len(row[column]) for row in rows) for column in range(4)]
        for row in rows:
            out.append("  " + "  ".join(cell.ljust(width) for cell, width in zip(row, widths)) + "  " + row[4])
        out += [
            "",
            "  The fourth column is the name the import gave each port on OpenBSD. It is a",
            "  guess from the driver: compare it with `ifconfig` on the OpenBSD machine, and",
            "  import again with, for example, --map igb0=em2 where it is wrong.",
            "",
            "Would write" if dry_run else "Written",
        ]
        width = max(len(str(path)) for path in written)
        for path in sorted(written):
            out.append(f"  {str(path).ljust(width)}  {self.counts.get(path, '')}".rstrip())
        out += [f"  {str(path).ljust(width)}  removed: an earlier import wrote it, this one does not" for path in removed]
        for area in ("Interfaces", "Routing", "Aliases", "Firewall rules", "NAT", "DHCP", "DNS", "Left in OPNsense"):
            if self.notes.get(area):
                out += ["", f"{area}: not imported, or to check"]
                out += [f"  - {message}" for message in self.notes[area]]
        out += [
            "",
            "Before you deploy",
            "  - firewall/30-rules.conf is yours and was not touched. Its \"block all\" is what",
            "    drops everything the imported rules do not pass. It also lets SSH and ping in",
            "    from anywhere, which OPNsense did not; narrow those once the deployment works.",
            "  - The interface files replace what the OpenBSD machine has now, including the",
            "    port the deployment arrives on. If that cuts the deployment off, the firewall",
            "    puts back what it had.",
            "  - Read ./fw assemble and ./fw assemble-network, run ./fw check, then commit.",
        ]
        return "\n".join(out) + "\n"


# ------------------------------------------------------------------ the files


def parse(data: bytes) -> ET.Element:
    if data.lstrip().startswith(b"---- BEGIN config.xml ----"):
        raise ImportFailed("This backup is encrypted. Download it from OPNsense again without a password.")
    # A backup has no use for a DOCTYPE; one could make the parser grow a
    # small file into gigabytes.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ImportFailed("This is not an OPNsense backup: it declares a DOCTYPE.")
    try:
        config = ET.fromstring(data)
    except ET.ParseError as problem:
        raise ImportFailed(f"This is not an XML file OPNsense wrote: {problem}") from None
    if config.tag == "pfsense":
        raise ImportFailed("This is a pfSense backup. Only OPNsense backups are read.")
    if config.tag != "opnsense":
        raise ImportFailed("This is not an OPNsense backup: it does not start with <opnsense>.")
    return config


def _ours(path: Path) -> bool:
    lines = rules.read_lines(path)
    return bool(lines) and lines[0] == MARKER


def _with_dhcp(existing: list[str], imported: list[str]) -> list[str]:
    """dhcpd.conf with the imported part put in, or replaced, or taken out."""
    if DHCP_BEGIN in existing and DHCP_END in existing[existing.index(DHCP_BEGIN) :]:
        start = existing.index(DHCP_BEGIN)
        end = existing.index(DHCP_END, start)
        existing = existing[:start] + existing[end + 1 :]
        while existing and not existing[-1].strip():
            existing = existing[:-1]
    if not imported:
        return existing
    return [*existing, *([""] if existing else []), DHCP_BEGIN, *imported, DHCP_END]


def plan(root: Path, data: bytes, device_map: dict[str, str] | None = None, force: bool = False, dry_run: bool = False) -> Result:
    """Works out every file an import would write, without writing any."""
    try:
        ssh_port = int(json.loads((root / "firewall.json").read_text()).get("port", 22))
    except (OSError, ValueError, AttributeError):
        ssh_port = 22
    importer = Importer(parse(data), device_map, ssh_port)
    files = importer.run()

    # The two files shared with the editor keep what is in them already.
    dhcp = rules.read_lines(root / rules.DHCP_FILE)
    merged = _with_dhcp(dhcp, files.pop(rules.DHCP_FILE, []))
    if merged != dhcp:
        files[rules.DHCP_FILE] = merged
        outside = _with_dhcp(dhcp, [])
        if rules.DHCP_FILE in importer.counts and any(rules.is_rule(line) for line in outside):
            importer.note("DHCP", "dhcp/dhcpd.conf already held networks or fixed addresses. They are kept; make sure they do not repeat what was imported.")
    sysctl = rules.read_lines(root / rules.SYSCTL_FILE)
    if not rules.routing_is_on(root):
        files[rules.SYSCTL_FILE] = rules.with_routing(sysctl, True)
        importer.counts[rules.SYSCTL_FILE] = "routing switched on"

    whole = [path for path in files if path not in (rules.DHCP_FILE, rules.SYSCTL_FILE)]
    kept = [
        path
        for path in whole
        if (root / path).exists() and not _ours(root / path)
        # A file that is only comments, as this repository starts with, is nobody's work.
        and (path.name.startswith("hostname.") or any(rules.is_rule(line) for line in rules.read_lines(root / path)))
    ]  # fmt: skip
    if kept and not force:
        raise ImportFailed(
            "These files exist and were not written by an import:\n"
            + "".join(f"  {path}\n" for path in sorted(kept))
            + "Move them away, or replace them with --force."
        )
    candidates = [ALIASES_FILE, NAT_FILE, RULES_FILE, rules.DNS_FILE, rules.NETWORK_FOLDER / "mygate"]
    candidates += [path.relative_to(root) for path in sorted((root / rules.NETWORK_FOLDER).glob("hostname.*"))]
    removed = [path for path in candidates if path not in files and _ours(root / path)]
    return Result(files, removed, importer.report(files, removed, dry_run))


def write(root: Path, result: Result) -> None:
    for path, lines in result.files.items():
        rules.write_lines(root / path, lines)
    for path in result.removed:
        (root / path).unlink()
