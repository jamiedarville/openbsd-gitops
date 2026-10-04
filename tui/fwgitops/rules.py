"""Builds and edits the text files that make up the firewall configuration.

The files in the repository are the source of truth and are meant to be read
and edited by hand as well. Nothing here parses PF syntax: a file is treated as
a list of lines, and the builders only ever produce one new line.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

# The folders whose *.conf files are joined, in file-name order, into pf.conf.
PF_FOLDERS = ("firewall", "nat")
RULES_FILE = Path("firewall/30-rules.conf")
NAT_FILE = Path("nat/20-nat.conf")
DHCP_FILE = Path("dhcp/dhcpd.conf")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,30}$")
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,14}$")
_PORT = re.compile(r"^\d{1,5}(:\d{1,5})?$")
_MAC = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class InvalidInput(ValueError):
    """Raised with a message that can be shown to the person typing."""


# ---------------------------------------------------------------- field checks


def check_interface(value: str) -> str:
    value = value.strip()
    if value and not _INTERFACE.match(value):
        raise InvalidInput("An interface looks like em0, vio0 or egress")
    return value


def check_address(value: str) -> str:
    """Accepts any, an IP address, a network, a <table>, or an interface in
    brackets such as (egress)."""
    value = value.strip()
    if value in ("", "any"):
        return "any"
    if value.startswith("<") and value.endswith(">"):
        if not _NAME.match(value[1:-1]):
            raise InvalidInput("A table is written like <admins>")
        return value
    if value.startswith("(") and value.endswith(")"):
        if not _INTERFACE.match(value[1:-1]):
            raise InvalidInput("An interface address is written like (egress)")
        return value
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise InvalidInput(
            "Enter any, an address like 192.0.2.10, a network like 10.0.0.0/8, "
            "a table like <admins>, or (interface)"
        ) from None


def check_ports(value: str) -> list[str]:
    ports = [part for part in re.split(r"[\s,]+", value.strip()) if part]
    for port in ports:
        if not _PORT.match(port) or any(
            not 1 <= int(number) <= 65535 for number in port.split(":")
        ):
            raise InvalidInput("Ports look like 22, or 80 443, or 8000:8010")
    return ports


def check_comment(value: str) -> str:
    value = " ".join(value.split())
    if "\n" in value or len(value) > 120:
        raise InvalidInput("Keep the description to one short line")
    # PF joins a line ending in a backslash onto the next one, even inside a
    # comment, which would silently turn the next rule into part of the comment.
    if value.endswith("\\"):
        raise InvalidInput("The description cannot end with a backslash")
    return value


def _ip4(value: str, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        raise InvalidInput(f"{what} must be an IPv4 address like 192.168.1.1") from None


# -------------------------------------------------------------- line builders


def _with_comment(line: str, comment: str) -> str:
    comment = check_comment(comment)
    return f"{line}  # {comment}" if comment else line


def _port_clause(ports: list[str]) -> str:
    if not ports:
        return ""
    return f" port {ports[0]}" if len(ports) == 1 else " port { " + ", ".join(ports) + " }"


@dataclass
class FilterRule:
    action: str = "pass"  # pass | block
    direction: str = "in"  # in | out | both
    interface: str = ""
    protocol: str = "tcp"  # any | tcp | udp | icmp | icmp6
    source: str = "any"
    destination: str = "any"
    ports: str = ""
    log: bool = False
    quick: bool = False
    comment: str = ""

    def render(self) -> str:
        if self.action not in ("pass", "block"):
            raise InvalidInput("The action is pass or block")
        if self.direction not in ("in", "out", "both"):
            raise InvalidInput("The direction is in, out or both")
        if self.protocol not in ("any", "tcp", "udp", "icmp", "icmp6"):
            raise InvalidInput("Unknown protocol")
        ports = check_ports(self.ports)
        if ports and self.protocol not in ("tcp", "udp"):
            raise InvalidInput("Ports only apply to TCP and UDP")

        parts = [self.action]
        if self.direction != "both":
            parts.append(self.direction)
        if self.log:
            parts.append("log")
        if self.quick:
            parts.append("quick")
        interface = check_interface(self.interface)
        if interface:
            parts += ["on", interface]
        if self.protocol != "any":
            parts += ["proto", self.protocol]
        parts += ["from", check_address(self.source)]
        parts += ["to", check_address(self.destination) + _port_clause(ports)]
        return _with_comment(" ".join(parts), self.comment)


def outbound_nat(interface: str, source: str, comment: str = "") -> str:
    """Hides a network behind the firewall's address on the given interface."""
    interface = check_interface(interface)
    if not interface:
        raise InvalidInput("Outbound NAT needs the outside interface, such as egress")
    source = check_address(source)
    if source == "any":
        raise InvalidInput("Give the inside network to translate, such as 192.168.10.0/24")
    return _with_comment(
        f"match out on {interface} inet from {source} to any nat-to ({interface})", comment
    )


def port_forward(
    interface: str, protocol: str, port: str, target: str, target_port: str = "", comment: str = ""
) -> str:
    """Sends connections arriving on a port to a machine inside."""
    interface = check_interface(interface)
    if not interface:
        raise InvalidInput("A port forward needs the outside interface, such as egress")
    if protocol not in ("tcp", "udp"):
        raise InvalidInput("A port forward is TCP or UDP")
    ports = check_ports(port)
    if len(ports) != 1:
        raise InvalidInput("Enter exactly one port or range to forward")
    inside = _ip4(target, "The inside machine")
    inside_ports = check_ports(target_port)
    if len(inside_ports) > 1:
        raise InvalidInput("Enter at most one inside port")
    suffix = f" port {inside_ports[0]}" if inside_ports else ""
    return _with_comment(
        f"pass in on {interface} inet proto {protocol} from any to ({interface}) "
        f"port {ports[0]} rdr-to {inside}{suffix}",
        comment,
    )


def dhcp_subnet(network: str, first: str, last: str, router: str, dns: str) -> str:
    try:
        subnet = ipaddress.ip_network(network.strip(), strict=True)
    except ValueError:
        raise InvalidInput("The network looks like 192.168.10.0/24") from None
    if subnet.version != 4:
        raise InvalidInput("dhcpd serves IPv4 networks")
    start, end, gateway = _ip4(first, "The first address"), _ip4(last, "The last address"), _ip4(router, "The router")
    for address, what in ((start, "first address"), (end, "last address"), (gateway, "router")):
        if ipaddress.IPv4Address(address) not in subnet:
            raise InvalidInput(f"The {what} is not inside {subnet}")
    if ipaddress.IPv4Address(start) > ipaddress.IPv4Address(end):
        raise InvalidInput("The first address comes after the last")
    servers = [_ip4(server, "A DNS server") for server in re.split(r"[\s,]+", dns.strip()) if server]
    if not servers:
        raise InvalidInput("Give at least one DNS server")
    return (
        f"subnet {subnet.network_address} netmask {subnet.netmask} {{ "
        f"range {start} {end}; option routers {gateway}; "
        f"option domain-name-servers {', '.join(servers)}; }}"
    )


def dhcp_static_lease(name: str, mac: str, address: str) -> str:
    name = name.strip()
    if not _HOSTNAME.match(name):
        raise InvalidInput("The name may use letters, digits and hyphens")
    if not _MAC.match(mac.strip()):
        raise InvalidInput("A MAC address looks like 00:11:22:33:44:55")
    return (
        f"host {name} {{ hardware ethernet {mac.strip().lower()}; "
        f"fixed-address {_ip4(address, 'The address')}; }}"
    )


# ------------------------------------------------------------------ the files


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text().splitlines()


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n" if lines else "")


def is_rule(line: str) -> bool:
    """True for a line that does something, as opposed to a comment or blank."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def _check_line(line: str) -> str:
    if "\n" in line:
        raise InvalidInput("A rule is a single line")
    # A rule may be continued with a backslash, but a comment that ends in one
    # swallows the line after it.
    if "#" in line and line.rstrip().endswith("\\"):
        raise InvalidInput("A comment cannot end with a backslash: PF would make the next line part of it")
    return line


def add_line(lines: list[str], line: str) -> list[str]:
    return [*lines, _check_line(line)]


def delete_line(lines: list[str], index: int) -> list[str]:
    return [line for position, line in enumerate(lines) if position != index]


def move_line(lines: list[str], index: int, offset: int) -> tuple[list[str], int]:
    """Moves a line up or down and returns the new list and the line's new index."""
    target = index + offset
    if not 0 <= target < len(lines):
        return lines, index
    moved = list(lines)
    moved[index], moved[target] = moved[target], moved[index]
    return moved, target


def replace_line(lines: list[str], index: int, line: str) -> list[str]:
    line = _check_line(line)
    return [line if position == index else existing for position, existing in enumerate(lines)]


def pf_files(root: Path) -> list[Path]:
    """The files that make up pf.conf, in the order they are joined."""
    files = [path for folder in PF_FOLDERS for path in (root / folder).glob("*.conf")]
    return sorted(files, key=lambda path: (path.name, path.parent.name))


def assemble_pf(root: Path) -> str:
    """Joins the pf files exactly as the deployment does."""
    parts = []
    for path in pf_files(root):
        text = path.read_text()
        parts.append(f"# --- {path.relative_to(root)} ---\n{text if text.endswith(chr(10)) else text + chr(10)}")
    return "\n".join(parts)


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def keeps_ssh_open(pf_conf: str) -> bool:
    """A rough check that some rule still lets SSH in.

    It is only a prompt to look twice. The real protection is the firewall's
    own watchdog, which undoes a change that locks the deployment out.
    """
    # Read the lines as PF does: one ending in a backslash runs on into the next.
    for line in pf_conf.replace("\\\n", "").splitlines():
        rule = line.split("#", 1)[0]
        if not re.match(r"\s*pass\b", rule) or re.search(r"\bout\b", rule):
            continue
        if re.search(r"\bport\b", rule) is None:
            # A pass rule with no port lets everything in, SSH included,
            # unless it is limited to a protocol that is not TCP.
            if re.search(r"\bproto\s+(?!tcp\b)\S+", rule) is None:
                return True
            continue
        ports = re.search(r"\bport\s+(\{[^}]*\}|\S+)", rule)
        if ports and re.search(r"(?<![\d:])(22|ssh)(?![\d:])", ports.group(1)):
            return True
    return False
