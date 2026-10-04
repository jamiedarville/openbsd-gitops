"""Talks to the firewall's helper over SSH, and to git.

Only read-only helper operations are used here: `status` and `validate`.
Changing the firewall is the deployment's job, never the editor's.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILE = "firewall.json"
# Per-machine settings that must not be committed: where this machine keeps
# the deployment key and the firewall's pinned host key.
LOCAL_FILE = ".fw-local.json"


class RemoteError(RuntimeError):
    pass


@dataclass
class Firewall:
    name: str
    host: str
    port: int
    user: str
    helper: str
    identity: str
    known_hosts: str

    @property
    def configured(self) -> bool:
        return bool(self.identity and self.known_hosts)


def load_firewall(root: Path) -> Firewall:
    shared = json.loads((root / CONFIG_FILE).read_text())
    local_path = root / LOCAL_FILE
    local = json.loads(local_path.read_text()) if local_path.exists() else {}
    return Firewall(
        name=shared["name"],
        host=shared["host"],
        port=int(shared.get("port", 22)),
        user=shared["user"],
        helper=shared.get("helper", "/usr/local/sbin/fcc-pfctl"),
        identity=os.path.expanduser(os.environ.get("FW_SSH_KEY") or local.get("identity", "")),
        known_hosts=os.path.expanduser(os.environ.get("FW_KNOWN_HOSTS") or local.get("knownHosts", "")),
    )


def ssh_command(firewall: Firewall, *operation: str) -> list[str]:
    return [
        "ssh",
        "-F", "/dev/null",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={firewall.known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ConnectTimeout=10",
        "-p", str(firewall.port),
        "-i", firewall.identity,
        "--", f"{firewall.user}@{firewall.host}",
        "doas", firewall.helper, *operation,
    ]  # fmt: skip


def run_helper(firewall: Firewall, *operation: str, stdin: str = "") -> dict[str, str]:
    if not firewall.configured:
        raise RemoteError(
            f"This machine has no SSH key configured for the firewall. Create {LOCAL_FILE}; see the README."
        )
    try:
        result = subprocess.run(
            ssh_command(firewall, *operation), input=stdin, capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        raise RemoteError("The firewall did not answer in time") from None
    if result.returncode == 255:
        raise RemoteError("Could not connect to the firewall: " + (result.stderr.strip() or "no answer"))
    if result.returncode != 0:
        raise RemoteError(result.stderr.strip() or f"The firewall refused ({result.returncode})")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def git(root: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RemoteError(result.stderr.strip() or result.stdout.strip() or "git failed")
    return result.stdout


def pending_changes(root: Path) -> str:
    """The uncommitted changes to the configuration, as a diff."""
    git(root, "add", "--intent-to-add", "--", "firewall", "nat", "dhcp", check=False)
    return git(root, "diff", "--", "firewall", "nat", "dhcp")


def commit(root: Path, message: str) -> str:
    git(root, "add", "--", "firewall", "nat", "dhcp")
    git(root, "commit", "-m", message, "--", "firewall", "nat", "dhcp")
    return git(root, "rev-parse", "--short", "HEAD").strip()


def has_remote(root: Path) -> bool:
    return bool(git(root, "remote", check=False).strip())


def push(root: Path) -> None:
    git(root, "push")
