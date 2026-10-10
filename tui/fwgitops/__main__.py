"""Command line entry point.

    fw            open the editor
    fw assemble   print pf.conf exactly as it will be deployed
    fw assemble-network   print the network files exactly as they will be sent
    fw check      ask the firewall to check the rules and the network files;
                  changes nothing
    fw status     compare this folder with what the firewall is running
    fw import-opnsense [-n] [--force] [--map igb0=em0 ...] config.xml
                  write this folder's files from an OPNsense backup, and say
                  what could not be brought across; -n only says
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import opnsense, remote, rules


def find_root(start: Path) -> Path:
    for directory in (start, *start.parents):
        if (directory / remote.CONFIG_FILE).exists():
            return directory
    sys.exit(f"No {remote.CONFIG_FILE} found here or in a parent folder.")


def import_opnsense(root: Path, arguments: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="fw import-opnsense", description="Writes this folder's files from an OPNsense backup.")
    parser.add_argument("backup", type=Path, help="the config.xml downloaded from OPNsense")
    parser.add_argument("-n", "--dry-run", action="store_true", help="say what would be written, and write nothing")
    parser.add_argument("--force", action="store_true", help="replace files that were not written by an import")
    parser.add_argument("--map", action="append", default=[], metavar="OLD=NEW", help="the OpenBSD name of an OPNsense port, such as igb0=em2")
    options = parser.parse_args(arguments)
    device_map = {}
    for pair in options.map:
        old, equals, new = pair.partition("=")
        try:
            device_map[old.strip()] = rules.check_port(new) if equals and old.strip() else rules.check_port("")
        except rules.InvalidInput:
            print(f"--map {pair}: write it like igb0=em2", file=sys.stderr)
            return 64
    try:
        result = opnsense.plan(root, options.backup.read_bytes(), device_map, options.force, options.dry_run)
    except OSError as problem:
        print(f"Could not read the backup: {problem}", file=sys.stderr)
        return 1
    except opnsense.ImportFailed as problem:
        print(problem, file=sys.stderr)
        return 1
    if not options.dry_run:
        opnsense.write(root, result)
    sys.stdout.write(result.report)
    return 0


def main(arguments: list[str]) -> int:
    root = find_root(Path.cwd())
    command = arguments[0] if arguments else "edit"

    if command == "edit":
        from . import app

        app.run(root)
        return 0
    if command == "assemble":
        sys.stdout.write(rules.assemble_pf(root))
        return 0
    if command == "assemble-network":
        sys.stdout.write(rules.assemble_network(root))
        return 0
    if command == "import-opnsense":
        return import_opnsense(root, arguments[1:])
    if command == "check":
        firewall = remote.load_firewall(root)
        checks = [("validate", rules.assemble_pf(root))]
        if rules.network_files(root):
            checks.append(("net-validate", rules.assemble_network(root)))
        for operation, text in checks:
            try:
                answer = remote.run_helper(firewall, operation, stdin=text)
            except remote.RemoteError as problem:
                print(f"Rejected: {problem}", file=sys.stderr)
                if "no IP address found" in str(problem) and len(checks) > 1:
                    print(
                        "A rule uses the address of an interface the firewall does not have yet. "
                        "Write it in brackets, like (vlan10:network), and PF looks it up as it goes.",
                        file=sys.stderr,
                    )
                return 1
            if answer.get("candidate_sha256") != rules.digest(text):
                print("The firewall received something different from what was sent.", file=sys.stderr)
                return 1
        print("The firewall accepts this configuration. Nothing was changed.")
        return 0
    if command == "status":
        try:
            answer = remote.run_helper(remote.load_firewall(root), "status")
        except remote.RemoteError as problem:
            print(f"Could not ask the firewall: {problem}", file=sys.stderr)
            return 1
        wanted = rules.digest(rules.assemble_pf(root))
        live, saved = answer.get("loaded_sha256"), answer.get("committed_sha256")
        print(f"this folder:      {wanted}")
        print(f"firewall saved:   {saved}")
        print(f"firewall running: {live}")
        print(f"last rollback:    {answer.get('last_rollback')}")
        # A helper from before network support says nothing about it.
        network = answer.get("net_sha256", rules.digest(rules.NETWORK_HEADER + "\n"))
        wanted_network = rules.digest(rules.assemble_network(root))
        print(f"network files:    {'the same' if network == wanted_network else 'different'}")
        in_sync = live == saved == wanted and network == wanted_network
        print("in sync" if in_sync else "different")
        return 0 if in_sync else 2

    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
