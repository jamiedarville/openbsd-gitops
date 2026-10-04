"""Command line entry point.

    fw            open the editor
    fw assemble   print pf.conf exactly as it will be deployed
    fw check      ask the firewall to parse the rules; changes nothing
    fw status     compare this folder with what the firewall is running
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import remote, rules


def find_root(start: Path) -> Path:
    for directory in (start, *start.parents):
        if (directory / remote.CONFIG_FILE).exists():
            return directory
    sys.exit(f"No {remote.CONFIG_FILE} found here or in a parent folder.")


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
    if command == "check":
        pf_conf = rules.assemble_pf(root)
        try:
            answer = remote.run_helper(remote.load_firewall(root), "validate", stdin=pf_conf)
        except remote.RemoteError as problem:
            print(f"Rejected: {problem}", file=sys.stderr)
            return 1
        if answer.get("candidate_sha256") != rules.digest(pf_conf):
            print("The firewall received something different from what was sent.", file=sys.stderr)
            return 1
        print("The firewall accepts these rules. Nothing was changed.")
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
        in_sync = live == saved == wanted
        print("in sync" if in_sync else "different")
        return 0 if in_sync else 2

    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
