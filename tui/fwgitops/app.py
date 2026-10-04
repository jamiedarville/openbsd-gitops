"""The interactive editor."""

from __future__ import annotations

import curses
from pathlib import Path

from . import remote, rules, ui

TITLE = "Firewall configuration"


def _yes_no(screen, title: str, question: str) -> bool:
    return ui.choose(screen, f"{title} — {question}", ["No", "Yes"]) == 1


# ------------------------------------------------------------------- wizards


def filter_rule_wizard(screen) -> str:
    title = "New firewall rule"
    rule = rules.FilterRule()
    rule.action = ["pass", "block"][ui.choose(screen, f"{title} — what should it do?", ["Pass (allow)", "Block"])]
    rule.direction = ["in", "out", "both"][
        ui.choose(screen, f"{title} — which direction?", ["In (arriving)", "Out (leaving)", "Both"])
    ]
    rule.interface = ui.ask(
        screen, title, "Interface", rules.check_interface, hint="Leave empty for every interface. Example: egress, em0"
    )
    rule.protocol = ["tcp", "udp", "icmp", "icmp6", "any"][
        ui.choose(screen, f"{title} — which protocol?", ["TCP", "UDP", "ICMP (ping)", "ICMPv6", "Any"])
    ]
    address_hint = "any, 192.0.2.10, 10.0.0.0/8, <table> or (interface). Empty means any."
    rule.source = ui.ask(screen, title, "From", rules.check_address, hint=address_hint)
    rule.destination = ui.ask(screen, title, "To", rules.check_address, hint=address_hint)
    if rule.protocol in ("tcp", "udp"):
        rule.ports = " ".join(
            ui.ask(screen, title, "Destination ports", rules.check_ports, hint="22, or 80 443, or 8000:8010. Empty means all.")
        )
    rule.log = _yes_no(screen, title, "log matching packets?")
    rule.quick = _yes_no(screen, title, "stop at this rule when it matches (quick)?")
    rule.comment = ui.ask(screen, title, "What is this rule for?", rules.check_comment, hint="Shown beside the rule")
    return rule.render()


def nat_wizard(screen) -> str:
    title = "New NAT rule"
    kind = ui.choose(
        screen,
        f"{title} — what kind?",
        ["Outbound NAT: let an inside network reach the internet", "Port forward: send a port to a machine inside"],
    )
    interface = ui.ask(screen, title, "Outside interface", rules.check_interface, default="egress")
    comment_hint = "Shown beside the rule"
    if kind == 0:
        source = ui.ask(screen, title, "Inside network", rules.check_address, hint="Example: 192.168.10.0/24")
        comment = ui.ask(screen, title, "What is this for?", rules.check_comment, hint=comment_hint)
        return rules.outbound_nat(interface, source, comment)
    protocol = ["tcp", "udp"][ui.choose(screen, f"{title} — which protocol?", ["TCP", "UDP"])]
    port = ui.text_input(screen, title, "Outside port", hint="Example: 443")
    target = ui.text_input(screen, title, "Inside machine", hint="Example: 192.168.10.20")
    target_port = ui.text_input(screen, title, "Inside port", hint="Leave empty to keep the same port")
    comment = ui.ask(screen, title, "What is this for?", rules.check_comment, hint=comment_hint)
    return rules.port_forward(interface, protocol, port, target, target_port, comment)


def dhcp_wizard(screen) -> str:
    title = "New DHCP entry"
    kind = ui.choose(
        screen, f"{title} — what kind?", ["Network: hand out addresses on a network", "Reservation: fixed address for one device"]
    )
    if kind == 0:
        return rules.dhcp_subnet(
            ui.text_input(screen, title, "Network", hint="Example: 192.168.10.0/24"),
            ui.text_input(screen, title, "First address to hand out", hint="Example: 192.168.10.100"),
            ui.text_input(screen, title, "Last address to hand out", hint="Example: 192.168.10.200"),
            ui.text_input(screen, title, "Router (gateway)", hint="Example: 192.168.10.1"),
            ui.text_input(screen, title, "DNS servers", hint="Example: 1.1.1.1 9.9.9.9"),
        )
    return rules.dhcp_static_lease(
        ui.text_input(screen, title, "Device name", hint="Example: printer"),
        ui.text_input(screen, title, "MAC address", hint="Example: 00:11:22:33:44:55"),
        ui.text_input(screen, title, "Address", hint="Example: 192.168.10.50"),
    )


# -------------------------------------------------------------------- screens


def edit_file(screen, root: Path, relative: Path, heading: str, wizard, selected: int = 0) -> None:
    """Lists a file's lines and lets them be added, changed, moved or removed."""
    path = root / relative
    footer = "a add  e edit  d delete  u/n move up/down  Esc back"
    while True:
        lines = rules.read_lines(path)
        dim = {index for index, line in enumerate(lines) if not rules.is_rule(line)}
        try:
            selected, key = ui.menu(screen, f"{heading}  ({relative})", lines, footer, selected, keys="aedun", dim=dim)
        except ui.Cancelled:
            return
        try:
            if key == "a":
                rules.write_lines(path, rules.add_line(lines, wizard(screen)))
                selected = len(lines)
            elif key in ("e", "") and lines:
                edited = ui.text_input(screen, heading, "Edit the line", default=lines[selected])
                rules.write_lines(path, rules.replace_line(lines, selected, edited))
            elif key == "d" and lines:
                if _yes_no(screen, heading, f"delete this line?  {lines[selected]}"):
                    rules.write_lines(path, rules.delete_line(lines, selected))
            elif key in ("u", "n") and lines:
                moved, selected = rules.move_line(lines, selected, -1 if key == "u" else 1)
                rules.write_lines(path, moved)
        except ui.Cancelled:
            continue
        except rules.InvalidInput as problem:
            ui.message(screen, heading, f"That was not saved:\n\n{problem}")


def firewall_menu(screen, root: Path) -> None:
    heading = "Firewall rules"
    path = root / rules.RULES_FILE
    selected = 0
    while True:
        selected = ui.choose(screen, heading, ["Create rule", "View and change rules"], selected)
        added = 0
        if selected == 0:
            try:
                lines = rules.read_lines(path)
                rules.write_lines(path, rules.add_line(lines, filter_rule_wizard(screen)))
            except ui.Cancelled:
                continue
            except rules.InvalidInput as problem:
                ui.message(screen, heading, f"That was not saved:\n\n{problem}")
                continue
            # Show the new rule in place, where it can be moved: order matters.
            added = len(lines)
        edit_file(screen, root, rules.RULES_FILE, heading, filter_rule_wizard, added)


def review(screen, root: Path) -> None:
    ui.pager(screen, "Changes not yet saved to Git", remote.pending_changes(root) or "No changes.")


def check_on_firewall(screen, root: Path) -> bool:
    """Asks the firewall to parse the rules. Nothing is loaded."""
    pf_conf = rules.assemble_pf(root)
    try:
        answer = remote.run_helper(remote.load_firewall(root), "validate", stdin=pf_conf)
    except remote.RemoteError as problem:
        ui.message(screen, "The firewall rejected these rules", f"{problem}\n\nNothing was changed on the firewall.")
        return False
    if answer.get("candidate_sha256") != rules.digest(pf_conf):
        ui.message(screen, "Check failed", "The firewall received something different from what was sent.")
        return False
    ui.message(screen, "Check passed", "The firewall accepts these rules.\n\nNothing was changed on the firewall.")
    return True


def save(screen, root: Path) -> None:
    title = "Save and deploy"
    changes = remote.pending_changes(root)
    if not changes:
        ui.message(screen, title, "There are no changes to save.")
        return
    ui.pager(screen, "These changes will be saved", changes)

    if not rules.keeps_ssh_open(rules.assemble_pf(root)):
        if not _yes_no(
            screen,
            title,
            "no rule seems to allow SSH in. The firewall would undo a lockout by itself, but save anyway?",
        ):
            return
    if _yes_no(screen, title, "check the rules on the firewall first?") and not check_on_firewall(screen, root):
        return

    description = ui.ask(screen, title, "Describe this change", _required, hint="This becomes the Git commit message")
    revision = remote.commit(root, description)
    if not remote.has_remote(root):
        ui.message(screen, title, f"Saved as commit {revision}.\n\nThis repository has no remote, so nothing was pushed.")
        return
    if _yes_no(screen, title, f"saved as {revision}. Push now so it deploys?"):
        remote.push(root)
        ui.message(screen, title, f"Pushed {revision}. The deployment picks it up within a minute.\n\nUse Status to see when it is live.")


def _required(value: str) -> str:
    value = " ".join(value.split())
    if not value:
        raise rules.InvalidInput("A description is required")
    return value


def status(screen, root: Path) -> None:
    title = "Status"
    wanted = rules.digest(rules.assemble_pf(root))
    lines = []
    try:
        firewall = remote.load_firewall(root)
        answer = remote.run_helper(firewall, "status")
        live, saved = answer.get("loaded_sha256", ""), answer.get("committed_sha256", "")
        lines.append(f"Firewall {firewall.name} ({firewall.host}): PF {answer.get('pf', 'unknown')}")
        lines.append("")
        if answer.get("armed") == "1":
            lines.append("A deployment is in progress: new rules are loaded and awaiting confirmation.")
        elif live == "unknown":
            lines.append("Warning: the firewall is running rules that no deployment loaded.")
            lines.append("They were changed by hand, or nothing was deployed yet. The next deployment replaces them.")
        elif live == saved == wanted:
            lines.append("In sync: the firewall is running the rules in this folder.")
        elif live == saved:
            lines.append("Different: the firewall is running other rules than this folder holds.")
            lines.append("That is normal if you have changes that are not pushed or not deployed yet.")
        else:
            lines.append("Warning: the running rules differ from the firewall's own saved file.")
        lines += ["", f"This folder:      {wanted}", f"Firewall saved:   {saved}", f"Firewall running: {live}"]
        lines += ["", f"Last rollback on the firewall: {answer.get('last_rollback', 'none')}"]
    except (remote.RemoteError, OSError, KeyError, ValueError) as problem:
        lines.append(f"Could not ask the firewall: {problem}")
    lines += ["", "Unsaved changes: " + ("yes" if remote.pending_changes(root) else "none")]
    lines.append("Latest commit:   " + remote.git(root, "log", "-1", "--format=%h %s (%cr)", check=False).strip())
    ui.message(screen, title, "\n".join(lines))


def main_menu(screen, root: Path) -> None:
    curses.curs_set(0)
    screen.keypad(True)
    entries = [
        ("Firewall rules", lambda: firewall_menu(screen, root)),
        ("NAT and port forwards", lambda: edit_file(screen, root, rules.NAT_FILE, "NAT", nat_wizard)),
        ("DHCP", lambda: edit_file(screen, root, rules.DHCP_FILE, "DHCP", dhcp_wizard)),
        ("Review changes", lambda: review(screen, root)),
        ("Check rules on the firewall (changes nothing)", lambda: check_on_firewall(screen, root)),
        ("Save and deploy", lambda: save(screen, root)),
        ("Status", lambda: status(screen, root)),
        ("Quit", None),
    ]
    selected = 0
    while True:
        try:
            selected = ui.choose(screen, TITLE, [label for label, _ in entries], selected)
        except ui.Cancelled:
            return
        action = entries[selected][1]
        if action is None:
            return
        try:
            action()
        except ui.Cancelled:
            pass
        except (remote.RemoteError, rules.InvalidInput) as problem:
            ui.message(screen, "That did not work", str(problem))


def run(root: Path) -> None:
    # Without this, curses waits a full second after Escape.
    import os

    os.environ.setdefault("ESCDELAY", "100")
    curses.wrapper(main_menu, root)
