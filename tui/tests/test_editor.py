"""Drives the real editor through a pseudo-terminal, as a person would."""

import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

TUI = Path(__file__).resolve().parents[1]
# curses puts the terminal in application mode, where Down is ESC O B.
ENTER, ESCAPE, DOWN = b"\r", b"\x1b", b"\x1bOB"


class Editor:
    def __init__(self, root: Path):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(root)
            os.environ.update(PYTHONPATH=str(TUI), TERM="xterm", LINES="40", COLUMNS="120", ESCDELAY="100")
            os.execvp(sys.executable, [sys.executable, "-m", "fwgitops"])
        self.screen = b""

    def read(self, quiet: float = 0.2, limit: float = 5.0) -> str:
        """Collects output until the editor has been quiet for a moment.

        Waiting for quiet, instead of a fixed pause, keeps the keys in step
        with the editor however busy the machine is.
        """
        deadline = time.time() + limit
        last_output = time.time()
        while time.time() < deadline and time.time() - last_output < quiet:
            ready, _, _ = select.select([self.fd], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if chunk:
                    self.screen += chunk
                    last_output = time.time()
        return self.screen.decode(errors="replace")

    def wait_for(self, text: str, limit: float = 10.0) -> str:
        deadline = time.time() + limit
        while time.time() < deadline:
            if text in self.read():
                return self.screen.decode(errors="replace")
        raise AssertionError(f"the editor never showed {text!r}")

    def press(self, *keys: bytes) -> str:
        for key in keys:
            os.write(self.fd, key)
            self.read()
        return self.screen.decode(errors="replace")

    def close(self) -> int:
        """Backs out of whatever screen is open until the editor exits."""
        deadline = time.time() + 10
        while time.time() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            try:
                os.write(self.fd, ESCAPE)
            except OSError:
                pass  # The editor has closed its terminal and is exiting.
            self.read()
            # Once the terminal is closed, reads return at once; do not spin.
            time.sleep(0.05)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        raise AssertionError("the editor did not exit")


@unittest.skipUnless(sys.platform.startswith(("linux", "darwin", "openbsd")), "needs a pseudo-terminal")
class EditorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "firewall.json").write_text('{"name": "test", "host": "192.0.2.10", "user": "fccdeploy"}')
        for folder in ("firewall", "nat", "dhcp"):
            (self.root / folder).mkdir()
        (self.root / "firewall/30-rules.conf").write_text("block all\npass in proto tcp from any to any port 22\n")
        (self.root / "nat/20-nat.conf").write_text("")
        (self.root / "dhcp/dhcpd.conf").write_text("")
        git = ["git", "-C", str(self.root), "-c", "user.name=test", "-c", "user.email=test@example.com"]
        subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "initial"], check=True)
        self.git = git

    def rules(self) -> list[str]:
        return (self.root / "firewall/30-rules.conf").read_text().splitlines()

    def test_adds_a_rule_through_the_wizard(self):
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")

        editor.press(DOWN, ENTER)  # open "Firewall rules"
        editor.press(ENTER)  # "Create rule"
        editor.press(ENTER)  # pass
        editor.press(ENTER)  # in
        editor.press(b"egress", ENTER)  # interface
        editor.press(ENTER)  # TCP
        editor.press(ENTER)  # from any
        editor.press(b"192.0.2.10", ENTER)  # to
        editor.press(b"443", ENTER)  # ports
        editor.press(ENTER)  # log: No
        editor.press(ENTER)  # quick: No
        screen = editor.press(b"Web server", ENTER)

        self.assertEqual(
            self.rules()[-1], "pass in on egress proto tcp from any to 192.0.2.10 port 443  # Web server"
        )
        self.assertIn("Web server", screen)
        editor.press(ESCAPE, ESCAPE, ESCAPE)
        self.assertEqual(editor.close(), 0)

    def test_adds_a_rule_from_the_list(self):
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")

        editor.press(DOWN, ENTER, DOWN, ENTER)  # Firewall rules, "View and change rules"
        editor.press(b"a")  # add
        editor.press(DOWN, ENTER)  # block
        editor.press(ENTER)  # in
        editor.press(ENTER)  # every interface
        editor.press(DOWN, ENTER)  # UDP
        editor.press(b"10.0.0.0/8", ENTER)  # from
        editor.press(ENTER)  # to any
        editor.press(b"53", ENTER)  # ports
        editor.press(ENTER, ENTER, ENTER)  # log: No, quick: No, no comment

        self.assertEqual(self.rules()[-1], "block in proto udp from 10.0.0.0/8 to any port 53")
        editor.press(ESCAPE, ESCAPE, ESCAPE)
        self.assertEqual(editor.close(), 0)

    def test_rejects_a_bad_answer_and_asks_again(self):
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")
        editor.press(DOWN, ENTER, ENTER, ENTER, ENTER)  # Firewall rules, "Create rule", pass, in
        screen = editor.press(b"em0; pass all", ENTER)
        self.assertIn("An interface looks like", screen)
        editor.press(ESCAPE, ESCAPE, ESCAPE)
        self.assertEqual(editor.close(), 0)
        self.assertEqual(len(self.rules()), 2)

    def test_moves_and_deletes_lines(self):
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")
        editor.press(DOWN, ENTER, DOWN, ENTER)  # Firewall rules, "View and change rules"; first line selected
        editor.press(b"n")  # move "block all" down
        self.assertEqual(self.rules(), ["pass in proto tcp from any to any port 22", "block all"])
        editor.press(b"d", DOWN, ENTER)  # delete it: move to "Yes", confirm
        self.assertEqual(self.rules(), ["pass in proto tcp from any to any port 22"])
        editor.press(ESCAPE, ESCAPE)
        self.assertEqual(editor.close(), 0)

    def test_adds_a_vlan_with_everything_behind_it(self):
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")

        editor.press(ENTER, ENTER)  # Networks, "Add a VLAN"
        editor.press(b"em1", ENTER)  # the port that carries it
        editor.press(b"10", ENTER)  # VLAN number
        editor.press(b"192.168.10.1/24", ENTER)  # the firewall's address
        editor.press(b"Office", ENTER)
        editor.press(DOWN, ENTER)  # DHCP: Yes
        editor.press(ENTER)  # keep the suggested DNS servers
        screen = editor.press(DOWN, ENTER)  # reach the internet: Yes

        self.assertIn("VLAN 10 is written", screen)
        read = lambda name: (self.root / name).read_text().splitlines()
        self.assertEqual(
            read("network/hostname.vlan10"),
            ["# Office", "parent em1 vnetid 10", "inet 192.168.10.1 255.255.255.0", "up"],
        )
        self.assertEqual(read("network/hostname.em1"), ["up"])
        self.assertEqual(read("network/sysctl.conf"), ["net.inet.ip.forwarding=1"])
        self.assertEqual(
            read("dhcp/dhcpd.conf"),
            [
                "subnet 192.168.10.0 netmask 255.255.255.0 { range 192.168.10.100 192.168.10.200; "
                "option routers 192.168.10.1; option domain-name-servers 1.1.1.1, 9.9.9.9; }"
            ],
        )
        self.assertEqual(
            read("nat/20-nat.conf"), ["match out on egress inet from (vlan10:network) to any nat-to (egress)  # Office"]
        )
        self.assertEqual(self.rules()[-1], "pass in on vlan10 from (vlan10:network) to any  # Office")
        editor.press(ENTER)  # close the summary
        # The list behind it now offers the new files. curses redraws only what
        # differs from the summary, so only whole new lines can be looked for.
        self.assertIn("Change hostname.em1", editor.read())
        self.assertIn("Routing between networks: on", editor.read())
        editor.press(ESCAPE)
        self.assertEqual(editor.close(), 0)

    def test_saves_changes_as_a_commit(self):
        (self.root / "firewall/30-rules.conf").write_text(
            "block all\npass in proto tcp from any to any port 22\npass out from any to any\n"
        )
        subprocess.run([*self.git, "config", "user.name", "test"], check=True)
        subprocess.run([*self.git, "config", "user.email", "test@example.com"], check=True)
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")

        editor.press(*[DOWN] * 7, ENTER)  # "Save and deploy"
        editor.press(ENTER)  # close the diff
        editor.press(ENTER)  # check on the firewall first: No
        screen = editor.press(b"Allow outbound", ENTER)

        self.assertIn("no remote", screen)
        log = subprocess.run([*self.git, "log", "-1", "--format=%s"], capture_output=True, text=True).stdout
        self.assertEqual(log.strip(), "Allow outbound")
        editor.press(ENTER, ESCAPE)
        self.assertEqual(editor.close(), 0)

    def test_warns_before_saving_rules_without_ssh(self):
        (self.root / "firewall/30-rules.conf").write_text("block all\n")
        editor = Editor(self.root)
        editor.wait_for("Save and deploy")

        editor.press(*[DOWN] * 7, ENTER)  # "Save and deploy"
        screen = editor.press(ENTER)  # close the diff

        self.assertIn("no rule seems to allow SSH", screen)
        editor.press(ENTER)  # "No": do not save
        log = subprocess.run([*self.git, "log", "-1", "--format=%s"], capture_output=True, text=True).stdout
        self.assertEqual(log.strip(), "initial")
        editor.press(ESCAPE)
        self.assertEqual(editor.close(), 0)


if __name__ == "__main__":
    unittest.main()
