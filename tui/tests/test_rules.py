import tempfile
import unittest
from pathlib import Path

from fwgitops import rules


class FilterRuleTests(unittest.TestCase):
    def test_renders_a_typical_rule(self):
        rule = rules.FilterRule(interface="egress", ports="22", comment="SSH management")
        self.assertEqual(
            rule.render(), "pass in on egress proto tcp from any to any port 22  # SSH management"
        )

    def test_renders_options_tables_and_several_ports(self):
        rule = rules.FilterRule(
            action="block", direction="both", protocol="udp", source="<blocked>",
            destination="10.1.2.3/8", ports="53, 123 8000:8010", log=True, quick=True,
        )  # fmt: skip
        self.assertEqual(
            rule.render(),
            "block log quick proto udp from <blocked> to 10.0.0.0/8 port { 53, 123, 8000:8010 }",
        )

    def test_any_protocol_has_no_proto_or_port(self):
        rule = rules.FilterRule(direction="out", protocol="any")
        self.assertEqual(rule.render(), "pass out from any to any")

    def test_rejects_what_pf_would_misread(self):
        bad = [
            rules.FilterRule(interface="em0; pass all"),
            rules.FilterRule(source="10.0.0.1 to any pass all"),
            rules.FilterRule(source="010.0.0.1"),
            rules.FilterRule(ports="22; pass all"),
            rules.FilterRule(ports="70000"),
            rules.FilterRule(protocol="icmp", ports="22"),
            rules.FilterRule(comment="line one\nline two" * 20),
            rules.FilterRule(comment="allow web \\"),
            rules.FilterRule(action="nat"),
        ]
        for rule in bad:
            with self.subTest(rule=rule), self.assertRaises(rules.InvalidInput):
                rule.render()

    def test_a_comment_cannot_carry_a_second_rule(self):
        rendered = rules.FilterRule(comment="ok\npass all").render()
        self.assertEqual(len(rendered.splitlines()), 1)


class NatAndDhcpTests(unittest.TestCase):
    def test_outbound_nat(self):
        self.assertEqual(
            rules.outbound_nat("egress", "192.168.10.0/24", "LAN to internet"),
            "match out on egress inet from 192.168.10.0/24 to any nat-to (egress)  # LAN to internet",
        )
        with self.assertRaises(rules.InvalidInput):
            rules.outbound_nat("egress", "any")

    def test_port_forward(self):
        self.assertEqual(
            rules.port_forward("egress", "tcp", "443", "192.168.10.20", "8443"),
            "pass in on egress inet proto tcp from any to (egress) port 443 rdr-to 192.168.10.20 port 8443",
        )
        for arguments in (("egress", "icmp", "1", "192.168.10.20"), ("egress", "tcp", "1 2", "192.168.10.20"), ("", "tcp", "1", "192.168.10.20"), ("egress", "tcp", "1", "not-an-ip")):
            with self.subTest(arguments=arguments), self.assertRaises(rules.InvalidInput):
                rules.port_forward(*arguments)

    def test_dhcp_subnet(self):
        self.assertEqual(
            rules.dhcp_subnet("192.168.10.0/24", "192.168.10.100", "192.168.10.200", "192.168.10.1", "1.1.1.1, 9.9.9.9"),
            "subnet 192.168.10.0 netmask 255.255.255.0 { range 192.168.10.100 192.168.10.200; "
            "option routers 192.168.10.1; option domain-name-servers 1.1.1.1, 9.9.9.9; }",
        )
        with self.assertRaises(rules.InvalidInput):
            rules.dhcp_subnet("192.168.10.0/24", "192.168.11.100", "192.168.10.200", "192.168.10.1", "1.1.1.1")
        with self.assertRaises(rules.InvalidInput):
            rules.dhcp_subnet("192.168.10.0/24", "192.168.10.200", "192.168.10.100", "192.168.10.1", "1.1.1.1")

    def test_dhcp_static_lease(self):
        self.assertEqual(
            rules.dhcp_static_lease("printer", "00:11:22:AA:BB:CC", "192.168.10.50"),
            "host printer { hardware ethernet 00:11:22:aa:bb:cc; fixed-address 192.168.10.50; }",
        )
        with self.assertRaises(rules.InvalidInput):
            rules.dhcp_static_lease("printer; }", "00:11:22:33:44:55", "192.168.10.50")


class FileTests(unittest.TestCase):
    def test_line_operations(self):
        lines = ["# heading", "block all", "pass out"]
        self.assertEqual(rules.add_line(lines, "pass in"), [*lines, "pass in"])
        self.assertEqual(rules.delete_line(lines, 1), ["# heading", "pass out"])
        self.assertEqual(rules.move_line(lines, 1, 1), (["# heading", "pass out", "block all"], 2))
        self.assertEqual(rules.move_line(lines, 2, 1), (lines, 2))
        self.assertEqual(rules.replace_line(lines, 2, "pass in"), ["# heading", "block all", "pass in"])
        with self.assertRaises(rules.InvalidInput):
            rules.add_line(lines, "pass in\npass all")

    def test_a_comment_cannot_swallow_the_next_line(self):
        lines = ["block all", "pass in proto tcp to port 22"]
        with self.assertRaises(rules.InvalidInput):
            rules.add_line(lines, "pass out  # everything \\")
        with self.assertRaises(rules.InvalidInput):
            rules.replace_line(lines, 0, "block all  # default \\ ")
        # A rule, as opposed to a comment, may still be continued by hand.
        self.assertEqual(rules.replace_line(lines, 1, "pass in proto tcp \\")[1], "pass in proto tcp \\")

    def test_assembles_files_from_both_folders_in_name_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules.write_lines(root / "firewall/30-rules.conf", ["block all"])
            rules.write_lines(root / "nat/20-nat.conf", ["match out on egress nat-to (egress)"])
            rules.write_lines(root / "firewall/10-settings.conf", ["set skip on lo"])
            (root / "firewall/notes.txt").write_text("ignored")

            assembled = rules.assemble_pf(root)

            self.assertEqual(
                [line for line in assembled.splitlines() if rules.is_rule(line)],
                ["set skip on lo", "match out on egress nat-to (egress)", "block all"],
            )
            self.assertTrue(assembled.endswith("\n"))
            self.assertEqual(rules.digest(assembled), rules.digest(rules.assemble_pf(root)))

    def test_notices_when_no_rule_lets_ssh_in(self):
        allows = [
            "pass in proto tcp from any to any port 22",
            "pass in on egress proto tcp from <admins> to any port { 80, 22 }  # ssh",
            "pass in proto tcp to port ssh",
            "pass in all",
            "pass from any to any",
        ]
        blocks = [
            "block all",
            "pass out from any to any",
            "pass in proto tcp from any to any port 2222",
            "pass in proto tcp from any to any port 220",
            "pass in proto udp from any to any",
            "# pass in proto tcp from any to any port 22",
            "block in proto tcp from any to any port 22",
        ]
        for rule in allows:
            self.assertTrue(rules.keeps_ssh_open(f"block all\n{rule}\n"), rule)
        for rule in blocks:
            self.assertFalse(rules.keeps_ssh_open(f"block all\n{rule}\n"), rule)

    def test_reads_continued_lines_as_pf_does(self):
        self.assertTrue(rules.keeps_ssh_open("block all\npass in proto tcp \\\n  to port 22\n"))
        self.assertFalse(rules.keeps_ssh_open("block all  # default \\\npass in proto tcp to port 22\n"))


if __name__ == "__main__":
    unittest.main()
