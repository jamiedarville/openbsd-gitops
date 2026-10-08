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



class NetworkTests(unittest.TestCase):
    def test_a_vlan_is_three_lines_in_a_file_named_after_it(self):
        address = rules.check_interface_address("192.168.10.1/24")
        self.assertEqual(
            rules.vlan_interface("em1", 10, address, "Office"),
            (Path("network/hostname.vlan10"), ["# Office", "parent em1 vnetid 10", "inet 192.168.10.1 255.255.255.0", "up"]),
        )

    def test_rejects_addresses_and_ports_that_cannot_work(self):
        for bad in ("192.168.10.1", "192.168.10.0/24", "192.168.10.255/24", "10.0.0.1/31", "2001:db8::1/64", "x"):
            with self.subTest(bad), self.assertRaises(rules.InvalidInput):
                rules.check_interface_address(bad)
        for bad in ("vlan10", "lo0", "em", "em1; id", "Em1"):
            with self.subTest(bad), self.assertRaises(rules.InvalidInput):
                rules.check_port(bad)
        for bad in ("0", "4095", "ten"):
            with self.subTest(bad), self.assertRaises(rules.InvalidInput):
                rules.check_vlan_number(bad)

    def test_the_dhcp_range_avoids_the_firewall(self):
        suggest = lambda value: rules.dhcp_range(rules.check_interface_address(value))
        self.assertEqual(suggest("192.168.10.1/24"), ("192.168.10.100", "192.168.10.200"))
        self.assertEqual(suggest("192.168.10.200/24"), ("192.168.10.100", "192.168.10.199"))
        self.assertEqual(suggest("10.0.0.1/28"), ("10.0.0.8", "10.0.0.14"))
        self.assertEqual(suggest("10.0.0.9/28"), ("10.0.0.10", "10.0.0.14"))

    def test_routing_is_one_line_switched_on_and_off(self):
        self.assertEqual(rules.with_routing(["# note"], True), ["# note", "net.inet.ip.forwarding=1"])
        self.assertEqual(rules.with_routing(["# note", "net.inet.ip.forwarding=1"], False), ["# note"])
        self.assertEqual(rules.with_routing(["net.inet.ip.forwarding=0"], True), ["net.inet.ip.forwarding=1"])

    def test_addresses_of_an_interface_macros_and_tables(self):
        for good in ("(vlan10:network)", "vlan10:network", "(egress)", "$lan"):
            self.assertEqual(rules.check_address(good), good)
        for bad in ("(vlan10:network", "vlan10:netwrk", "vlan10", "$(id)"):
            with self.subTest(bad), self.assertRaises(rules.InvalidInput):
                rules.check_address(bad)
        self.assertEqual(rules.macro("lan", "vlan10"), 'lan = "vlan10"')
        self.assertEqual(rules.table("<admins>", "192.0.2.10, 10.1.2.3/8"), "table <admins> { 192.0.2.10, 10.0.0.0/8 }")
        with self.assertRaises(rules.InvalidInput):
            rules.macro("lan", 'vlan10" pass all "')

    def test_joins_the_network_files_as_the_firewall_reports_them(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "network").mkdir()
            self.assertEqual(rules.assemble_network(root), "# openbsd-gitops network\n")
            (root / "network/hostname.vlan10").write_text("parent em1 vnetid 10\nup")
            (root / "network/hostname.em1").write_text("up\n")
            (root / "network/hostname.vlan10.bak").write_text("ignored\n")
            (root / "network/sysctl.conf").write_text("# only a comment\n")
            self.assertEqual(
                rules.assemble_network(root),
                "# openbsd-gitops network\n# --- hostname.em1 ---\nup\n"
                "# --- hostname.vlan10 ---\nparent em1 vnetid 10\nup\n",
            )
            (root / "network/sysctl.conf").write_text("net.inet.ip.forwarding=1\n")
            self.assertTrue(rules.assemble_network(root).endswith("# --- sysctl.conf ---\nnet.inet.ip.forwarding=1\n"))


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
