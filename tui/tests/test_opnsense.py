import re
import shutil
import tempfile
import unittest
from pathlib import Path

from fwgitops import opnsense, rules

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
SAMPLE = (HERE / "opnsense-config.xml").read_bytes()
# What the firewall's helper lets through in an interface file; see check_network.
ALLOWED_IN_INTERFACE_FILE = re.compile(r"^(\s*#.*|[A-Za-z0-9 \t._:/-]*)$")


def backup(body: str) -> bytes:
    return f"<opnsense>{body}</opnsense>".encode()


TWO_PORTS = """
<system><hostname>fw</hostname><domain>example.net</domain><dnsserver>9.9.9.9</dnsserver></system>
<interfaces>
  <wan><if>igb0</if><enable>1</enable><ipaddr>203.0.113.2</ipaddr><subnet>30</subnet><gateway>WAN_GW</gateway><blockpriv>1</blockpriv></wan>
  <lan><if>igb1</if><enable>1</enable><ipaddr>10.1.0.1</ipaddr><subnet>24</subnet></lan>
</interfaces>
<gateways><gateway_item><interface>wan</interface><gateway>203.0.113.1</gateway><name>WAN_GW</name><defaultgw>1</defaultgw></gateway_item></gateways>
"""


class Folder(unittest.TestCase):
    """A copy of the files this repository starts with, to import into."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for name in ("firewall", "nat", "dhcp", "dns", "network", "firewall.json"):
            source = REPOSITORY / name
            if source.is_dir():
                shutil.copytree(source, self.root / name)
            else:
                shutil.copy(source, self.root / name)

    def run_import(self, data: bytes = SAMPLE, **options) -> opnsense.Result:
        result = opnsense.plan(self.root, data, **options)
        opnsense.write(self.root, result)
        return result

    def lines(self, path) -> list[str]:
        return rules.read_lines(self.root / path)


class SampleBackupTests(Folder):
    def setUp(self):
        super().setUp()
        self.result = self.run_import()

    def test_ports_get_their_openbsd_names_and_vlans_their_numbers(self):
        self.assertEqual(self.lines("network/hostname.vio0")[2:], ["inet autoconf", "up"])
        self.assertEqual(self.lines("network/hostname.vio1")[2:], ["inet 192.168.1.1 255.255.255.0", "up"])
        self.assertEqual(
            self.lines("network/hostname.vlan10")[2:],
            ["parent vio1 vnetid 10", "inet 192.168.10.1 255.255.255.0", "up"],
        )
        self.assertFalse((self.root / "network/hostname.vlan30").exists(), "a VLAN nothing was assigned to")
        self.assertIn("net.inet.ip.forwarding=1", self.lines("network/sysctl.conf"))

    def test_a_gateway_on_an_inside_port_is_not_the_default_route(self):
        self.assertFalse((self.root / "network/mygate").exists())
        self.assertIn("static route to 10.50.0.0/16 by way of 192.168.1.254", self.result.report)

    def test_interface_files_hold_nothing_the_firewall_would_refuse(self):
        for path in (self.root / "network").glob("hostname.*"):
            for line in path.read_text().splitlines():
                self.assertRegex(line, ALLOWED_IN_INTERFACE_FILE)

    def test_rules_keep_their_order_and_meaning(self):
        found = [line.split("  #")[0] for line in self.lines(opnsense.RULES_FILE) if rules.is_rule(line)]
        self.assertEqual(
            found,
            [
                "pass in quick on vio1 proto tcp from any to (self) port 22",
                "block in quick on { vio0, vlan20 } proto tcp from <badcountries> to any port 25",
                "pass in quick on { vio1, vlan10 } inet proto icmp from any to (self) icmp-type echoreq",
                "pass in quick on vio0 inet proto tcp from any to 192.168.1.10 port 8443",
                "pass in quick on vio1 inet from (vio1:network) to any",
                "pass in quick on vlan10 inet proto { tcp, udp } from (vlan10:network) to (vlan10) port 53",
                "block in log quick on vlan10 inet from (vlan10:network) to <rfc1918>",
                "pass in quick on vlan10 inet proto tcp from (vlan10:network) to any port $web",
                "pass in quick on vlan20 inet from (vlan20:network) to ! (vlan10:network)",
            ],
        )

    def test_a_rule_that_cannot_be_written_is_named_and_not_guessed(self):
        text = "\n".join(self.lines(opnsense.RULES_FILE))
        self.assertIn("# switched off in OPNsense: pass in quick on vlan20 inet proto tcp", text)
        self.assertIn("# NOT IMPORTED, the interface VPN was not imported: Nothing in from the VPN", text)
        self.assertIn('A BLOCK RULE IS MISSING. The rule "Nothing in from the VPN" on VPN', self.result.report)
        self.assertIn("its schedule did not come across", self.result.report)

    def test_aliases_become_tables_and_macros(self):
        found = self.lines(opnsense.ALIASES_FILE)
        self.assertIn("table <servers> { 192.168.1.10, 192.168.1.11 }  # Machines that serve", found)
        self.assertIn('web = "{ 80, 443, 8000:8010 }"  # Web ports', found)
        self.assertIn("table <badcountries> persist", found)
        self.assertIn("'nas.example.net' is not an address", self.result.report)

    def test_nat(self):
        found = [line.split("  #")[0] for line in self.lines(opnsense.NAT_FILE) if rules.is_rule(line)]
        self.assertEqual(
            found,
            [
                "match in on vio0 inet proto tcp from any to (vio0) port 443 rdr-to 192.168.1.10 port 8443",
                "match out on vio0 inet proto udp from 192.168.10.0/24 to any port 123 nat-to (vio0) static-port",
                "match out on vio0 inet from (vio1:network) to any nat-to (vio0)",
                "match out on vio0 inet from (vlan10:network) to any nat-to (vio0)",
                "match out on vio0 inet from (vlan20:network) to any nat-to (vio0)",
            ],
        )

    def test_dhcp_is_added_below_what_was_there(self):
        found = self.lines(rules.DHCP_FILE)
        self.assertEqual(found[0], rules.read_lines(REPOSITORY / rules.DHCP_FILE)[0])
        self.assertIn(
            "subnet 192.168.1.0 netmask 255.255.255.0 { range 192.168.1.100 192.168.1.199; "
            "option routers 192.168.1.1; option domain-name-servers 192.168.1.1; "
            'option domain-name "home.arpa"; default-lease-time 3600; }  # LAN',
            found,
        )
        # A DNS server the network was given by name wins over the firewall's own.
        self.assertTrue(any("192.168.10.0" in line and "domain-name-servers 9.9.9.9;" in line for line in found))
        self.assertIn("host camera { hardware ethernet aa:bb:cc:00:00:01; fixed-address 192.168.10.50; }", found)
        self.assertFalse(any("roaming" in line for line in found), "a device without a fixed address")

    def test_dns(self):
        found = [line.strip().split("  #")[0] for line in self.lines(rules.DNS_FILE)]
        for line in (
            "interface: 192.168.1.1",
            "access-control: 192.168.20.0/24 allow",
            'auto-trust-anchor-file: "/var/unbound/db/root.key"',
            'local-data: "nas.home.arpa. IN A 192.168.1.10"',
            'local-data: "files.home.arpa. IN A 192.168.1.10"',
            'local-data: "camera.home.arpa. IN A 192.168.10.50"',
            'local-data-ptr: "192.168.1.10 nas.home.arpa."',
            'name: "corp.example."',
            "forward-addr: 192.168.1.53",
            "forward-tls-upstream: yes",
            "forward-addr: 9.9.9.9@853#dns.quad9.net",
        ):
            self.assertIn(line, found)
        self.assertFalse(any("old.home.arpa" in line for line in found), "a host override that was switched off")
        self.assertFalse(any("10.0.2" in line or "vio0" in line for line in found), "the outside is not listened on")

    def test_nothing_secret_is_copied(self):
        for path in self.result.files:
            self.assertNotIn("NotARealHash", (self.root / path).read_text())

    def test_importing_again_changes_nothing(self):
        before = {path: (self.root / path).read_text() for path in self.result.files}
        again = self.run_import()
        self.assertEqual(again.removed, [])
        for path, text in before.items():
            self.assertEqual((self.root / path).read_text(), text, path)

    def test_files_of_an_earlier_import_go_when_no_longer_wanted(self):
        smaller = SAMPLE.replace(b"<if>vlan0.20</if>", b"<if>wg1</if>")
        result = self.run_import(smaller)
        self.assertIn(Path("network/hostname.vlan20"), result.removed)
        self.assertFalse((self.root / "network/hostname.vlan20").exists())
        self.assertFalse(any("192.168.20" in line for line in self.lines(rules.DHCP_FILE)))


class OwnershipTests(Folder):
    def test_a_file_written_by_hand_is_not_replaced(self):
        rules.write_lines(self.root / "network/hostname.vio1", ["up"])
        with self.assertRaises(opnsense.ImportFailed) as refusal:
            opnsense.plan(self.root, SAMPLE)
        self.assertIn("network/hostname.vio1", str(refusal.exception))
        self.run_import(force=True)
        self.assertEqual(self.lines("network/hostname.vio1")[0], opnsense.MARKER)

    def test_a_dry_run_writes_nothing(self):
        result = opnsense.plan(self.root, SAMPLE, dry_run=True)
        self.assertIn("Would write", result.report)
        self.assertFalse((self.root / opnsense.RULES_FILE).exists())

    def test_dhcp_lines_written_by_hand_are_kept(self):
        mine = "host printer { hardware ethernet 00:11:22:33:44:55; fixed-address 192.168.1.50; }"
        rules.write_lines(self.root / rules.DHCP_FILE, [mine])
        result = self.run_import()
        self.assertEqual(self.lines(rules.DHCP_FILE)[0], mine)
        self.assertIn("already held networks", result.report)


class OtherBackupTests(Folder):
    def test_a_fixed_outside_address_and_ports_that_change_driver(self):
        result = self.run_import(backup(TWO_PORTS))
        self.assertEqual(self.lines("network/hostname.em0")[2:], ["inet 203.0.113.2 255.255.255.252", "up"])
        self.assertEqual(self.lines("network/mygate"), [opnsense.MARKER, "203.0.113.1"])
        self.assertIn(
            "match out on em0 inet from (em1:network) to any nat-to (em0)",
            [line.split("  #")[0] for line in self.lines(opnsense.NAT_FILE)],
        )
        self.assertTrue(any(line.startswith("block in quick on em0 from { 10.0.0.0/8,") for line in self.lines(opnsense.RULES_FILE)))
        self.assertIn("igb0", result.report)

    def test_a_port_can_be_named_by_hand(self):
        self.run_import(backup(TWO_PORTS), device_map={"igb0": "ix3"})
        self.assertTrue((self.root / "network/hostname.ix3").exists())
        self.assertFalse((self.root / "network/hostname.em0").exists())

    def test_two_ports_that_would_share_a_name_stop_the_import(self):
        clash = TWO_PORTS.replace("<if>igb1</if>", "<if>em0</if>")
        with self.assertRaises(opnsense.ImportFailed) as refusal:
            opnsense.plan(self.root, backup(clash))
        self.assertIn("--map", str(refusal.exception))

    def test_older_formats_of_aliases_rules_and_dns(self):
        self.run_import(backup(TWO_PORTS + """
            <aliases>
              <alias><name>admins</name><type>host</type><address>10.1.0.10 10.1.0.20-10.1.0.21</address></alias>
              <alias><name>mgmt</name><type>port</type><address>22 8443</address></alias>
            </aliases>
            <filter>
              <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
                <source><address>admins</address></source>
                <destination><network>(self)</network><port>mgmt</port></destination></rule>
              <rule><type>reject</type><interface>lan</interface><ipprotocol>inet6</ipprotocol>
                <source><any/></source><destination><any/></destination></rule>
              <rule><type>pass</type><interface>lan</interface><floating>yes</floating><direction>out</direction>
                <statetype>none</statetype><protocol>udp</protocol>
                <source><any/></source><destination><address>10.1.0.0/24</address><port>5000-5010</port></destination></rule>
            </filter>
            <unbound><enable>1</enable><forwarding>1</forwarding>
              <hosts><host>nas</host><domain>example.net</domain><ip>10.1.0.5</ip>
                <aliases><item><host>files</host><domain>example.net</domain></item></aliases></hosts>
              <domainoverrides><domain>10.in-addr.arpa</domain><ip>10.1.0.53</ip></domainoverrides>
            </unbound>
        """))  # fmt: skip
        self.assertIn("table <admins> { 10.1.0.10, 10.1.0.20/31 }", self.lines(opnsense.ALIASES_FILE))
        found = self.lines(opnsense.RULES_FILE)
        # The floating rule comes first, and stops nothing: it was not marked quick.
        self.assertEqual(found.index("pass out on em1 inet proto udp from any to 10.1.0.0/24 port 5000:5010 no state"), 8)
        self.assertIn("pass in quick on em1 inet proto tcp from <admins> to (self) port $mgmt", found)
        self.assertIn("block return in quick on em1 inet6 from any to any", found)
        dns = [line.strip() for line in self.lines(rules.DNS_FILE)]
        self.assertIn('local-data: "files.example.net. IN A 10.1.0.5"', dns)
        self.assertIn('local-zone: "10.in-addr.arpa." nodefault', dns)
        self.assertEqual(dns[dns.index('name: "."') + 1], "forward-addr: 9.9.9.9")

    def test_kea_and_the_newer_rule_format(self):
        self.run_import(backup(TWO_PORTS + """
            <OPNsense>
              <Kea><dhcp4><general><enabled>1</enabled></general>
                <subnets><subnet4 uuid="a"><subnet>10.1.0.0/24</subnet>
                  <option_data><domain_name_servers>1.1.1.1,9.9.9.9</domain_name_servers></option_data>
                  <pools>10.1.0.100-10.1.0.150</pools></subnet4></subnets>
                <reservations><reservation><subnet>a</subnet><ip_address>10.1.0.7</ip_address>
                  <hw_address>AA-BB-CC-DD-EE-FF</hw_address><hostname>tv</hostname></reservation></reservations>
              </dhcp4></Kea>
              <Firewall><Filter><rules>
                <rule><enabled>1</enabled><sequence>2</sequence><action>block</action><quick>1</quick>
                  <interface>lan</interface><direction>in</direction><ipprotocol>inet</ipprotocol><protocol>TCP</protocol>
                  <source_net>lan</source_net><destination_net>192.0.2.0/24,198.51.100.7</destination_net>
                  <destination_port>25</destination_port><log>1</log><description>No mail out</description></rule>
                <rule><enabled>1</enabled><sequence>1</sequence><action>pass</action><quick>0</quick>
                  <interface>lan</interface><source_net>any</source_net><source_not>0</source_not>
                  <destination_net>wanip</destination_net><destination_not>1</destination_not></rule>
              </rules></Filter></Firewall>
            </OPNsense>
        """))  # fmt: skip
        dhcp = self.lines(rules.DHCP_FILE)
        self.assertIn(
            "subnet 10.1.0.0 netmask 255.255.255.0 { range 10.1.0.100 10.1.0.150; option routers 10.1.0.1; "
            'option domain-name-servers 1.1.1.1, 9.9.9.9; option domain-name "example.net"; }  # LAN',
            dhcp,
        )
        self.assertIn("host tv { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 10.1.0.7; }", dhcp)
        found = [line for line in self.lines(opnsense.RULES_FILE) if "em1" in line and "Anti-lockout" not in line]
        self.assertEqual(
            found,
            [
                "pass in on em1 inet from any to ! (em0)",
                "block in log quick on em1 inet proto tcp from (em1:network) to { 192.0.2.0/24, 198.51.100.7 } port 25  # No mail out",
            ],
        )

    def test_a_rule_that_sends_traffic_by_a_gateway(self):
        result = self.run_import(backup(TWO_PORTS + """
            <filter>
              <rule><type>pass</type><interface>lan</interface><gateway>WAN_GW</gateway>
                <source><network>lan</network></source><destination><any/></destination></rule>
              <rule><type>pass</type><interface>lan</interface><gateway>WAN_GROUP</gateway><protocol>tcp</protocol>
                <statetype>sloppy state</statetype>
                <source><address>10.1.0.9</address><not>1</not></source><destination><any/></destination></rule>
            </filter>
        """))  # fmt: skip
        found = self.lines(opnsense.RULES_FILE)
        self.assertIn("pass in quick on em1 inet from (em1:network) to any route-to 203.0.113.1", found)
        self.assertIn("pass in quick on em1 inet proto tcp from ! 10.1.0.9 to any keep state (sloppy)", found)
        self.assertIn("by way of the gateway WAN_GROUP", result.report)

    def test_nat_written_by_hand_and_dnsmasq(self):
        result = self.run_import(backup(TWO_PORTS + """
            <aliases><alias><name>one</name><type>port</type><address>8080</address></alias></aliases>
            <nat>
              <outbound><mode>advanced</mode>
                <rule><source><network>lan</network></source><destination><network>10.9.0.0/16</network></destination>
                  <interface>wan</interface><nonat>1</nonat></rule>
                <rule><source><network>10.1.0.0/24</network></source><destination><any>1</any></destination>
                  <interface>wan</interface><target>203.0.113.5</target></rule>
              </outbound>
              <rule><protocol>tcp/udp</protocol><interface>wan</interface><target>10.1.0.5</target><local-port>5000</local-port>
                <source><address>198.51.100.0/24</address></source>
                <destination><network>wanip</network><port>6000-6010</port></destination>
                <associated-rule-id>pass</associated-rule-id></rule>
              <rule><protocol>tcp</protocol><interface>wan</interface><target>10.1.0.5</target><local-port>one</local-port>
                <source><any/></source><destination><address>203.0.113.9</address><port>80</port></destination></rule>
              <rule><protocol>tcp</protocol><interface>wan</interface><target>10.1.0.5</target><nordr>1</nordr>
                <source><any/></source><destination><any/><port>81</port></destination><descr>Exception</descr></rule>
              <onetoone><external>203.0.113.10</external><source><address>10.1.0.10</address></source>
                <destination><any>1</any></destination><interface>wan</interface></onetoone>
            </nat>
            <dnsmasq><enable>1</enable>
              <hosts><host>tv</host><domain>example.net</domain><ip>10.1.0.7</ip><hwaddr>aa:bb:cc:dd:ee:01</hwaddr></hosts>
              <domainoverrides><domain>lab.example</domain><ip>10.1.0.53</ip></domainoverrides>
              <dhcp_ranges><interface>lan</interface><start_addr>10.1.0.100</start_addr><end_addr>10.1.0.200</end_addr></dhcp_ranges>
            </dnsmasq>
        """))  # fmt: skip
        self.assertEqual(
            [line for line in self.lines(opnsense.NAT_FILE) if rules.is_rule(line)],
            [
                "match on em0 inet from 10.1.0.10 to any binat-to 203.0.113.10",
                "pass in quick on em0 inet proto { tcp, udp } from 198.51.100.0/24 to (em0) port 6000:6010 rdr-to 10.1.0.5 port 5000:*",
                "match in on em0 inet proto tcp from any to 203.0.113.9 port 80 rdr-to 10.1.0.5 port 8080",
                "pass out quick on em0 inet from (em1:network) to 10.9.0.0/16",
                "match out on em0 inet from 10.1.0.0/24 to any nat-to 203.0.113.5",
            ],
        )
        self.assertIn('The port forward "Exception" on WAN was not imported', result.report)
        dns = [line.strip() for line in self.lines(rules.DNS_FILE)]
        self.assertIn('local-data: "tv.example.net. IN A 10.1.0.7"', dns)
        self.assertEqual(dns[dns.index('name: "lab.example."') + 1], "forward-addr: 10.1.0.53")
        self.assertIn("host tv { hardware ethernet aa:bb:cc:dd:ee:01; fixed-address 10.1.0.7; }", self.lines(rules.DHCP_FILE))

    def test_what_a_backup_says_is_never_copied_as_it_stands(self):
        self.run_import(backup(TWO_PORTS + """
            <aliases><alias><name>x</name><type>host</type><address>1.1.1.1;pass&#10;all</address></alias></aliases>
            <filter>
              <rule><type>pass</type><interface>lan</interface><descr>one&#10;pass all \\</descr>
                <source><any/></source><destination><any/></destination></rule>
              <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
                <source><address>1.2.3.4 to any&#10;pass all</address></source><destination><any/></destination></rule>
              <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
                <source><any/></source><destination><any/><port>22; pass all</port></destination></rule>
              <rule><type>pass&#10;pass all</type><interface>lan</interface>
                <source><any/></source><destination><any/></destination></rule>
            </filter>
            <dhcpd><lan><enable>1</enable><range><from>10.1.0.10</from><to>10.1.0.20; }</to></range>
              <domain>x"; } host y { </domain>
              <staticmap><mac>00:11:22:33:44:55</mac><ipaddr>10.1.0.9</ipaddr><hostname>a { b</hostname></staticmap></lan></dhcpd>
            <unbound><enable>1</enable>
              <hosts><host>a"&#10;include: "/etc/passwd</host><domain>example.net</domain><ip>10.1.0.5</ip></hosts></unbound>
        """))  # fmt: skip
        active = [line for line in self.lines(opnsense.RULES_FILE) if rules.is_rule(line)]
        self.assertEqual([line for line in active if "pass all" in line], ["pass in quick on em1 inet from any to any  # one pass all"])
        self.assertEqual(len(active), 3, "the anti-lockout rule, the block of private networks, and one rule")
        self.assertEqual(self.lines(opnsense.ALIASES_FILE)[-1], "table <x> persist")
        dhcp = [line for line in self.lines(rules.DHCP_FILE) if rules.is_rule(line)]
        self.assertEqual(
            dhcp,
            [
                'subnet 10.1.0.0 netmask 255.255.255.0 { option routers 10.1.0.1; option domain-name-servers 10.1.0.1; option domain-name "example.net"; }  # LAN',
                "host host-001122334455 { hardware ethernet 00:11:22:33:44:55; fixed-address 10.1.0.9; }",
            ],
        )
        self.assertFalse(any("include" in line for line in self.lines(rules.DNS_FILE)))

    def test_what_is_not_a_backup_is_turned_down(self):
        for data, reason in (
            (b"---- BEGIN config.xml ----\nabc", "encrypted"),
            (b"<pfsense/>", "pfSense"),
            (b"<html/>", "<opnsense>"),
            (b"<opnsense", "XML"),
            (b'<!DOCTYPE x [<!ENTITY a "b">]><opnsense/>', "DOCTYPE"),
            (b"<opnsense><interfaces><wan><if>pppoe0</if><enable>1</enable></wan></interfaces></opnsense>", "no interface"),
        ):
            with self.assertRaises(opnsense.ImportFailed) as refusal:
                opnsense.plan(self.root, data)
            self.assertIn(reason, str(refusal.exception))


if __name__ == "__main__":
    unittest.main()
