"""
test_proton_import.py: Unit tests for Proton VPN WireGuard config parsing,
batch import, metadata extraction, and AmneziaWG generation in v5.
"""

import io
import os
import tempfile
import unittest
import zipfile

from proton_manager import (
    ProtonManager,
    extract_proton_metadata,
    parse_wireguard_conf_content,
)
from config_builder import (
    AmneziaParams,
    build_amnezia_config,
    build_shadowrocket_wg_url,
)


class TestProtonVpnImport(unittest.TestCase):
    def setUp(self):
        self.sample_proton_conf = """
[Interface]
# Key for User Account
# Bouncing = 17
# NetShield = 1
# Moderate NAT = off
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# NL-FREE#123456
PublicKey = lP3ZlU7q5xL0hFkS5aE9N0zO2bJ4yD8mQ6wR1vC7uTk=
AllowedIPs = 0.0.0.0/0
Endpoint = 185.159.158.123:51820
"""

    def test_parse_wireguard_conf_content(self):
        user_iface, peers = parse_wireguard_conf_content(
            self.sample_proton_conf,
            source_name="NL-FREE#123456.conf"
        )
        self.assertIsNotNone(user_iface)
        self.assertEqual(user_iface["private_key"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
        self.assertEqual(user_iface["address"], "10.2.0.2/32")
        self.assertEqual(user_iface["dns"], "10.2.0.1")

        self.assertEqual(len(peers), 1)
        p = peers[0]
        self.assertEqual(p["country"], "Netherlands")
        self.assertEqual(p["country_code"], "NL")
        self.assertEqual(p["city"], "Amsterdam")
        self.assertEqual(p["endpoint_ip"], "185.159.158.123")
        self.assertEqual(p["port"], 51820)
        self.assertEqual(p["public_key"], "lP3ZlU7q5xL0hFkS5aE9N0zO2bJ4yD8mQ6wR1vC7uTk=")

    def test_extract_proton_metadata(self):
        # Netherlands Free
        cc, country, city, s_name = extract_proton_metadata("NL-FREE#123456.conf")
        self.assertEqual(cc, "NL")
        self.assertEqual(country, "Netherlands")
        self.assertEqual(city, "Amsterdam")

        # US California
        cc, country, city, s_name = extract_proton_metadata("US-CA#12.conf")
        self.assertEqual(cc, "US")
        self.assertEqual(country, "United States")
        self.assertEqual(city, "Los Angeles")

        # Switzerland
        cc, country, city, s_name = extract_proton_metadata("CH#1.conf")
        self.assertEqual(cc, "CH")
        self.assertEqual(country, "Switzerland")

        # Japan
        cc, country, city, s_name = extract_proton_metadata("jp-free-01.conf")
        self.assertEqual(cc, "JP")
        self.assertEqual(country, "Japan")

    def test_proton_manager_seed_blueprint(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name

        try:
            pm = ProtonManager(data_file=tmp_path)
            self.assertGreaterEqual(len(pm.blueprint.servers), 5)
            self.assertTrue(pm.blueprint.user_interface.address.startswith("10.2.0.2/32"))

            # Check that servers have valid resolved IPs
            for s in pm.blueprint.servers:
                self.assertTrue(len(s.resolved_ips) > 0)
                self.assertEqual(s.port, 51820)
                self.assertTrue(len(s.public_key) > 30)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_proton_manager_import_from_text(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name

        try:
            pm = ProtonManager(data_file=tmp_path)
            initial_count = len(pm.blueprint.servers)

            new_conf = """
[Interface]
PrivateKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
Address = 10.2.0.5/32
DNS = 10.2.0.1

[Peer]
# US-NY#99
PublicKey = 1111111111111111111111111111111111111111111=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.50:51820
"""
            added, creds = pm.import_from_conf_text(new_conf, filename="US-NY#99.conf")
            self.assertEqual(added, 1)
            self.assertEqual(creds, 1)
            self.assertEqual(len(pm.blueprint.servers), initial_count + 1)
            self.assertEqual(pm.blueprint.user_interface.private_key, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=")
            self.assertEqual(pm.blueprint.user_interface.address, "10.2.0.5/32")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_proton_manager_import_from_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name

        try:
            pm = ProtonManager(data_file=tmp_path)
            initial_count = len(pm.blueprint.servers)

            # Build in-memory zip containing two .conf files
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr(
                    "CH#5.conf",
                    """[Interface]
PrivateKey = ccccccccccccccccccccccccccccccccccccccccccc=
Address = 10.2.0.2/32

[Peer]
PublicKey = 2222222222222222222222222222222222222222222=
Endpoint = 192.0.2.10:51820
"""
                )
                zf.writestr(
                    "DE#3.conf",
                    """[Interface]
Address = 10.2.0.2/32

[Peer]
PublicKey = 3333333333333333333333333333333333333333333=
Endpoint = 192.0.2.20:51820
"""
                )

            zip_buffer.seek(0)
            added, creds = pm.import_from_zip(zip_buffer.getvalue())
            self.assertEqual(added, 2)
            self.assertEqual(creds, 1)
            self.assertEqual(len(pm.blueprint.servers), initial_count + 2)
            self.assertEqual(pm.blueprint.user_interface.private_key, "ccccccccccccccccccccccccccccccccccccccccccc=")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_amnezia_wg_generation_for_proton(self):
        params = AmneziaParams.iran_preset()
        conf = build_amnezia_config(
            client_private_key="a" * 43 + "=",
            client_address="10.2.0.2/32",
            client_dns="10.2.0.1",
            server_public_key="b" * 43 + "=",
            endpoint_ip="185.159.158.123",
            endpoint_port=51820,
            amnezia_params=params,
            tunnel_name="🇳🇱 Netherlands — Amsterdam (185.159.158.123)",
        )

        self.assertIn("[Interface]", conf)
        self.assertIn("Address = 10.2.0.2/32", conf)
        self.assertIn("DNS = 10.2.0.1", conf)
        self.assertIn(f"Jc = {params.jc}", conf)
        self.assertIn(f"H1 = {params.h1}", conf)
        self.assertIn(f"H4 = {params.h4}", conf)
        self.assertIn("Endpoint = 185.159.158.123:51820", conf)
        self.assertIn("Surfshark & Proton AmneziaWG Studio v5", conf)

    def test_shadowrocket_wg_url_for_proton(self):
        params = AmneziaParams.iran_preset()
        server_info = {
            "endpoint_ip": "185.159.158.123",
            "port": 51820,
            "public_key": "lP3ZlU7q5xL0hFkS5aE9N0zO2bJ4yD8mQ6wR1vC7uTk=",
            "country_code": "NL",
            "city": "Amsterdam",
            "country": "Netherlands",
        }
        user_iface = {
            "private_key": "a" * 43 + "=",
            "address": "10.2.0.2/32",
            "dns": "10.2.0.1",
        }
        url = build_shadowrocket_wg_url(server_info, user_iface, params)
        self.assertTrue(url.startswith("wg://185.159.158.123:51820?"))
        self.assertIn("lP3ZlU7q5xL0hFkS5aE9N0zO2bJ4yD8mQ6wR1vC7uTk", url)
        self.assertIn("10.2.0.2", url)

    def test_proton_manager_reset_to_seed_catalog(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name

        try:
            pm = ProtonManager(data_file=tmp_path)
            # Wipe servers and set custom private key
            pm.blueprint.servers.clear()
            pm.blueprint.user_interface.private_key = "custom_proton_priv_key="
            self.assertEqual(len(pm.blueprint.servers), 0)

            # Reset to seed catalog, keeping credentials
            cnt = pm.reset_to_seed_catalog(keep_credentials=True)
            self.assertGreaterEqual(cnt, 20)
            self.assertEqual(len(pm.blueprint.servers), cnt)
            self.assertEqual(pm.blueprint.user_interface.private_key, "custom_proton_priv_key=")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_proton_settings_dataclass(self):
        from proton_manager import ProtonSettings
        ps = ProtonSettings(
            routing_mode="secure_core",
            netshield_level=2,
            moderate_nat=True,
            nat_pmp=False,
            vpn_accelerator=True,
        )
        d = ps.to_dict()
        self.assertEqual(d["routing_mode"], "secure_core")
        self.assertEqual(d["netshield_level"], 2)
        self.assertTrue(d["moderate_nat"])
        self.assertFalse(d["nat_pmp"])

        restored = ProtonSettings.from_dict(d)
        self.assertEqual(restored.routing_mode, "secure_core")
        self.assertEqual(restored.netshield_level, 2)
        self.assertTrue(restored.moderate_nat)

    def test_parse_wireguard_conf_with_dashboard_headers(self):
        conf_with_headers = """
[Interface]
# Key for elahekaveh
# Bouncing = 10
# NetShield = 2
# Moderate NAT = on
# NAT-PMP (Port Forwarding) = off
# VPN Accelerator = on
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# CH-AR#2
PublicKey = 2222222222222222222222222222222222222222222=
Endpoint = 185.159.158.1:51820
AllowedIPs = 0.0.0.0/0
"""
        u_iface, peers = parse_wireguard_conf_content(conf_with_headers, source_name="CH-AR#2.conf")
        self.assertIsNotNone(u_iface)
        self.assertEqual(u_iface["netshield_level"], 2)
        self.assertTrue(u_iface["moderate_nat"])
        self.assertFalse(u_iface["nat_pmp"])
        self.assertTrue(u_iface["vpn_accelerator"])
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["server_name"], "CH-AR#2")
        self.assertTrue(peers[0]["secure_core"])

    def test_proton_manager_filter_servers(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_path = tf.name

        try:
            pm = ProtonManager(data_file=tmp_path)
            # Full catalog should have over 1,000 servers
            all_servers = pm.blueprint.servers
            self.assertGreaterEqual(len(all_servers), 1000)

            # Test standard filter
            standard_svrs = pm.filter_servers(routing_mode="standard")
            self.assertGreaterEqual(len(standard_svrs), 500)
            self.assertTrue(all(not s.secure_core for s in standard_svrs))

            # Test secure core filter
            sc_svrs = pm.filter_servers(routing_mode="secure_core")
            self.assertGreaterEqual(len(sc_svrs), 350)
            self.assertTrue(all(s.secure_core for s in sc_svrs))

            # Test port forward filter
            pf_svrs = pm.filter_servers(port_forward_only=True)
            self.assertGreaterEqual(len(pf_svrs), 400)
            self.assertTrue(all(s.port_forward for s in pf_svrs))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_build_amnezia_config_with_proton_headers(self):
        conf = build_amnezia_config(
            client_private_key="a" * 43 + "=",
            client_address="10.2.0.2/32",
            client_dns="10.2.0.1",
            server_public_key="b" * 43 + "=",
            endpoint_ip="185.159.158.123",
            endpoint_port=51820,
            provider="proton",
            netshield_level=2,
            moderate_nat=True,
            nat_pmp=False,
            vpn_accelerator=True,
            routing_mode="secure_core",
        )
        self.assertIn("# Routing = Secure_core", conf)
        self.assertIn("# NetShield = 2", conf)
        self.assertIn("# Moderate NAT = on", conf)
        self.assertIn("# NAT-PMP (Port Forwarding) = off", conf)
        self.assertIn("# VPN Accelerator = on", conf)
        self.assertIn("Address = 10.2.0.2/32", conf)
        self.assertIn("DNS = 10.2.0.1", conf)

    def test_generate_batch_zip_and_shadowrocket_for_proton(self):
        from config_builder import generate_batch_zip, generate_shadowrocket_batch_conf
        test_servers = [{
            "country": "Switzerland",
            "country_code": "CH",
            "city": "Zurich",
            "hostname": "ch-01.protonvpn.net",
            "public_key": "b" * 43 + "=",
            "endpoint_ip": "185.159.158.1",
            "port": 51820,
        }]
        user_iface = {
            "private_key": "a" * 43 + "=",
            "address": "10.2.0.2/32",
            "dns": "10.2.0.1",
        }

        # 1. Batch ZIP
        zip_bytes = generate_batch_zip(
            server_configs=test_servers,
            user_interface=user_iface,
            provider="proton",
            netshield_level=2,
            moderate_nat=True,
            vpn_accelerator=True,
        )
        self.assertGreater(len(zip_bytes), 100)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            readme = zf.read("README.txt").decode("utf-8")
            self.assertIn("Proton VPN AmneziaWG", readme)
            conf_files = [n for n in zf.namelist() if n.endswith(".conf")]
            self.assertEqual(len(conf_files), 1)
            conf_content = zf.read(conf_files[0]).decode("utf-8")
            self.assertIn("# NetShield = 2", conf_content)
            self.assertIn("# Moderate NAT = on", conf_content)

        # 2. Shadowrocket Master Conf
        sr_conf = generate_shadowrocket_batch_conf(
            server_configs=test_servers,
            user_interface=user_iface,
            provider="proton",
            netshield_level=1,
            vpn_accelerator=True,
        )
        self.assertIn("# Proton VPN AmneziaWG Master Configuration for Shadowrocket", sr_conf)
        self.assertIn("# NetShield = 1", sr_conf)
        self.assertIn("# VPN Accelerator = on", sr_conf)


if __name__ == "__main__":
    unittest.main()
