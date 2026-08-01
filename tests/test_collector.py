import base64
import json
import tempfile
import unittest
from pathlib import Path

import collector
import rank_configs


def vmess_link(name: str) -> str:
    data = {
        "v": "2",
        "ps": name,
        "add": "1.1.1.1",
        "port": "443",
        "id": "00000000-0000-0000-0000-000000000001",
        "net": "ws",
        "tls": "tls",
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return "vmess://" + payload


class CollectorTests(unittest.TestCase):
    def test_decodes_base64_subscription(self):
        plain = "vless://id@example.com:443?type=ws&security=tls#old\n"
        encoded = base64.b64encode(plain.encode()).decode()
        self.assertEqual(collector.extract_links(encoded), [plain.strip()])

    def test_duplicates_ignore_fragment_and_query_order(self):
        links = [
            "vless://id@example.com:443?type=ws&security=tls#one",
            "vless://id@example.com:443?security=tls&type=ws#two",
        ]
        self.assertEqual(len(collector.unique_configs(links)), 1)

    def test_vmess_duplicates_ignore_ps(self):
        self.assertEqual(
            len(collector.unique_configs([vmess_link("one"), vmess_link("two")])), 1
        )

    def test_labels_and_renames(self):
        config = collector.parse_config(
            "vless://id@1.1.1.1:443?type=tcp&security=reality#old"
        )
        assert config is not None
        self.assertEqual(collector.protocol_label(config), "VLESS/RAW/REALITY")
        renamed = collector.rename_config(config, "@STenmenB 🇦🇺 VLESS/RAW/REALITY")
        self.assertIn("%40STenmenB", renamed)
        self.assertNotIn("#old", renamed)

    def test_invalid_legacy_hostname_does_not_crash_resolution(self):
        overlong_host = "a" * 100
        self.assertIsNone(collector.CountryLookup.resolve(overlong_host))

    def test_collect_end_to_end_with_local_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.txt"
            source.write_text(
                "vless://id@1.1.1.1:443?type=ws&security=tls#one\n"
                "vless://id@1.1.1.1:443?security=tls&type=ws#duplicate\n",
                encoding="utf-8",
            )
            links, errors = collector.collect(
                [str(source)], 2, lambda host: "AU", "@STenmenB"
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(links), 1)
        decoded_name = __import__("urllib.parse").parse.unquote(links[0].split("#", 1)[1])
        self.assertEqual(decoded_name, "@STenmenB 🇦🇺 VLESS/WS/TLS")

    def test_builds_mihomo_vless_reality_proxy(self):
        config = collector.parse_config(
            "vless://abc@server.example:443?type=tcp&security=reality&"
            "sni=example.com&pbk=publickey&sid=12ab#%40STenmenB%20%F0%9F%87%A9%F0%9F%87%AA%20VLESS%2FRAW%2FREALITY"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, collector.config_display_name(config))
        assert proxy is not None
        self.assertEqual(proxy["type"], "vless")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["reality-opts"], {"public-key": "publickey", "short-id": "12ab"})

    def test_yaml_names_are_unique(self):
        links = [
            "vless://one@example.com:443?type=ws&security=tls#Same",
            "vless://two@example.com:443?type=ws&security=tls#Same",
        ]
        configs = [collector.parse_config(link) for link in links]
        full, provider = collector.build_yaml_documents([item for item in configs if item])
        names = [proxy["name"] for proxy in provider["proxies"]]
        self.assertEqual(names, ["Same", "Same-2"])
        self.assertEqual(full["rules"], ["MATCH,🚀 Proxy"])

    def test_hysteria_has_required_bandwidth_defaults(self):
        config = collector.parse_config(
            "hysteria://secret@server.example:443?sni=example.com&insecure=1#HY"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "HY")
        assert proxy is not None
        self.assertEqual(proxy["up"], "30 Mbps")
        self.assertEqual(proxy["down"], "200 Mbps")
        self.assertEqual(proxy["protocol"], "udp")
        self.assertEqual(proxy["sni"], "example.com")
        self.assertNotIn("tls", proxy)

    def test_hysteria2_uses_sni_field(self):
        config = collector.parse_config(
            "hysteria2://secret@server.example:443?sni=example.com#HY2"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "HY2")
        assert proxy is not None
        self.assertEqual(proxy["sni"], "example.com")
        self.assertNotIn("servername", proxy)
        self.assertNotIn("tls", proxy)

    def test_ranked_candidates_keep_only_alive_in_delay_order(self):
        links = [
            "vless://one@example.com:443?type=ws&security=tls#Same",
            "vless://two@example.com:443?type=ws&security=tls#Same",
            "vless://three@example.com:443?type=ws&security=tls#Third",
        ]
        candidates = rank_configs.build_candidates(links)
        alive, failed = rank_configs.ranked_candidates(
            candidates, {"Same-2": 80, "Same": 120}
        )
        self.assertEqual([item.name for item in alive], ["Same-2", "Same"])
        self.assertEqual([item.name for item in failed], ["Third"])


if __name__ == "__main__":
    unittest.main()
