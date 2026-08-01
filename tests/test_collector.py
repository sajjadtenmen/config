import base64
import json
import tempfile
import unittest
from pathlib import Path

import collector


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


if __name__ == "__main__":
    unittest.main()
