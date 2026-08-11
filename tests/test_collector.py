import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_source_status_preserves_previous_success_when_fetch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            working = root / "working.txt"
            missing = root / "missing.txt"
            working.write_text(
                "vless://id@1.1.1.1:443?type=ws&security=tls#one\n",
                encoding="utf-8",
            )
            previous = {
                str(missing): {
                    "last_success_at": "2026-08-01T00:00:00+00:00",
                    "upstream_last_modified": "2026-07-31T00:00:00+00:00",
                    "etag": '"old"',
                    "last_success_configs": 12,
                }
            }
            _, errors, statuses = collector.collect_with_status(
                [str(working), str(missing)],
                2,
                lambda host: None,
                "@STenmenB",
                previous,
            )
        failed = statuses[1]
        self.assertEqual(len(errors), 1)
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["last_success_at"], "2026-08-01T00:00:00+00:00")
        self.assertEqual(failed["last_success_configs"], 12)

    def test_source_status_output_contains_success_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text(
                "vless://id@1.1.1.1:443?type=ws&security=tls#one\n",
                encoding="utf-8",
            )
            links, errors, statuses = collector.collect_with_status(
                [str(source)], 2, lambda host: "AU", "@STenmenB"
            )
            output = root / "sources-status.json"
            collector.write_source_status(output, statuses)
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(len(links), 1)
        self.assertEqual(errors, [])
        self.assertEqual(report["summary"], {"total": 1, "ok": 1, "failed": 0})
        self.assertEqual(report["sources"][0]["configs_found"], 1)
        self.assertEqual(report["sources"][0]["status"], "ok")
        self.assertIsNotNone(report["sources"][0]["upstream_last_modified"])

    def test_parses_github_raw_source_for_commit_lookup(self):
        self.assertEqual(
            collector.github_source_parts(
                "https://raw.githubusercontent.com/owner/repository/refs/heads/main/path/file.txt"
            ),
            ("owner", "repository", "main", "path/file.txt"),
        )
        self.assertEqual(
            collector.github_source_parts(
                "https://github.com/owner/repository/blob/master/list.txt"
            ),
            ("owner", "repository", "master", "list.txt"),
        )

    def test_reads_github_file_commit_date(self):
        response = mock.MagicMock()
        response.read.return_value = json.dumps(
            [{"commit": {"committer": {"date": "2026-08-11T12:34:56Z"}}}]
        ).encode()
        response.__enter__.return_value = response
        with mock.patch.object(collector.urllib.request, "urlopen", return_value=response) as api:
            modified = collector.github_file_last_modified(
                "https://raw.githubusercontent.com/owner/repository/main/path/file.txt",
                5,
            )
        self.assertEqual(modified, "2026-08-11T12:34:56Z")
        requested = api.call_args.args[0]
        self.assertIn("/repos/owner/repository/commits?", requested.full_url)
        self.assertIn("path=path%2Ffile.txt", requested.full_url)
        self.assertIn("sha=main", requested.full_url)

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

    def test_reality_short_id_that_looks_exponential_is_quoted(self):
        config = collector.parse_config(
            "vless://abc@server.example:443?type=tcp&security=reality&"
            "sni=example.com&pbk=publickey&sid=11e9#Reality"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "Reality")
        assert proxy is not None
        rendered = collector.dump_yaml({"proxies": [proxy]})
        self.assertIn("short-id: '11e9'", rendered)

    def test_reality_short_id_strips_non_hex_source_suffix(self):
        config = collector.parse_config(
            "vless://abc@server.example:443?type=tcp&security=reality&"
            "pbk=publickey&sid=c39cc7310a@freenettir%20%C2%B2#Reality"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "Reality")
        assert proxy is not None
        self.assertEqual(config.details["sid"], "c39cc7310a")
        self.assertIn("sid=c39cc7310a", config.original)
        self.assertNotIn("freenettir", config.original)
        self.assertEqual(proxy["reality-opts"]["short-id"], "c39cc7310a")

    def test_reality_short_id_omits_unrecoverable_value(self):
        config = collector.parse_config(
            "vless://abc@server.example:443?type=tcp&security=reality&"
            "pbk=publickey&sid=not-a-short-id#Reality"
        )
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "Reality")
        assert proxy is not None
        self.assertNotIn("sid", config.details)
        self.assertNotIn("sid=", config.original)
        self.assertEqual(proxy["reality-opts"], {"public-key": "publickey"})

    def test_unsupported_shadowsocks_cipher_is_kept_out_of_yaml(self):
        userinfo = base64.urlsafe_b64encode(
            b"chacha20-poly1305:secret"
        ).decode().rstrip("=")
        link = f"ss://{userinfo}@82.38.31.46:8080#Unsupported"
        config = collector.parse_config(link)
        assert config is not None
        self.assertIsNone(collector.to_mihomo_proxy(config, "Unsupported"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_count, yaml_count = collector.write_outputs(
                [link],
                root / "all.txt",
                root / "base64.txt",
                root / "mihomo.yaml",
                root / "proxies.yaml",
            )
            self.assertEqual((config_count, yaml_count), (1, 0))
            self.assertEqual((root / "all.txt").read_text(encoding="utf-8").strip(), link)

    def test_supported_shadowsocks_cipher_is_added_to_yaml(self):
        userinfo = base64.urlsafe_b64encode(
            b"chacha20-ietf-poly1305:secret"
        ).decode().rstrip("=")
        link = f"ss://{userinfo}@example.com:443#Supported"
        config = collector.parse_config(link)
        assert config is not None
        proxy = collector.to_mihomo_proxy(config, "Supported")
        assert proxy is not None
        self.assertEqual(proxy["cipher"], "chacha20-ietf-poly1305")

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

    def test_proxy_delay_uses_encoded_name_and_expected_status(self):
        with mock.patch.object(rank_configs, "api_json", return_value={"delay": 123}) as api:
            delay = rank_configs.test_proxy(
                "http://127.0.0.1:9090", "Proxy Name", "https://example.com/test", 5000, "200/204"
            )
        self.assertEqual(delay, 123)
        requested_url = api.call_args.args[0]
        self.assertIn("/proxies/Proxy%20Name/delay?", requested_url)
        self.assertIn("expected=200%2F204", requested_url)

    def test_bounded_retry_uses_second_url_only_for_failures(self):
        links = [
            "vless://one@example.com:443?type=ws&security=tls#One",
            "vless://two@example.com:443?type=ws&security=tls#Two",
        ]
        candidates = rank_configs.build_candidates(links)

        def fake_test(_controller, name, url, _timeout, _expected):
            if name == "One" and "google" in url:
                return 100
            if name == "Two" and "cloudflare" in url:
                return 150
            return None

        with mock.patch.object(rank_configs, "test_proxy", side_effect=fake_test) as test:
            delays, urls = rank_configs.test_proxies_bounded(
                candidates,
                "http://127.0.0.1:9090",
                ["https://google.test", "https://cloudflare.test"],
                5000,
                "200/204",
                2,
                1,
            )
        self.assertEqual(delays, {"One": 100, "Two": 150})
        self.assertEqual(urls["Two"], "https://cloudflare.test")
        second_attempt_names = [call.args[1] for call in test.call_args_list[2:]]
        self.assertEqual(second_attempt_names, ["Two"])


if __name__ == "__main__":
    unittest.main()
