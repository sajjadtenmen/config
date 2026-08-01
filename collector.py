#!/usr/bin/env python3
"""Collect, deduplicate, geo-label, and rename proxy subscription links."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import socket
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import yaml


SUPPORTED_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
}


@dataclass(frozen=True)
class ProxyConfig:
    original: str
    scheme: str
    host: str
    canonical: str
    details: dict[str, str]


def add_base64_padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def decode_base64_text(value: str) -> str | None:
    compact = "".join(value.split())
    if not compact:
        return None
    try:
        decoded = base64.urlsafe_b64decode(add_base64_padding(compact)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if "://" in decoded else None


def extract_links(text: str) -> list[str]:
    """Extract proxy links from plain text or a Base64 subscription."""
    decoded = decode_base64_text(text)
    if decoded is not None:
        text = decoded

    links: list[str] = []
    for raw_line in text.replace("\r", "\n").split("\n"):
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        scheme = line.partition("://")[0].lower()
        if scheme in SUPPORTED_SCHEMES:
            links.append(line)
    return links


def decode_vmess(link: str) -> dict[str, object]:
    payload = link.split("://", 1)[1].split("#", 1)[0]
    decoded = base64.urlsafe_b64decode(add_base64_padding(payload)).decode("utf-8")
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("VMess payload is not an object")
    return data


def parse_config(link: str) -> ProxyConfig | None:
    scheme = link.partition("://")[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None

    if scheme == "vmess":
        try:
            data = decode_vmess(link)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        host = str(data.get("add", "")).strip("[] ")
        canonical_data = dict(data)
        canonical_data.pop("ps", None)
        canonical = "vmess://" + json.dumps(
            canonical_data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        details = {str(k).lower(): str(v) for k, v in data.items() if v is not None}
        return ProxyConfig(link, scheme, host, canonical, details)

    try:
        parsed = urllib.parse.urlsplit(link)
    except ValueError:
        return None
    host = parsed.hostname or ""
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = urllib.parse.urlencode(sorted(query_pairs))
    canonical = urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, query, "")
    )
    details = {key.lower(): value for key, value in query_pairs}
    return ProxyConfig(link, scheme, host, canonical, details)


def protocol_label(config: ProxyConfig) -> str:
    protocol = {"hysteria2": "HY2", "hysteria": "HY", "hy2": "HY2"}.get(
        config.scheme, config.scheme.upper()
    )
    transport = (
        config.details.get("type")
        or config.details.get("network")
        or config.details.get("net")
        or "raw"
    ).lower()
    if transport in {"tcp", "none"}:
        transport = "raw"

    security = (config.details.get("security") or config.details.get("tls") or "none").lower()
    if security in {"1", "true"}:
        security = "tls"
    elif security in {"0", "false", ""}:
        security = "none"
    if config.scheme == "trojan" and security == "none":
        security = "tls"
    return f"{protocol}/{transport.upper()}/{security.upper()}"


def country_flag(country_code: str | None) -> str:
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "\U0001f310"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


class CountryLookup:
    def __init__(self, database: Path | None) -> None:
        self.reader = None
        if database and database.exists():
            try:
                import geoip2.database  # type: ignore[import-not-found]

                self.reader = geoip2.database.Reader(str(database))
            except ImportError as exc:
                raise RuntimeError("Install requirements.txt to use the GeoLite database") from exc

    def close(self) -> None:
        if self.reader:
            self.reader.close()

    def __enter__(self) -> "CountryLookup":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def resolve(host: str) -> str | None:
        if not host:
            return None
        # Some legacy SS/SSR links place an encoded payload where a normal
        # hostname would appear. Never let an invalid DNS label abort a full
        # subscription refresh; it can still be retained with the globe flag.
        if len(host) > 253 or any(len(label) > 63 for label in host.split(".")):
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        try:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError):
            return None
        public = []
        for result in results:
            address = result[4][0]
            try:
                if ipaddress.ip_address(address).is_global:
                    public.append(address)
            except ValueError:
                continue
        return sorted(set(public))[0] if public else None

    def code_for_host(self, host: str) -> str | None:
        address = self.resolve(host)
        if not address or not self.reader:
            return None
        try:
            return self.reader.country(address).country.iso_code
        except Exception:  # geoip2 uses several address/database-specific exceptions
            return None


def rename_config(config: ProxyConfig, name: str) -> str:
    if config.scheme == "vmess":
        data = decode_vmess(config.original)
        data["ps"] = name
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    base = config.original.split("#", 1)[0]
    return base + "#" + urllib.parse.quote(name, safe="")


def config_display_name(config: ProxyConfig) -> str:
    if config.scheme == "vmess":
        return str(decode_vmess(config.original).get("ps") or "Proxy")
    fragment = urllib.parse.urlsplit(config.original).fragment
    return urllib.parse.unquote(fragment) or "Proxy"


def as_bool(value: str | None) -> bool:
    return (value or "").lower() in {"1", "true", "yes"}


def uri_parts(config: ProxyConfig) -> urllib.parse.SplitResult:
    return urllib.parse.urlsplit(config.original.split("#", 1)[0])


def network_options(proxy: dict[str, object], details: dict[str, str]) -> None:
    network = (details.get("type") or details.get("network") or details.get("net") or "").lower()
    if network in {"", "tcp", "raw", "none"}:
        return
    proxy["network"] = network
    if network == "ws":
        ws_options: dict[str, object] = {}
        if details.get("path"):
            ws_options["path"] = details["path"]
        if details.get("host"):
            ws_options["headers"] = {"Host": details["host"]}
        if ws_options:
            proxy["ws-opts"] = ws_options
    elif network == "grpc" and (details.get("serviceName") or details.get("servicename")):
        proxy["grpc-opts"] = {
            "grpc-service-name": details.get("serviceName") or details.get("servicename")
        }


def tls_options(proxy: dict[str, object], details: dict[str, str], default_tls: bool = False) -> None:
    security = (details.get("security") or details.get("tls") or "").lower()
    tls = default_tls or security in {"tls", "reality", "1", "true"}
    if tls:
        proxy["tls"] = True
    server_name = details.get("sni") or details.get("servername") or details.get("serverName")
    if server_name:
        proxy["servername"] = server_name
    if as_bool(details.get("allowinsecure") or details.get("insecure") or details.get("skip-cert-verify")):
        proxy["skip-cert-verify"] = True
    fingerprint = details.get("fp") or details.get("client-fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    if security == "reality":
        reality: dict[str, object] = {}
        if details.get("pbk"):
            reality["public-key"] = details["pbk"]
        if details.get("sid"):
            reality["short-id"] = details["sid"]
        if reality:
            proxy["reality-opts"] = reality


def decode_ss_parts(config: ProxyConfig) -> tuple[str, int, str, str] | None:
    raw = config.original.split("#", 1)[0]
    parsed = urllib.parse.urlsplit(raw)
    try:
        if parsed.hostname and parsed.port:
            userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
            decoded_userinfo = decode_base64_text(userinfo)
            if decoded_userinfo is None:
                try:
                    decoded_userinfo = base64.urlsafe_b64decode(add_base64_padding(userinfo)).decode()
                except (ValueError, UnicodeDecodeError):
                    decoded_userinfo = urllib.parse.unquote(userinfo)
            cipher, password = decoded_userinfo.split(":", 1)
            return parsed.hostname, parsed.port, cipher, password
        payload = raw.split("://", 1)[1].split("?", 1)[0]
        decoded = base64.urlsafe_b64decode(add_base64_padding(payload)).decode()
        legacy = urllib.parse.urlsplit("ss://" + decoded)
        if legacy.hostname and legacy.port and legacy.username is not None:
            return legacy.hostname, legacy.port, legacy.username, legacy.password or ""
    except (ValueError, UnicodeDecodeError):
        return None
    return None


def to_mihomo_proxy(config: ProxyConfig, name: str) -> dict[str, object] | None:
    """Convert supported URI fields into a Mihomo/Clash proxy mapping."""
    proxy: dict[str, object] = {"name": name}
    if config.scheme == "vmess":
        data = decode_vmess(config.original)
        try:
            proxy.update(
                {
                    "type": "vmess",
                    "server": str(data["add"]),
                    "port": int(str(data["port"])),
                    "uuid": str(data["id"]),
                    "alterId": int(str(data.get("aid", 0) or 0)),
                    "cipher": str(data.get("scy") or "auto"),
                    "udp": True,
                }
            )
        except (KeyError, ValueError):
            return None
        network_options(proxy, config.details)
        tls_options(proxy, config.details)
        return proxy

    if config.scheme == "ss":
        parts = decode_ss_parts(config)
        if not parts:
            return None
        server, port, cipher, password = parts
        proxy.update(
            {"type": "ss", "server": server, "port": port, "cipher": cipher, "password": password, "udp": True}
        )
        return proxy

    parsed = uri_parts(config)
    try:
        server, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if not server or not port:
        return None
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")

    if config.scheme == "vless":
        if not username:
            return None
        proxy.update({"type": "vless", "server": server, "port": port, "uuid": username, "udp": True})
        if config.details.get("flow"):
            proxy["flow"] = config.details["flow"]
        network_options(proxy, config.details)
        tls_options(proxy, config.details)
    elif config.scheme == "trojan":
        if not username:
            return None
        proxy.update({"type": "trojan", "server": server, "port": port, "password": username, "udp": True})
        network_options(proxy, config.details)
        tls_options(proxy, config.details, default_tls=True)
    elif config.scheme in {"hysteria2", "hy2"}:
        auth = password or username
        if not auth:
            return None
        proxy.update({"type": "hysteria2", "server": server, "port": port, "password": auth})
        tls_options(proxy, config.details, default_tls=True)
        if config.details.get("obfs"):
            proxy["obfs"] = config.details["obfs"]
        if config.details.get("obfs-password"):
            proxy["obfs-password"] = config.details["obfs-password"]
    elif config.scheme == "hysteria":
        proxy.update({"type": "hysteria", "server": server, "port": port})
        if username:
            proxy["auth-str"] = username
        for key in ("up", "down", "protocol"):
            if config.details.get(key):
                proxy[key] = config.details[key]
        tls_options(proxy, config.details, default_tls=True)
    else:
        return None
    return proxy


def build_yaml_documents(configs: list[ProxyConfig]) -> tuple[dict[str, object], dict[str, object]]:
    counts: dict[str, int] = {}
    proxies: list[dict[str, object]] = []
    for config in configs:
        base_name = config_display_name(config)
        counts[base_name] = counts.get(base_name, 0) + 1
        sequence = counts[base_name]
        unique_name = base_name if sequence == 1 else f"{base_name}-{sequence}"
        proxy = to_mihomo_proxy(config, unique_name)
        if proxy:
            proxies.append(proxy)

    names = [str(proxy["name"]) for proxy in proxies]
    provider = {"proxies": proxies}
    full_config: dict[str, object] = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "♻️ Auto",
                "type": "url-test",
                "proxies": names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
            {"name": "🚀 Proxy", "type": "select", "proxies": ["♻️ Auto", "DIRECT", *names]},
        ],
        "rules": ["MATCH,🚀 Proxy"],
    }
    return full_config, provider


def normalize_source_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.netloc.lower() == "github.com" and "/blob/" in parsed.path:
        owner_repo, file_path = parsed.path.split("/blob/", 1)
        return urllib.parse.urlunsplit(
            ("https", "raw.githubusercontent.com", f"{owner_repo}/{file_path}", "", "")
        )
    return url


def read_sources(path: Path) -> list[str]:
    sources = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            sources.append(line)
    return sources


def fetch_source(source: str, timeout: int) -> str:
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(
            normalize_source_url(source),
            headers={"User-Agent": "STenmenB-config-collector/1.0"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8-sig", errors="replace")
    return Path(source).read_text(encoding="utf-8-sig")


def unique_configs(links: Iterable[str]) -> list[ProxyConfig]:
    unique: dict[str, ProxyConfig] = {}
    for link in links:
        config = parse_config(link)
        if config and config.canonical not in unique:
            unique[config.canonical] = config
    return list(unique.values())


def collect(
    sources: list[str],
    timeout: int,
    country_lookup: Callable[[str], str | None],
    brand: str,
) -> tuple[list[str], list[str]]:
    all_links: list[str] = []
    errors: list[str] = []

    def load(source: str) -> tuple[str, list[str], str | None]:
        try:
            return source, extract_links(fetch_source(source, timeout)), None
        except Exception as exc:
            return source, [], str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, max(1, len(sources)))) as pool:
        results = list(pool.map(load, sources))
    for source, links, error in results:
        if error:
            errors.append(f"{source}: {error}")
        else:
            all_links.extend(links)

    if len(errors) == len(sources):
        raise RuntimeError("Every source failed:\n" + "\n".join(errors))
    for error in errors:
        print(f"warning: {error}", file=sys.stderr)

    configs = unique_configs(all_links)
    hosts = sorted({config.host for config in configs if config.host})
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts)))) as pool:
        codes = dict(zip(hosts, pool.map(country_lookup, hosts)))

    renamed = []
    for config in configs:
        display_name = f"{brand} {country_flag(codes.get(config.host))} {protocol_label(config)}"
        renamed.append(rename_config(config, display_name))
    return renamed, errors


def write_outputs(
    links: list[str],
    plain_path: Path,
    base64_path: Path,
    mihomo_path: Path,
    provider_path: Path,
) -> tuple[int, int]:
    plain = "\n".join(links) + ("\n" if links else "")
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    plain_path.parent.mkdir(parents=True, exist_ok=True)
    base64_path.parent.mkdir(parents=True, exist_ok=True)
    plain_path.write_text(plain, encoding="utf-8", newline="\n")
    base64_path.write_text(encoded + "\n", encoding="ascii", newline="\n")
    configs = [config for link in links if (config := parse_config(link))]
    mihomo, provider = build_yaml_documents(configs)
    yaml_options = {"allow_unicode": True, "sort_keys": False, "width": 1000}
    mihomo_path.parent.mkdir(parents=True, exist_ok=True)
    provider_path.parent.mkdir(parents=True, exist_ok=True)
    mihomo_path.write_text(yaml.safe_dump(mihomo, **yaml_options), encoding="utf-8", newline="\n")
    provider_path.write_text(yaml.safe_dump(provider, **yaml_options), encoding="utf-8", newline="\n")
    return len(configs), len(provider["proxies"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("sources.txt"))
    parser.add_argument("--output", type=Path, default=Path("subscriptions/all.txt"))
    parser.add_argument("--base64-output", type=Path, default=Path("subscriptions/base64.txt"))
    parser.add_argument("--mihomo-output", type=Path, default=Path("subscriptions/mihomo.yaml"))
    parser.add_argument("--provider-output", type=Path, default=Path("subscriptions/proxies.yaml"))
    parser.add_argument("--geo-db", type=Path, default=Path(".cache/GeoLite2-Country.mmdb"))
    parser.add_argument("--brand", default="@STenmenB")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    sources = read_sources(args.sources)
    if not sources:
        print(f"No sources found in {args.sources}", file=sys.stderr)
        return 2
    try:
        with CountryLookup(args.geo_db) as lookup:
            links, errors = collect(sources, args.timeout, lookup.code_for_host, args.brand)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    if not links:
        print("No supported proxy configurations were found; outputs were not changed.", file=sys.stderr)
        return 1
    _, yaml_count = write_outputs(
        links, args.output, args.base64_output, args.mihomo_output, args.provider_output
    )
    print(
        f"Wrote {len(links)} unique configurations and {yaml_count} YAML proxies "
        f"({len(errors)} source errors)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
