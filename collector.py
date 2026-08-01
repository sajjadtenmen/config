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


def write_outputs(links: list[str], plain_path: Path, base64_path: Path) -> None:
    plain = "\n".join(links) + ("\n" if links else "")
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    plain_path.parent.mkdir(parents=True, exist_ok=True)
    base64_path.parent.mkdir(parents=True, exist_ok=True)
    plain_path.write_text(plain, encoding="utf-8", newline="\n")
    base64_path.write_text(encoded + "\n", encoding="ascii", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("sources.txt"))
    parser.add_argument("--output", type=Path, default=Path("subscriptions/all.txt"))
    parser.add_argument("--base64-output", type=Path, default=Path("subscriptions/base64.txt"))
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
    write_outputs(links, args.output, args.base64_output)
    print(f"Wrote {len(links)} unique configurations ({len(errors)} source errors).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
