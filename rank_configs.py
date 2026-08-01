#!/usr/bin/env python3
"""URL-test Mihomo proxies and write fastest-first tested subscriptions."""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

import collector


@dataclass(frozen=True)
class Candidate:
    name: str
    link: str
    proxy: dict[str, object]


def build_candidates(links: list[str]) -> list[Candidate]:
    counts: dict[str, int] = {}
    candidates: list[Candidate] = []
    for link in links:
        config = collector.parse_config(link)
        if not config:
            continue
        base_name = collector.config_display_name(config)
        counts[base_name] = counts.get(base_name, 0) + 1
        sequence = counts[base_name]
        name = base_name if sequence == 1 else f"{base_name}-{sequence}"
        proxy = collector.to_mihomo_proxy(config, name)
        if proxy:
            candidates.append(Candidate(name, link, proxy))
    return candidates


def api_json(url: str, timeout: float) -> object:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_mihomo(controller: str, startup_timeout: int) -> None:
    deadline = time.monotonic() + startup_timeout
    version_url = controller.rstrip("/") + "/version"
    while time.monotonic() < deadline:
        try:
            api_json(version_url, 2)
            return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.5)
    raise RuntimeError(f"Mihomo API did not start within {startup_timeout} seconds")


def test_group(
    controller: str,
    group: str,
    test_url: str,
    timeout_ms: int,
    expected: str,
) -> dict[str, int]:
    query = urllib.parse.urlencode(
        {"url": test_url, "timeout": timeout_ms, "expected": expected}
    )
    endpoint = (
        controller.rstrip("/")
        + "/group/"
        + urllib.parse.quote(group, safe="")
        + "/delay?"
        + query
    )
    result = api_json(endpoint, timeout=max(60, timeout_ms / 1000 + 60))
    if not isinstance(result, dict):
        raise RuntimeError("Mihomo group-delay response was not an object")
    return {
        str(name): int(delay)
        for name, delay in result.items()
        if isinstance(delay, (int, float)) and int(delay) > 0
    }


def ranked_candidates(
    candidates: list[Candidate], delays: dict[str, int]
) -> tuple[list[Candidate], list[Candidate]]:
    alive = [candidate for candidate in candidates if candidate.name in delays]
    alive.sort(key=lambda candidate: (delays[candidate.name], candidate.name))
    failed = [candidate for candidate in candidates if candidate.name not in delays]
    return alive, failed


def tested_mihomo_config(
    full_config: dict[str, object], proxies: list[dict[str, object]]
) -> dict[str, object]:
    tested = copy.deepcopy(full_config)
    names = [str(proxy["name"]) for proxy in proxies]
    tested["proxies"] = proxies
    groups = tested.get("proxy-groups", [])
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            if group.get("name") == "♻️ Auto":
                group["proxies"] = names
            elif group.get("name") == "🚀 Proxy":
                group["proxies"] = ["♻️ Auto", "DIRECT", *names]
    return tested


def write_tested_outputs(
    alive: list[Candidate],
    failed: list[Candidate],
    delays: dict[str, int],
    full_config: dict[str, object],
    test_url: str,
    timeout_ms: int,
    plain_path: Path,
    base64_path: Path,
    mihomo_path: Path,
    provider_path: Path,
    latency_path: Path,
) -> None:
    if not alive:
        raise RuntimeError("No proxies passed the URL test; tested outputs were not changed")
    links = [candidate.link for candidate in alive]
    plain = "\n".join(links) + "\n"
    proxies = [candidate.proxy for candidate in alive]
    mihomo = tested_mihomo_config(full_config, proxies)
    provider = {"proxies": proxies}
    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "test_url": test_url,
        "timeout_ms": timeout_ms,
        "total": len(alive) + len(failed),
        "alive": len(alive),
        "failed": len(failed),
        "results": [
            {"name": candidate.name, "delay_ms": delays[candidate.name], "status": "alive"}
            for candidate in alive
        ]
        + [
            {"name": candidate.name, "delay_ms": None, "status": "timeout"}
            for candidate in failed
        ],
    }
    for path in (plain_path, base64_path, mihomo_path, provider_path, latency_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    plain_path.write_text(plain, encoding="utf-8", newline="\n")
    base64_path.write_text(
        base64.b64encode(plain.encode("utf-8")).decode("ascii") + "\n",
        encoding="ascii",
        newline="\n",
    )
    yaml_options = {"allow_unicode": True, "sort_keys": False, "width": 1000}
    mihomo_path.write_text(yaml.safe_dump(mihomo, **yaml_options), encoding="utf-8", newline="\n")
    provider_path.write_text(
        yaml.safe_dump(provider, **yaml_options), encoding="utf-8", newline="\n"
    )
    latency_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", default="http://127.0.0.1:9090")
    parser.add_argument("--group", default="♻️ Auto")
    parser.add_argument("--url", default="https://www.gstatic.com/generate_204")
    parser.add_argument("--timeout", type=int, default=5000, help="Per-proxy timeout in ms")
    parser.add_argument("--expected", default="204")
    parser.add_argument("--startup-timeout", type=int, default=30)
    parser.add_argument("--all", type=Path, default=Path("subscriptions/all.txt"))
    parser.add_argument("--mihomo", type=Path, default=Path("subscriptions/mihomo.yaml"))
    parser.add_argument("--tested", type=Path, default=Path("subscriptions/tested.txt"))
    parser.add_argument(
        "--tested-base64", type=Path, default=Path("subscriptions/tested-base64.txt")
    )
    parser.add_argument(
        "--tested-mihomo", type=Path, default=Path("subscriptions/mihomo-tested.yaml")
    )
    parser.add_argument(
        "--tested-provider", type=Path, default=Path("subscriptions/proxies-tested.yaml")
    )
    parser.add_argument("--latency", type=Path, default=Path("subscriptions/latency.json"))
    args = parser.parse_args()

    links = [line.strip() for line in args.all.read_text(encoding="utf-8").splitlines() if line.strip()]
    candidates = build_candidates(links)
    full_config = yaml.safe_load(args.mihomo.read_text(encoding="utf-8"))
    if not isinstance(full_config, dict):
        raise RuntimeError("Mihomo subscription is not a YAML mapping")
    existing_names = [str(proxy["name"]) for proxy in full_config.get("proxies", [])]
    candidate_names = [candidate.name for candidate in candidates]
    if existing_names != candidate_names:
        raise RuntimeError("TXT and Mihomo subscriptions are not synchronized")

    wait_for_mihomo(args.controller, args.startup_timeout)
    delays = test_group(args.controller, args.group, args.url, args.timeout, args.expected)
    alive, failed = ranked_candidates(candidates, delays)
    write_tested_outputs(
        alive,
        failed,
        delays,
        full_config,
        args.url,
        args.timeout,
        args.tested,
        args.tested_base64,
        args.tested_mihomo,
        args.tested_provider,
        args.latency,
    )
    print(
        f"Wrote {len(alive)} tested proxies in delay order; "
        f"{len(failed)} failed or timed out."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
