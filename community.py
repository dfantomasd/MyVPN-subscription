"""Build a ranked VLESS-only community subscription from public feeds."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import re
import socket
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    url: str
    trust: int
    report_url: str | None = None


SOURCES = (
    Source(
        "free_nodes", "FreeNodes",
        "https://735754647.github.io/Free-Nodes/v2ray-raw.txt", 100,
        "https://735754647.github.io/Free-Nodes/report.json",
    ),
    Source(
        "radikal", "Radikal",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt", 75,
    ),
    Source(
        "vestra", "Vestra",
        "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/vless.txt", 75,
    ),
    Source(
        "free_proxy_ru", "FreeProxyRU",
        "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt", 60,
    ),
)

COUNTRY_NAMES = {
    "AT": "Austria", "CA": "Canada", "CH": "Switzerland", "DE": "Germany",
    "FI": "Finland", "FR": "France", "GB": "UK", "JP": "Japan",
    "NL": "Netherlands", "PL": "Poland", "RU": "Russia", "SE": "Sweden",
    "SG": "Singapore", "TR": "Turkey", "UA": "Ukraine", "US": "USA",
}


def country_flag(code: str | None) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(char)) for char in code.upper())


def detect_country(text: str) -> str | None:
    if "🇷🇺" in text or "росси" in text.lower() or "russia" in text.lower():
        return "RU"
    match = re.search(r"(?:^|[| _\-])([A-Z]{2})(?:$|[| _\-])", text.upper())
    if match and match.group(1) in COUNTRY_NAMES:
        return match.group(1)
    for code, name in COUNTRY_NAMES.items():
        if name.lower() in text.lower():
            return code
    return None


@dataclass
class Node:
    source: Source
    uri: str
    node_id: str
    host: str
    port: int
    security: str
    transport: str
    original_name: str
    country: str | None
    tcp_ms: float | None = None
    proxy_ms: float | None = None
    speed_mbps: float | None = None
    score: float = 0
    errors: list[str] = field(default_factory=list)

    @property
    def dedupe_key(self) -> str:
        parsed = urlsplit(self.uri)
        params = tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return json.dumps([parsed.username, self.host.lower(), self.port, params])


def parse_vless(uri: str, source: Source) -> Node | None:
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        return None
    try:
        parsed = urlsplit(uri)
        user_id = unquote(parsed.username or "")
        uuid.UUID(user_id)
        host = parsed.hostname or ""
        port = parsed.port
        if not host or not port or not 1 <= port <= 65535:
            return None
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (ValueError, OSError):
        return None
    params = {key.lower(): value for key, value in parse_qsl(parsed.query)}
    security = params.get("security", "none").lower()
    if security not in {"tls", "reality"}:
        return None
    if params.get("allowinsecure", "0").lower() in {"1", "true", "yes"}:
        return None
    transport = params.get("type", "tcp").lower()
    if transport not in {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}:
        return None
    original_name = unquote(parsed.fragment) or f"{host}:{port}"
    node_id = hashlib.sha256(uri.split("#", 1)[0].encode()).hexdigest()[:12]
    return Node(
        source=source, uri=uri, node_id=node_id, host=host, port=port,
        security=security, transport=transport, original_name=original_name,
        country=detect_country(original_name),
    )


def extract_uris(body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="ignore").strip()
    direct = re.findall(r"vless://[^\s\"'<>]+", text, flags=re.IGNORECASE)
    if direct:
        return direct
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode(errors="ignore")
    except (ValueError, UnicodeDecodeError):
        return []
    return re.findall(r"vless://[^\s\"'<>]+", decoded, flags=re.IGNORECASE)


def fetch(url: str, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "MyVPN/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} from {url}")
        return response.read(20_000_000)


def stable_sample(items: list[str], limit: int) -> list[str]:
    unique = set(items)
    return sorted(unique, key=lambda item: hashlib.sha256(item.encode()).digest())[:limit]


async def tcp_probe(node: Node, semaphore: asyncio.Semaphore, timeout: float) -> None:
    async with semaphore:
        start = asyncio.get_running_loop().time()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(node.host, node.port), timeout=timeout
            )
            node.tcp_ms = round((asyncio.get_running_loop().time() - start) * 1000, 1)
            writer.close()
            await writer.wait_closed()
        except (OSError, TimeoutError):
            node.errors.append("tcp_unreachable")


def apply_upstream_report(nodes: list[Node], report: dict[str, Any]) -> None:
    metrics = {
        (str(item.get("server", "")).lower(), int(item.get("port", 0))): item
        for item in report.get("nodes", []) if item.get("type") == "vless"
    }
    for node in nodes:
        item = metrics.get((node.host.lower(), node.port))
        if not item:
            continue
        if item.get("latency_ms") is not None:
            node.proxy_ms = float(item["latency_ms"])
        if item.get("speed_mbps") is not None:
            node.speed_mbps = float(item["speed_mbps"])
        if item.get("country_code"):
            node.country = str(item["country_code"]).upper()


def calculate_score(node: Node) -> float:
    latency = node.proxy_ms if node.proxy_ms is not None else node.tcp_ms
    if latency is None or node.errors:
        return 0
    latency_score = max(0, 40 - latency / 12)
    verified_score = 30 if node.proxy_ms is not None else 0
    security_score = 15 if node.security == "reality" else 10
    source_score = node.source.trust / 10
    speed_score = min(5, math.log2(1 + node.speed_mbps)) if node.speed_mbps else 0
    return round(
        latency_score + verified_score + security_score + source_score + speed_score, 2
    )


def display_name(node: Node, rank: int) -> str:
    latency = node.proxy_ms if node.proxy_ms is not None else node.tcp_ms
    prefix = "" if node.proxy_ms is not None else "TCP "
    ping = f"{prefix}{latency:.0f}ms" if latency is not None else "ping—"
    speed = f"{node.speed_mbps:.0f}Mbps" if node.speed_mbps is not None else "speed—"
    country = node.country or "XX"
    security = "Reality" if node.security == "reality" else "TLS"
    return (
        f"{country_flag(node.country)} {country} · #{rank:02d} · {ping} · "
        f"{speed} · {security} · {node.source.label}"
    )


def named_uri(node: Node, rank: int) -> str:
    parsed = urlsplit(node.uri)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, quote(display_name(node, rank))))


async def build(limit_per_source: int, max_output: int, timeout: float) -> tuple[list[str], dict[str, Any]]:
    nodes: list[Node] = []
    source_stats: dict[str, dict[str, Any]] = {}
    for source in SOURCES:
        try:
            uris = extract_uris(await asyncio.to_thread(fetch, source.url))
            sampled = stable_sample(uris, limit_per_source)
            parsed = [node for uri in sampled if (node := parse_vless(uri, source))]
            if source.report_url:
                report = json.loads((await asyncio.to_thread(fetch, source.report_url)).decode())
                apply_upstream_report(parsed, report)
            nodes.extend(parsed)
            source_stats[source.key] = {"fetched": len(uris), "accepted": len(parsed)}
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            source_stats[source.key] = {"error": str(exc)}

    excluded_ru = sum(node.country == "RU" for node in nodes)
    nodes = [node for node in nodes if node.country != "RU"]
    deduped: dict[str, Node] = {}
    for node in nodes:
        current = deduped.get(node.dedupe_key)
        if current is None or node.source.trust > current.source.trust:
            deduped[node.dedupe_key] = node
    nodes = list(deduped.values())
    semaphore = asyncio.Semaphore(100)
    await asyncio.gather(*(tcp_probe(node, semaphore, timeout) for node in nodes))
    for node in nodes:
        node.score = calculate_score(node)
    ranked = sorted((node for node in nodes if node.score > 0), key=lambda node: node.score, reverse=True)

    selected: list[Node] = []
    source_counts: dict[str, int] = {}
    host_counts: dict[str, int] = {}
    for node in ranked:
        if source_counts.get(node.source.key, 0) >= max(3, max_output // 2):
            continue
        if host_counts.get(node.host, 0) >= 1:
            continue
        selected.append(node)
        source_counts[node.source.key] = source_counts.get(node.source.key, 0) + 1
        host_counts[node.host] = 1
        if len(selected) >= max_output:
            break

    links = [named_uri(node, index) for index, node in enumerate(selected, 1)]
    report_nodes = []
    for index, node in enumerate(selected, 1):
        item = asdict(node)
        item["source"] = node.source.key
        item["display_name"] = display_name(node, index)
        item.pop("uri")
        report_nodes.append(item)
    report = {
        "version": 1, "generated_at": datetime.now(UTC).isoformat(),
        "policy": {"excluded_countries": ["RU"]},
        "sources": source_stats, "excluded_ru": excluded_ru,
        "candidates": len(nodes), "published": len(links), "nodes": report_nodes,
    }
    return links, report


def write_outputs(output: Path, links: list[str], report: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    raw = "\n".join(links) + "\n"
    (output / "vless.txt").write_text(raw)
    (output / "vless-base64.txt").write_text(base64.b64encode(raw.encode()).decode() + "\n")
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("public"))
    parser.add_argument("--limit-per-source", type=int, default=200)
    parser.add_argument("--max-output", type=int, default=30)
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    links, report = asyncio.run(build(args.limit_per_source, args.max_output, args.timeout))
    if not links:
        raise SystemExit("No healthy VLESS nodes found; keeping the previous publication")
    write_outputs(args.output, links, report)
    print(f"Published {len(links)} VLESS nodes from {report['candidates']} candidates")


if __name__ == "__main__":
    main()
