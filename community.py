"""Build a ranked VLESS-only community subscription from public feeds."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import re
import shutil
import socket
import subprocess
import tempfile
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


# These feeds are maintained specifically for Russian networks.  Generic global
# aggregators are intentionally excluded: reachability from GitHub Actions says
# nothing about reachability through a Russian mobile operator's DPI/allowlist.
SOURCES = (
    Source(
        "aetris_mobile_whitelist", "RU-LTE·Aetris",
        "https://raw.githubusercontent.com/flaafix/AetrisVPN-white-list-lite/"
        "refs/heads/main/AetrisVPN.txt", 135,
    ),
    Source(
        "igareck_mobile_whitelist", "RU-LTE·Whitelist",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
        "Vless-Reality-White-Lists-Rus-Mobile.txt", 130,
    ),
    Source(
        "igareck_cidr_whitelist", "RU-LTE·CIDR",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
        "WHITE-CIDR-RU-all.txt", 125,
    ),
    Source(
        "igareck_sni_whitelist", "RU-LTE·SNI",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
        "WHITE-SNI-RU-all.txt", 120,
    ),
    Source(
        "vsv_mobile_whitelist", "RU-LTE·RKN",
        "https://raw.githubusercontent.com/vsvavan2/vpn-config-rkn/main/output/"
        "WHITE_Reality_Mobile_working.txt", 110,
    ),
    Source(
        "igareck_mobile_regular", "RU-Mobile·Regular",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
        "BLACK_VLESS_RUS_mobile.txt", 95,
    ),
    Source(
        "aviamasters_ru", "RU-Mobile·Reserve",
        "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/ru_configs.txt", 85,
    ),
)

COUNTRY_NAMES = {
    "AT": "Austria", "CA": "Canada", "CH": "Switzerland", "DE": "Germany",
    "BG": "Bulgaria", "FI": "Finland", "FR": "France", "GB": "UK",
    "JP": "Japan", "NL": "Netherlands", "NO": "Norway", "PL": "Poland",
    "RU": "Russia", "SE": "Sweden",
    "SG": "Singapore", "TR": "Turkey", "UA": "Ukraine", "US": "USA",
}

def country_flag(code: str | None) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(char)) for char in code.upper())


def detect_country(text: str) -> str | None:
    lowered = text.lower()
    if (
        "🇷🇺" in text or "росси" in lowered or "russia" in lowered
        or lowered.endswith(".ru") or re.search(r"(?:^|[.\-_])ru\d*(?:[.\-_]|$)", lowered)
    ):
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
    live_ms: float | None = None
    telegram_verified: bool = False
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
        country=detect_country(original_name) or detect_country(host),
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


def geolocate_endpoints(nodes: list[Node]) -> None:
    """Set countries from resolved endpoint IPs, never from an upstream label."""
    host_ips: dict[str, str] = {}
    for node in nodes:
        try:
            answers = socket.getaddrinfo(node.host, node.port, type=socket.SOCK_STREAM)
            host_ips[node.host] = answers[0][4][0]
        except OSError:
            node.errors.append("dns_failed")

    countries: dict[str, str] = {}
    ips = sorted(set(host_ips.values()))
    for offset in range(0, len(ips), 100):
        payload = json.dumps(ips[offset:offset + 100]).encode()
        request = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,query,countryCode",
            data=payload, headers={"Content-Type": "application/json", "User-Agent": "MyVPN/0.1"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            results = json.load(response)
        for item in results:
            if item.get("status") == "success" and item.get("countryCode"):
                countries[str(item["query"])] = str(item["countryCode"]).upper()

    for node in nodes:
        endpoint_ip = host_ips.get(node.host)
        node.country = countries.get(endpoint_ip or "")
        if node.country is None:
            node.errors.append("country_unknown")


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
    latency = node.live_ms or node.proxy_ms or node.tcp_ms
    if latency is None or node.errors:
        return 0
    latency_score = max(0, 40 - latency / 75)
    verified_score = 35 if node.telegram_verified else (20 if node.proxy_ms is not None else 0)
    security_score = 15 if node.security == "reality" else 10
    source_score = node.source.trust / 10
    speed_score = min(5, math.log2(1 + node.speed_mbps)) if node.speed_mbps else 0
    return round(
        latency_score + verified_score + security_score + source_score + speed_score, 2
    )


def display_name(node: Node, rank: int) -> str:
    latency = node.live_ms or node.proxy_ms or node.tcp_ms
    prefix = "" if node.live_ms is not None else ("upstream " if node.proxy_ms is not None else "TCP ")
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


def sing_box_config(node: Node, port: int) -> dict[str, Any] | None:
    parsed = urlsplit(node.uri)
    params = dict(parse_qsl(parsed.query))
    outbound: dict[str, Any] = {
        "type": "vless", "tag": "proxy", "server": node.host,
        "server_port": node.port, "uuid": parsed.username,
    }
    if params.get("flow"):
        outbound["flow"] = params["flow"]
    tls: dict[str, Any] = {"enabled": True, "server_name": params.get("sni", node.host)}
    if params.get("fp"):
        fingerprint = "chrome" if params["fp"] == "randomized" else params["fp"]
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if node.security == "reality":
        tls["reality"] = {
            "enabled": True, "public_key": params.get("pbk", ""),
            "short_id": params.get("sid", ""),
        }
    outbound["tls"] = tls
    if node.transport == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", "")}
    elif node.transport == "ws":
        outbound["transport"] = {
            "type": "ws", "path": params.get("path", "/"),
            "headers": {"Host": params.get("host", params.get("sni", node.host))},
        }
    elif node.transport != "tcp":
        return None
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


async def live_probe(node: Node, index: int, semaphore: asyncio.Semaphore) -> None:
    config = sing_box_config(node, 32000 + index)
    if not config:
        node.errors.append("unsupported_by_probe")
        return
    async with semaphore:
        with tempfile.NamedTemporaryFile("w", suffix=".json") as config_file:
            json.dump(config, config_file)
            config_file.flush()
            process = await asyncio.create_subprocess_exec(
                "sing-box", "run", "-c", config_file.name,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(0.35)
            if process.returncode is not None:
                node.errors.append("sing_box_start_failed")
                return
            start = asyncio.get_running_loop().time()
            curl = await asyncio.create_subprocess_exec(
                "curl", "--silent", "--show-error", "--max-time", "8",
                "--proxy", f"socks5h://127.0.0.1:{32000 + index}",
                "--output", "/dev/null", "--write-out", "%{http_code}",
                "https://telegram.org/", stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            output, _ = await curl.communicate()
            if curl.returncode == 0 and output.decode() in {"200", "301", "302"}:
                node.telegram_verified = True
                node.live_ms = round((asyncio.get_running_loop().time() - start) * 1000, 1)
                speed = await asyncio.create_subprocess_exec(
                    "curl", "--silent", "--show-error", "--max-time", "12",
                    "--proxy", f"socks5h://127.0.0.1:{32000 + index}",
                    "--output", "/dev/null", "--write-out", "%{speed_download}",
                    "https://proof.ovh.net/files/1Mb.dat",
                    stdout=asyncio.subprocess.PIPE, stderr=subprocess.DEVNULL,
                )
                speed_output, _ = await speed.communicate()
                try:
                    measured = round(float(speed_output.decode()) * 8 / 1_000_000, 2)
                    node.speed_mbps = measured if measured > 0 else None
                except ValueError:
                    node.speed_mbps = None
            else:
                node.errors.append("telegram_probe_failed")
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()


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

    await asyncio.to_thread(geolocate_endpoints, nodes)
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
    # Every TCP-reachable candidate must get the real VLESS+Telegram probe.  The
    # former condition accidentally admitted only nodes carrying an upstream
    # report, effectively preventing all other feeds from ever being tested.
    preliminary = sorted(
        (node for node in nodes if node.tcp_ms is not None and not node.errors),
        key=lambda node: (-node.source.trust, node.tcp_ms or 99999),
    )[:120]
    if not shutil.which("sing-box"):
        raise RuntimeError("sing-box is required for live Telegram verification")
    live_semaphore = asyncio.Semaphore(10)
    await asyncio.gather(
        *(live_probe(node, index, live_semaphore) for index, node in enumerate(preliminary))
    )
    for node in nodes:
        node.score = calculate_score(node)
    ranked = sorted(
        (
            node for node in nodes
            if node.score > 0 and node.telegram_verified
            and node.speed_mbps is not None and node.speed_mbps >= 1.0
        ),
        key=lambda node: node.score, reverse=True,
    )

    selected: list[Node] = []
    source_counts: dict[str, int] = {}
    host_counts: dict[str, int] = {}
    for node in ranked:
        source_cap = max_output if node.proxy_ms is not None else max(3, max_output // 2)
        if source_counts.get(node.source.key, 0) >= source_cap:
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
        "policy": {
            "excluded_countries": ["RU"], "require_telegram_probe": True,
            "network_diversity": "one_profile_per_host",
            "lte_status": "unverified_until_user_feedback",
        },
        "sources": source_stats, "excluded_ru": excluded_ru,
        "candidates": len(nodes), "published": len(links), "nodes": report_nodes,
    }
    return links, report


def write_outputs(output: Path, links: list[str], report: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    raw = "\n".join(links) + "\n"
    (output / "vless.txt").write_text(raw)
    (output / "happ.txt").write_text(raw)
    encoded = base64.b64encode(raw.encode()).decode() + "\n"
    (output / "vless-base64.txt").write_text(encoded)
    (output / "subscription.txt").write_text(encoded)
    (output / "karing.txt").write_text(encoded)
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
