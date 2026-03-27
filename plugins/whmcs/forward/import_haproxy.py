#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SECTION_KEYWORDS = {
    "global",
    "defaults",
    "frontend",
    "backend",
    "listen",
    "resolvers",
    "peers",
    "mailers",
    "program",
    "userlist",
    "cache",
}

UNSUPPORTED_SOCKET_PREFIXES = ("unix@", "abns@", "fd@", "/")


@dataclass
class SkipItem:
    section: str
    reason: str
    line: int = 0


@dataclass
class BindTarget:
    host: str
    port: int
    raw: str
    line: int


@dataclass
class BackendServer:
    name: str
    host: str
    port: int
    raw: str
    line: int
    disabled: bool = False


@dataclass
class ProxySection:
    kind: str
    name: str
    line: int
    mode: str = ""
    binds: list[BindTarget] = field(default_factory=list)
    default_backend: str = ""
    servers: list[BackendServer] = field(default_factory=list)
    has_use_backend: bool = False

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name}"


@dataclass
class RuleCandidate:
    section: str
    line: int
    payload: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import simple HAProxy TCP forwarding rules into forward via API."
    )
    parser.add_argument("--url", required=True, help="Base URL, for example http://127.0.0.1:8080")
    parser.add_argument("--token", required=True, help="Bearer token for the forward API")
    parser.add_argument("--file", required=True, help="Path to haproxy.cfg")
    parser.add_argument("--in-interface", default="", help="Default inbound interface for imported rules")
    parser.add_argument("--out-interface", default="", help="Default outbound interface for imported rules")
    parser.add_argument("--tag", default="", help="Tag to apply to imported rules")
    parser.add_argument(
        "--remark-prefix",
        default="HAProxy",
        help="Remark prefix for imported rules (default: HAProxy)",
    )
    parser.add_argument(
        "--transparent",
        action="store_true",
        help="Set transparent=true on imported rules",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and show rules without calling POST /api/rules",
    )
    parser.add_argument(
        "--skip-existing-check",
        action="store_true",
        help="Do not call GET /api/rules before importing",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10)",
    )
    return parser.parse_args()


def strip_comment(line: str) -> str:
    if "#" not in line:
        return line
    return line.split("#", 1)[0]


def is_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False


def parse_port(text: str) -> int:
    raw = text.strip()
    if not raw or "-" in raw:
        raise ValueError("port ranges are not supported")
    port = int(raw)
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def split_host_port(raw: str) -> tuple[str, str]:
    text = raw.strip()
    if not text:
        raise ValueError("empty endpoint")
    if text.startswith(UNSUPPORTED_SOCKET_PREFIXES):
        raise ValueError("unix and fd binds are not supported")
    if text.startswith("["):
        if "]:" not in text:
            raise ValueError("invalid bracketed endpoint")
        host, port = text[1:].split("]:", 1)
        if ":" in host:
            raise ValueError("IPv6 is not supported")
        return host, port
    if ":" not in text:
        return text, ""
    host, port = text.rsplit(":", 1)
    return host, port


def parse_bind_target(raw: str, line: int) -> BindTarget:
    host, port_text = split_host_port(raw)
    host = host.strip()
    if host in {"", "*"}:
        host = "0.0.0.0"
    if not is_ipv4(host):
        raise ValueError("only IPv4 bind addresses are supported")
    return BindTarget(host=host, port=parse_port(port_text), raw=raw.strip(), line=line)


def parse_server_target(raw: str, extra_fields: list[str], line: int) -> tuple[str, int]:
    host, port_text = split_host_port(raw)
    host = host.strip()
    if host in {"", "*", "0.0.0.0"}:
        raise ValueError("invalid backend server address")
    if port_text:
        return host, parse_port(port_text)

    for idx, token in enumerate(extra_fields[:-1]):
        if token.lower() == "port":
            return host, parse_port(extra_fields[idx + 1])
    raise ValueError("backend server port is missing")


def build_remark(prefix: str, section: ProxySection, bind: BindTarget) -> str:
    prefix = prefix.strip()
    suffix = f"{section.kind} {section.name} {bind.host}:{bind.port}"
    return f"{prefix} {suffix}".strip() if prefix else suffix


def parse_haproxy_config(text: str) -> tuple[list[ProxySection], dict[str, ProxySection], list[SkipItem]]:
    sections: list[ProxySection] = []
    backends: dict[str, ProxySection] = {}
    skips: list[SkipItem] = []
    current: ProxySection | None = None
    defaults_mode = ""

    for lineno, original_line in enumerate(text.splitlines(), start=1):
        line = strip_comment(original_line).strip()
        if not line:
            continue

        fields = line.split()
        keyword = fields[0].lower()

        if keyword in SECTION_KEYWORDS:
            name = fields[1] if len(fields) > 1 else keyword
            if keyword == "defaults":
                current = ProxySection(kind=keyword, name=name, line=lineno, mode=defaults_mode)
            elif keyword in {"frontend", "backend", "listen"}:
                current = ProxySection(kind=keyword, name=name, line=lineno, mode=defaults_mode)
                sections.append(current)
                if keyword == "backend":
                    backends[current.name] = current
            else:
                current = None
            continue

        if current is None:
            continue

        if keyword == "mode" and len(fields) > 1:
            current.mode = fields[1].lower()
            if current.kind == "defaults":
                defaults_mode = current.mode
            continue

        if current.kind == "defaults":
            continue

        if keyword == "bind" and current.kind in {"frontend", "listen"} and len(fields) > 1:
            for item in fields[1].split(","):
                try:
                    current.binds.append(parse_bind_target(item, lineno))
                except ValueError as exc:
                    skips.append(SkipItem(current.label, f"skip bind {item!r}: {exc}", lineno))
            continue

        if keyword == "default_backend" and current.kind == "frontend" and len(fields) > 1:
            current.default_backend = fields[1]
            continue

        if keyword == "use_backend" and current.kind == "frontend":
            current.has_use_backend = True
            continue

        if keyword == "server" and current.kind in {"backend", "listen"} and len(fields) > 2:
            disabled = any(token.lower() == "disabled" for token in fields[3:])
            try:
                host, port = parse_server_target(fields[2], fields[3:], lineno)
            except ValueError as exc:
                skips.append(SkipItem(current.label, f"skip server {fields[1]!r}: {exc}", lineno))
                continue
            current.servers.append(
                BackendServer(
                    name=fields[1],
                    host=host,
                    port=port,
                    raw=fields[2],
                    line=lineno,
                    disabled=disabled,
                )
            )

    return sections, backends, skips


def active_servers(section: ProxySection) -> list[BackendServer]:
    return [server for server in section.servers if not server.disabled]


def collect_candidates(
    sections: list[ProxySection],
    backends: dict[str, ProxySection],
    args: argparse.Namespace,
) -> tuple[list[RuleCandidate], list[SkipItem]]:
    candidates: list[RuleCandidate] = []
    skips: list[SkipItem] = []

    for section in sections:
        if section.kind not in {"frontend", "listen"}:
            continue

        if section.mode and section.mode != "tcp":
            skips.append(SkipItem(section.label, f"mode {section.mode!r} is not supported", section.line))
            continue

        if section.has_use_backend:
            skips.append(SkipItem(section.label, "conditional use_backend rules are not supported", section.line))
            continue

        if not section.binds:
            skips.append(SkipItem(section.label, "no importable bind address found", section.line))
            continue

        target_section = section
        if section.kind == "frontend":
            if not section.default_backend:
                skips.append(SkipItem(section.label, "missing default_backend", section.line))
                continue
            target_section = backends.get(section.default_backend)
            if target_section is None:
                skips.append(
                    SkipItem(
                        section.label,
                        f"default_backend {section.default_backend!r} was not found",
                        section.line,
                    )
                )
                continue
            if target_section.mode and target_section.mode != "tcp":
                skips.append(
                    SkipItem(
                        section.label,
                        f"backend {target_section.name!r} uses mode {target_section.mode!r}",
                        target_section.line,
                    )
                )
                continue

        servers = active_servers(target_section)
        if len(servers) != 1:
            skips.append(
                SkipItem(
                    section.label,
                    f"requires exactly one enabled backend server, found {len(servers)}",
                    target_section.line,
                )
            )
            continue

        server = servers[0]
        for bind in section.binds:
            candidates.append(
                RuleCandidate(
                    section=section.label,
                    line=bind.line,
                    payload={
                        "in_interface": args.in_interface,
                        "in_ip": bind.host,
                        "in_port": bind.port,
                        "out_interface": args.out_interface,
                        "out_ip": server.host,
                        "out_port": server.port,
                        "protocol": "tcp",
                        "remark": build_remark(args.remark_prefix, section, bind),
                        "tag": args.tag,
                        "transparent": bool(args.transparent),
                    },
                )
            )

    return candidates, skips


def tcp_conflicts(protocol: str) -> bool:
    return (protocol or "").strip().lower() in {"tcp", "tcp+udp"}


def filter_conflicts(
    candidates: list[RuleCandidate],
    existing_rules: list[dict[str, Any]],
) -> tuple[list[RuleCandidate], list[SkipItem]]:
    kept: list[RuleCandidate] = []
    skips: list[SkipItem] = []
    existing_claims: dict[tuple[str, int], dict[str, Any]] = {}
    planned_claims: dict[tuple[str, int], RuleCandidate] = {}

    for rule in existing_rules:
        if not tcp_conflicts(str(rule.get("protocol", ""))):
            continue
        key = (str(rule.get("in_ip", "")), int(rule.get("in_port", 0) or 0))
        if key[1] > 0:
            existing_claims[key] = rule

    for candidate in candidates:
        key = (
            str(candidate.payload["in_ip"]),
            int(candidate.payload["in_port"]),
        )
        if key in existing_claims:
            existing = existing_claims[key]
            skips.append(
                SkipItem(
                    candidate.section,
                    (
                        "conflicts with existing rule "
                        f"#{existing.get('id')} ({key[0]}:{key[1]})"
                    ),
                    candidate.line,
                )
            )
            continue
        if key in planned_claims:
            first = planned_claims[key]
            skips.append(
                SkipItem(
                    candidate.section,
                    (
                        "conflicts with another imported rule from "
                        f"{first.section} ({key[0]}:{key[1]})"
                    ),
                    candidate.line,
                )
            )
            continue
        planned_claims[key] = candidate
        kept.append(candidate)

    return kept, skips


def api_request(
    base_url: str,
    token: str,
    method: str,
    path: str,
    timeout: float,
    payload: dict[str, Any] | None = None,
) -> Any:
    data: bytes | None = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=base_url.rstrip("/") + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace").strip()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        message = body or exc.reason
        try:
            parsed = json.loads(body)
            message = parsed.get("error") or parsed.get("message") or message
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"{method} {path} failed: {exc.code} {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {path} failed: {exc.reason}") from exc


def print_candidates(title: str, candidates: list[RuleCandidate]) -> None:
    print(title)
    for candidate in candidates:
        rule = candidate.payload
        print(
            "  + "
            f"[{candidate.section}] "
            f"{rule['in_ip']}:{rule['in_port']} -> {rule['out_ip']}:{rule['out_port']}"
        )


def print_skips(skips: list[SkipItem]) -> None:
    if not skips:
        return
    print("Skipped:")
    for item in skips:
        prefix = f"  - [{item.section}]"
        if item.line:
            prefix += f" line {item.line}"
        print(f"{prefix}: {item.reason}")


def main() -> int:
    args = parse_args()
    config_path = Path(args.file)
    if not config_path.is_file():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 2

    config_text = config_path.read_text(encoding="utf-8")
    sections, backends, parse_skips = parse_haproxy_config(config_text)
    candidates, collect_skips = collect_candidates(sections, backends, args)

    existing_rules: list[dict[str, Any]] = []
    if not args.skip_existing_check:
        try:
            existing_rules = api_request(args.url, args.token, "GET", "/api/rules", args.timeout) or []
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    candidates, conflict_skips = filter_conflicts(candidates, existing_rules)
    all_skips = [*parse_skips, *collect_skips, *conflict_skips]

    if not candidates and all_skips:
        print("No rules can be imported from the provided HAProxy config.")
        print_skips(all_skips)
        return 1

    if not candidates:
        print("No importable rules were found.")
        return 1

    print_candidates("Planned rules:", candidates)
    print_skips(all_skips)

    if args.dry_run:
        print(f"Dry run complete: {len(candidates)} rule(s) ready to import.")
        return 0

    created = 0
    failures = 0
    for candidate in candidates:
        try:
            api_request(args.url, args.token, "POST", "/api/rules", args.timeout, candidate.payload)
            created += 1
        except RuntimeError as exc:
            failures += 1
            print(
                f"Failed to import [{candidate.section}] "
                f"{candidate.payload['in_ip']}:{candidate.payload['in_port']}: {exc}",
                file=sys.stderr,
            )

    print(
        f"Import finished: created={created}, failed={failures}, skipped={len(all_skips)}."
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
