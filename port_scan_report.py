#!/usr/bin/env python3
"""Summarize local port-scan events from firewall/IDS text logs.

This tool is for incident response on systems you own. It aggregates source
addresses, destination ports, first/last seen times, and event counts. Source
identifiers are hashed by default so the report is safer to share. It does not
identify people, bypass privacy controls, scan networks, or launch actions.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from pathlib import Path

IP_RE = re.compile(r"(?<![\w:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})(?![\w:])")
PORT_RE = re.compile(r"(?:dpt|dst_port|destination_port|port)[=:\s]+(\d{1,5})", re.I)
TIME_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}[T\s][\d:.+-]+)")


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def token(value: str, salt: str) -> str:
    return hashlib.sha256((salt + value).encode()).hexdigest()[:12]


def analyze(path: Path, salt: str) -> str:
    events = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        ips = [x for x in IP_RE.findall(line) if valid_ip(x)]
        if not ips:
            continue
        port_match = PORT_RE.search(line)
        port = port_match.group(1) if port_match else "unknown"
        timestamp = TIME_RE.search(line)
        timestamp = timestamp.group(1) if timestamp else "unknown"
        events.append({"source": ips[0], "port": port, "time": timestamp, "line": line_no})

    by_source = Counter(e["source"] for e in events)
    by_port = Counter(e["port"] for e in events)
    source_ports = defaultdict(set)
    for e in events:
        source_ports[e["source"]].add(e["port"])

    lines = ["# Local Port-Scan Report", "", f"Source log: `{path.name}`", f"Events parsed: **{len(events)}**", "", "## Source summary", "", "| Source token | Events | Ports targeted |", "|---|---:|---:|"]
    for source, count in by_source.most_common():
        ports = ", ".join(sorted(source_ports[source], key=lambda x: (x == "unknown", x)))
        lines.append(f"| `{token(source, salt)}` | {count} | {ports} |")
    lines += ["", "## Targeted ports", "", "| Port | Events |", "|---|---:|"]
    lines += [f"| {port} | {count} |" for port, count in by_port.most_common()]
    lines += ["", "## Response guidance", "", "- Review the original local log before blocking anything.", "- Check whether the event is expected scanner traffic, a health check, or an actual threat.", "- Prefer firewall rate limits, least-privilege exposure, patching, and monitoring over personal attribution.", "- Preserve timestamps and evidence if escalation is required.", "", "> Privacy and safety: identifiers are hashed by default. This report does not deanonymize people, infer identity, scrape personal data, contact sources, or perform scans."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze local firewall/IDS port-scan logs")
    ap.add_argument("log_file", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path("port_scan_report.md"))
    ap.add_argument("--salt", default="local-report", help="Local salt for stable non-reversible source tokens")
    args = ap.parse_args()
    args.output.write_text(analyze(args.log_file, args.salt), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
