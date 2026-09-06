# Local Port-Scan Report

[![CI](https://github.com/gugrinus-cyber/port-scan-report/actions/workflows/ci.yml/badge.svg)](https://github.com/gugrinus-cyber/port-scan-report/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Defensive security](https://img.shields.io/badge/Security-defensive--only-2E8B57)](#safety-boundaries)
[![Privacy by default](https://img.shields.io/badge/Privacy-hashed--identifiers-6f42c1)](#privacy)

> A defensive, privacy-first Python utility for summarizing port-scan events from firewall or IDS logs on systems you own.

## What it does

The script extracts source IP addresses, destination ports, timestamps, and event counts from common text-log formats. It produces a Markdown report with source tokens, targeted ports, and conservative response guidance.

Source identifiers are hashed by default so the report is safer to share. The original log remains local.

## Quick start

```bash
python3 port_scan_report.py /var/log/ufw.log --output port_scan_report.md
```

For stable tokens across reports, use a private local salt:

```bash
python3 port_scan_report.py firewall.log --salt "keep-this-local"
```

## Safety boundaries

This project does **not** deanonymize people, infer real-world identity, scrape personal information, contact source addresses, scan networks, exploit services, or launch blocking actions. An IP address is not proof of a person or intent.

## Defensive workflow

1. Preserve the original log and timestamp.
2. Review whether the traffic is an expected health check, scanner, or suspicious event.
3. Patch exposed services and reduce unnecessary network exposure.
4. Use firewall rate limits or deny rules only after validating the event.
5. Escalate with the report and evidence when appropriate.

## Privacy

Do not commit raw firewall logs. The default report intentionally avoids publishing raw source IPs. Treat logs as sensitive operational data.

## Recruiter signal

This project demonstrates defensive Python automation, log parsing, privacy-aware reporting, incident-response thinking, and careful separation between observable network evidence and unsupported attribution.

## License

MIT
