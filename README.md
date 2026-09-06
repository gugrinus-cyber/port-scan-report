# Local Port-Scan Report

A defensive, privacy-first Python utility for summarizing port-scan events from firewall or IDS logs on systems you own.

## What it does

The script extracts source IP addresses, destination ports, timestamps, and event counts from common text-log formats. It produces a Markdown report with source tokens, targeted ports, and conservative response guidance.

Source identifiers are hashed by default so the report is safer to share. The original log remains local.

## What it does not do

This project does not deanonymize people, infer a real-world identity, scrape personal information, contact source addresses, scan networks, exploit services, or launch blocking actions. An IP address is not proof of a person or intent.

## Usage

```bash
python3 port_scan_report.py /var/log/ufw.log --output port_scan_report.md
```

For stable tokens across reports, use a private local salt:

```bash
python3 port_scan_report.py firewall.log --salt "keep-this-local"
```

## Defensive workflow

1. Preserve the original log and timestamp.
2. Review whether the traffic is expected health-check, scanner, or suspicious activity.
3. Patch exposed services and reduce unnecessary network exposure.
4. Use firewall rate limits or deny rules only after validating the event.
5. Escalate with the report and evidence when appropriate.

## Privacy

Do not commit raw firewall logs. The default report intentionally avoids publishing raw source IPs. Treat logs as sensitive operational data.

## License

MIT
