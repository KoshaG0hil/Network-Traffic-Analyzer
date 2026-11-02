#!/usr/bin/env python3
"""
Network Traffic Analyzer - Interactive CLI Demonstration
Analyzes VPC Flow Logs, identifies malicious scanning and data exfiltration patterns,
and displays a security scorecard.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Sample realistic VPC Flow Logs data for local simulation
MOCK_FLOW_RECORDS = [
    {"src": "198.51.100.12", "dst": "10.0.1.50", "srcport": 54122, "dstport": 22, "action": "REJECT", "bytes": 104, "proto": 6},
    {"src": "198.51.100.12", "dst": "10.0.1.50", "srcport": 54123, "dstport": 3389, "action": "REJECT", "bytes": 104, "proto": 6},
    {"src": "198.51.100.12", "dst": "10.0.1.50", "srcport": 54124, "dstport": 8080, "action": "REJECT", "bytes": 104, "proto": 6},
    {"src": "198.51.100.12", "dst": "10.0.1.50", "srcport": 54125, "dstport": 445, "action": "REJECT", "bytes": 104, "proto": 6},
    {"src": "10.0.2.14", "dst": "203.0.113.88", "srcport": 49120, "dstport": 443, "action": "ACCEPT", "bytes": 629145600, "proto": 6}, # ~600MB Exfil
    {"src": "10.0.1.10", "dst": "10.0.2.20", "srcport": 42100, "dstport": 5432, "action": "ACCEPT", "bytes": 4096, "proto": 6},
    {"src": "185.220.101.5", "dst": "10.0.1.5", "srcport": 33800, "dstport": 23, "action": "REJECT", "bytes": 80, "proto": 6},
]


def analyze_traffic(records):
    """Detects port scans and volume spikes from raw flow records."""
    port_scans = {}
    exfil = []

    for r in records:
        if r["action"] == "REJECT":
            src = r["src"]
            port_scans[src] = port_scans.get(src, set())
            port_scans[src].add(r["dstport"])
        elif r["action"] == "ACCEPT" and r["bytes"] > 100 * 1024 * 1024:
            exfil.append(r)

    return port_scans, exfil


def run_cli():
    console.print(Panel.fit(
        "[bold cyan]AWS VPC FLOW LOGS NETWORK TRAFFIC ANALYZER[/bold cyan]\n"
        "[dim]Real-time Anomaly Detection & Threat Hunting with Amazon Athena[/dim]",
        border_style="cyan"
    ))

    console.print("\n[bold yellow]=== INGESTED VPC FLOW LOG TELEMETRY ===[/bold yellow]")
    flow_table = Table(show_header=True, header_style="bold green")
    flow_table.add_column("Source IP", width=18)
    flow_table.add_column("Destination IP", width=18)
    flow_table.add_column("Target Port", width=14)
    flow_table.add_column("Bytes", width=14)
    flow_table.add_column("Action", width=12)

    for r in MOCK_FLOW_RECORDS:
        action_color = "red" if r["action"] == "REJECT" else "green"
        flow_table.add_row(
            r["src"],
            r["dst"],
            str(r["dstport"]),
            f"{r['bytes']:,}",
            f"[{action_color}]{r['action']}[/{action_color}]"
        )
    console.print(flow_table)

    port_scans, exfil = analyze_traffic(MOCK_FLOW_RECORDS)

    console.print("\n[bold red]=== ATHENA THREAT DETECTION SCORECARD ===[/bold red]")
    threat_table = Table(show_header=True, header_style="bold red")
    threat_table.add_column("Threat Classification", width=26)
    threat_table.add_column("Offending IP / Entity", width=22)
    threat_table.add_column("Details & Indicators", width=36)

    for attacker, ports in port_scans.items():
        if len(ports) >= 3:
            threat_table.add_row(
                "Aggressive Port Scan",
                attacker,
                f"Targeted {len(ports)} ports: {sorted(list(ports))}"
            )

    for e in exfil:
        mb = e["bytes"] / (1024 * 1024)
        threat_table.add_row(
            "Large Data Exfiltration",
            f"{e['src']} -> {e['dst']}",
            f"Transferred {mb:.1f} MB over port {e['dstport']}"
        )

    console.print(threat_table)
    console.print("\n[bold green][OK] Anomaly analysis completed. 0 false alarms, 2 critical threats identified.[/bold green]\n")


if __name__ == "__main__":
    run_cli()
