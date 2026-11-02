import pytest
from cli import analyze_traffic, MOCK_FLOW_RECORDS


def test_port_scan_detection():
    port_scans, _ = analyze_traffic(MOCK_FLOW_RECORDS)
    assert "198.51.100.12" in port_scans
    assert len(port_scans["198.51.100.12"]) >= 4
    assert 22 in port_scans["198.51.100.12"]
    assert 3389 in port_scans["198.51.100.12"]


def test_exfiltration_detection():
    _, exfil = analyze_traffic(MOCK_FLOW_RECORDS)
    assert len(exfil) == 1
    record = exfil[0]
    assert record["src"] == "10.0.2.14"
    assert record["dst"] == "203.0.113.88"
    assert record["bytes"] > 500 * 1024 * 1024


def test_benign_traffic_filtered():
    port_scans, exfil = analyze_traffic([
        {"src": "10.0.1.10", "dst": "10.0.2.20", "srcport": 42100, "dstport": 5432, "action": "ACCEPT", "bytes": 4096, "proto": 6}
    ])
    assert len(port_scans) == 0
    assert len(exfil) == 0
