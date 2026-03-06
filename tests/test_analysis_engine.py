"""Tests for the AnalysisEngine finding extractors."""

from analysis_engine import AnalysisEngine


def test_nmap_findings():
    engine = AnalysisEngine()
    history = [{"tool": "nmap", "params": {}, "result": {
        "ports": [
            {"port": "22/tcp", "service": "ssh"},
            {"port": "445/tcp", "service": "microsoft-ds"},
        ]
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 2
    # Port 445 should be High severity
    high = [f for f in findings if f["severity"] == "High"]
    assert len(high) == 1
    assert "445" in high[0]["name"]


def test_sqlmap_vulnerable():
    engine = AnalysisEngine()
    history = [{"tool": "sqlmap", "params": {"url": "http://test.local"}, "result": {
        "vulnerable": True, "banner": "MySQL 5.7",
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"


def test_sqlmap_not_vulnerable():
    engine = AnalysisEngine()
    history = [{"tool": "sqlmap", "params": {"url": "http://test.local"}, "result": {
        "vulnerable": False,
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 0


def test_nuclei_findings():
    engine = AnalysisEngine()
    history = [{"tool": "nuclei", "params": {}, "result": {"findings": [
        {
            "template_id": "cve-2021-44228",
            "name": "Log4Shell",
            "severity": "critical",
            "description": "Remote code execution via Log4j",
            "matched_at": "http://target:8080",
            "cve_id": ["CVE-2021-44228"],
            "cvss_score": 10.0,
        },
    ]}}]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
    assert "CVE-2021-44228" in findings[0]["name"]


def test_hydra_cracked():
    engine = AnalysisEngine()
    history = [{"tool": "hydra", "params": {}, "result": {
        "service": "ssh",
        "credentials": [{"host": "10.0.0.1", "username": "admin", "password": "pass123"}],
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"


def test_sslscan_expired_cert():
    engine = AnalysisEngine()
    history = [{"tool": "sslscan", "params": {}, "result": {
        "target": "example.com:443",
        "data": {
            "vulnerabilities": ["Deprecated protocol enabled: TLS TLSv1.0"],
            "certificate": {"expired": True, "not_after": "2024-01-01", "self_signed": False},
        },
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 2  # deprecated protocol + expired cert
    severities = {f["severity"] for f in findings}
    assert "High" in severities


def test_gobuster_sensitive_dirs():
    engine = AnalysisEngine()
    history = [{"tool": "gobuster", "params": {}, "result": {
        "mode": "dir",
        "results": [
            {"path": "/admin", "status": 200, "size": 1234},
            {"path": "/.git", "status": 403, "size": 0},
            {"path": "/index.html", "status": 200, "size": 5000},
        ],
    }}]
    findings = engine.derive_findings(history)
    sensitive = [f for f in findings if f["severity"] == "High"]
    assert len(sensitive) == 1  # /admin and /.git are sensitive


def test_dns_zone_transfer():
    engine = AnalysisEngine()
    history = [{"tool": "dns_enum", "params": {}, "result": {
        "type": "axfr",
        "records": [{"type": "A", "name": "sub.example.com", "address": "10.0.0.1"}],
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert "zone transfer" in findings[0]["name"].lower()


def test_msf_exploit_success():
    engine = AnalysisEngine()
    history = [{"tool": "msf_exploit", "params": {}, "result": {
        "success": True,
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "sessions_after": {"1": {"type": "meterpreter"}},
    }}]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"


def test_dedupe():
    engine = AnalysisEngine()
    history = [
        {"tool": "nmap", "params": {}, "result": {"ports": [{"port": "80/tcp", "service": "http"}]}},
        {"tool": "nmap", "params": {}, "result": {"ports": [{"port": "80/tcp", "service": "http"}]}},
    ]
    findings = engine.derive_findings(history)
    assert len(findings) == 1
