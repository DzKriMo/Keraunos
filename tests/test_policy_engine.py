import json

from policy_engine import PolicyEngine


def test_policy_denies_blocked_flag(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_data = {
        "allowed_tools": ["nmap"],
        "blocked_flags": {"nmap": ["-sU"]},
        "require_confirmation_for_risk": ["high"],
    }
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")
    engine = PolicyEngine(str(policy_path))

    allowed, reason, needs_confirmation = engine.evaluate(
        "nmap", {"flags": "-sV -sU"}, "127.0.0.1", "medium"
    )

    assert not allowed
    assert "Blocked flag pattern" in reason
    assert not needs_confirmation


def test_policy_requires_confirmation_for_high_risk(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_data = {
        "allowed_tools": ["sqlmap"],
        "blocked_flags": {},
        "require_confirmation_for_risk": ["high"],
    }
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")
    engine = PolicyEngine(str(policy_path))

    allowed, _, needs_confirmation = engine.evaluate(
        "sqlmap", {"url": "http://127.0.0.1"}, "127.0.0.1", "high"
    )

    assert allowed
    assert needs_confirmation
