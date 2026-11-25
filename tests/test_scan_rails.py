import subprocess

import pytest

from cybot.demo_app import create_demo_app, serve
from cybot.rails import ScanBudget, argv_is_safe, attestation_ok, permit_scan, tool_allowed
from cybot.scan import REFLECT_MARKER, gate_plan, plan_commands, run_local_demo
from cybot.scope import Scope, check_scope, parse_scope
from cybot.store import Store, load_fernet
from cybot.validate import validate_boolean, validate_reflection

SCOPE = {
    "program": "Example",
    "include": ["example.com", "*.example.com"],
    "exclude": ["mail.example.com"],
    "authorization": "I am authorized to test only the listed assets.",
}

ATTEST = "I am authorized to run non-destructive checks on the in-scope assets only."


def _scope(include=None) -> Scope:
    data = dict(SCOPE)
    if include is not None:
        data["include"] = include
    return parse_scope(data)


def test_private_and_metadata_stay_blocked_and_demo_loopback_is_explicit():
    scope = _scope(["example.com", "127.0.0.1", "169.254.169.254"])
    assert check_scope(scope, "127.0.0.1").rule == "non-public-ip"
    assert check_scope(scope, "169.254.169.254", allow_demo=True).rule == "non-public-ip"
    assert check_scope(scope, "10.1.1.1", allow_demo=True).rule == "non-public-ip"
    allowed = check_scope(scope, "127.0.0.1", allow_demo=True)
    assert allowed.allowed
    assert allowed.host == "127.0.0.1"


def test_rails_refuse_missing_opt_in_attestation_budget_and_rate():
    scope = _scope()
    soft = permit_scan(scope, "www.example.com", mode="soft-active", active_approved=False)
    assert not soft.allowed
    assert "opt-in" in soft.reason
    active = permit_scan(
        scope,
        "www.example.com",
        mode="active-test",
        active_approved=True,
        attestation="too short",
    )
    assert not active.allowed
    assert "attestation" in active.reason.lower()
    assert not attestation_ok("I am authorized")
    assert attestation_ok(ATTEST)
    budget = permit_scan(
        scope,
        "www.example.com",
        mode="passive",
        active_approved=False,
        budget_ok=False,
    )
    assert "budget" in budget.reason.lower()
    rate = permit_scan(
        scope,
        "www.example.com",
        mode="passive",
        active_approved=False,
        rate_ok=False,
    )
    assert "rate" in rate.reason.lower()
    outside = permit_scan(scope, "payments.example.net", mode="passive", active_approved=False)
    assert not outside.allowed
    ok = permit_scan(
        scope,
        "www.example.com",
        mode="active-test",
        active_approved=True,
        attestation=ATTEST,
    )
    assert ok.allowed


def test_passive_plan_omits_intrusive_tools_and_banned_flags_never_pass():
    passive = [item.name for item in plan_commands("passive", "example.com", binaries={"sqlmap", "ffuf", "subfinder", "nmap"})]
    assert passive == ["subfinder"]
    soft = [item.name for item in plan_commands("soft-active", "example.com", binaries={"sqlmap", "nmap", "httpx"})]
    assert "nmap" in soft and "httpx" in soft and "sqlmap" not in soft
    assert tool_allowed("sqlmap", "active-test")
    assert not tool_allowed("dalfox", "soft-active")
    refused, reason = argv_is_safe(["sqlmap", "-u", "https://example.com", "--os-shell"], "active-test")
    assert not refused
    assert "os-shell" in reason
    sudo, _ = argv_is_safe(["sudo", "nmap", "example.com"], "active-test")
    assert not sudo
    syn, _ = argv_is_safe(["nmap", "-sS", "example.com"], "soft-active")
    assert not syn
    scope = _scope()
    planned = plan_commands("active-test", "example.com", binaries={"sqlmap", "ffuf"})
    budget = ScanBudget(max_requests=1, max_seconds=30)
    accepted, notes = gate_plan(
        scope,
        "example.com",
        "active-test",
        planned,
        active_approved=True,
        attestation=ATTEST,
        budget=budget,
    )
    assert len(accepted) == 1
    assert notes


def test_demo_app_reflects_and_boolean_difference_needs_a_person():
    with pytest.raises(RuntimeError):
        serve("0.0.0.0")
    client = create_demo_app().test_client()
    reflected = client.get("/reflect", query_string={"q": REFLECT_MARKER}).get_data(as_text=True)
    finding = validate_reflection(reflected, REFLECT_MARKER)
    assert finding.confidence >= 0.7
    assert finding.needs_human_validation
    assert finding.repro.startswith("curl -sS ")
    assert "127.0.0.1" in finding.repro
    true_body = client.get("/lookup", query_string={"name": "widget' OR '1'='1"}).get_data(as_text=True)
    false_body = client.get("/lookup", query_string={"name": "widget' AND '1'='2"}).get_data(as_text=True)
    boolean = validate_boolean(true_body, false_body)
    assert boolean.confidence >= 0.6
    assert boolean.needs_human_validation
    assert "curl -sS " in boolean.repro


def test_local_demo_run_records_validation(tmp_path, cfg):
    store = Store(tmp_path / "demo.db", load_fernet(tmp_path, None))
    scope = parse_scope(
        {
            "program": "CYBOT local demo",
            "include": ["127.0.0.1"],
            "exclude": [],
            "authorization": "Local demo only. I am authorized to review this app.",
        }
    )
    started = __import__("asyncio").run(
        __import__("cybot.service", fromlist=["Service"]).Service(cfg, store).start_run(
            {
                "program": scope.program,
                "include": list(scope.include),
                "exclude": [],
                "authorization": scope.authorization,
                "target": "127.0.0.1",
                "mode": "active-test",
                "intensity": "standard",
                "active_approved": True,
                "attestation": ATTEST,
                "demo": True,
                "provider": "mock",
            },
            source="dashboard",
        )
    )
    assert started["status"] == "complete"
    assert started["mode"] == "active-test"
    findings = store.findings(started["id"])
    assert findings
    assert all(row["needs_human"] == 1 for row in findings)
    assert all(row["repro"].startswith("curl -sS ") for row in findings)
    assert all(float(row["confidence"]) >= 0.6 for row in findings)


def test_active_test_without_attestation_is_rejected(client):
    response = client.post(
        "/api/runs",
        headers={"X-CYBOT": "1"},
        json={
            "program": "Example",
            "include": ["example.com"],
            "exclude": [],
            "authorization": "I am authorized to test only example.com.",
            "target": "example.com",
            "mode": "active-test",
            "active_approved": True,
            "attestation": "short",
            "demo": True,
        },
    )
    assert response.status_code == 400
    assert "attestation" in response.json()["detail"].lower()


def test_install_script_exits_cleanly_when_tools_are_missing():
    completed = subprocess.run(
        ["sh", "scripts/install-scan-tools.sh"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "missing" in completed.stdout or "ready" in completed.stdout
