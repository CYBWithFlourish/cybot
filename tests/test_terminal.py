import subprocess

from cybot.rails import ScanBudget
from cybot.scope import parse_scope
from cybot.store import Store, load_fernet
from cybot.terminal import (
    MAX_STEPS,
    OUTPUT_CAP,
    extract_targets,
    parse_command,
    prepare_command,
    react_loop,
    run_prepared,
    submit_command,
)

SCOPE = parse_scope(
    {
        "program": "Example",
        "include": ["example.com", "*.example.com"],
        "exclude": ["mail.example.com"],
        "authorization": "I am authorized to test only the listed assets.",
    }
)
ATTEST = "I am authorized to run non-destructive checks on the in-scope assets only."


def _run(mode="passive", target="www.example.com", attestation=""):
    return {
        "id": "run1",
        "mode": mode,
        "target": target,
        "attestation": attestation,
    }


class Mem:
    def __init__(self):
        self.audit_rows = []
        self.lines = []

    def audit(self, action, target, decision, detail, run_id=None):
        self.audit_rows.append((action, decision, detail, target))

    def add_terminal(self, run_id, command, status, output):
        self.lines.append({"command": command, "status": status, "output": output})
        return len(self.lines)


def test_allowlist_rejects_unknown_binaries_and_shell_syntax():
    argv, _ = parse_command("dig www.example.com")
    assert argv[0] == "dig"
    blocked, reason = parse_command("bash -c id")
    assert blocked is None
    assert "not an allowlisted" in reason
    sqlmap, sql_reason = parse_command("sqlmap -u https://example.com")
    assert sqlmap is None
    assert "not an allowlisted" in sql_reason
    piped, pipe_reason = parse_command("dig example.com | tee /tmp/out")
    assert piped is None
    assert "refused" in pipe_reason
    sudo = prepare_command(
        "sudo nmap example.com",
        SCOPE,
        mode="active-test",
        workdir=__import__("pathlib").Path("/tmp"),
        attestation=ATTEST,
    )
    assert not sudo["ok"]
    assert "sudo" in sudo["reason"]


def test_scope_extraction_refuses_out_of_scope_and_private_addresses(tmp_path):
    targets = extract_targets(["curl", "-I", "https://payments.example.net/login", "10.1.1.1"])
    assert "payments.example.net" in targets
    assert "10.1.1.1" in targets
    outside = prepare_command(
        "curl -I https://payments.example.net/login",
        SCOPE,
        mode="soft-active",
        workdir=tmp_path,
    )
    assert not outside["ok"]
    assert "not covered" in outside["reason"]
    private = prepare_command("curl http://10.1.1.1/", SCOPE, mode="soft-active", workdir=tmp_path)
    assert not private["ok"]
    meta = prepare_command("curl http://169.254.169.254/", SCOPE, mode="active-test", workdir=tmp_path, attestation=ATTEST)
    assert not meta["ok"]
    mail = prepare_command("dig mail.example.com", SCOPE, mode="passive", workdir=tmp_path)
    assert not mail["ok"]
    inside = prepare_command("dig www.example.com", SCOPE, mode="passive", workdir=tmp_path)
    assert inside["ok"]
    assert "www.example.com" in inside["targets"]


def test_intrusive_flags_need_active_test_and_attestation(tmp_path):
    soft = prepare_command("ffuf -u https://www.example.com/FUZZ -w words.txt", SCOPE, mode="soft-active", workdir=tmp_path)
    assert not soft["ok"]
    assert "active-test" in soft["reason"]
    missing = prepare_command(
        "nmap --script vuln www.example.com",
        SCOPE,
        mode="active-test",
        workdir=tmp_path,
        attestation="short",
    )
    assert not missing["ok"]
    script = prepare_command(
        "nmap --script vuln www.example.com",
        SCOPE,
        mode="active-test",
        workdir=tmp_path,
        attestation=ATTEST,
    )
    assert not script["ok"]
    syn = prepare_command("nmap -sS www.example.com", SCOPE, mode="active-test", workdir=tmp_path, attestation=ATTEST)
    assert not syn["ok"]
    outside = prepare_command(
        "curl -o /etc/passwd https://www.example.com/",
        SCOPE,
        mode="soft-active",
        workdir=tmp_path,
    )
    assert not outside["ok"]
    assert "work directory" in outside["reason"]


def test_timeout_output_cap_confirm_and_step_cap(tmp_path):
    prepared = prepare_command("dig www.example.com", SCOPE, mode="passive", workdir=tmp_path)
    def hang(_argv, timeout, _folder):
        raise subprocess.TimeoutExpired(_argv, timeout)

    timed = run_prepared(prepared, workdir=tmp_path, timeout=1, runner=hang)
    assert timed["status"] == "timeout"
    assert "1s" in timed["output"]

    def huge(_argv, _timeout, _folder):
        return subprocess.CompletedProcess(_argv, 0, stdout="x" * (OUTPUT_CAP + 50), stderr="")

    capped = run_prepared(prepared, workdir=tmp_path, runner=huge)
    assert "output capped" in capped["output"]
    assert len(capped["output"]) < OUTPUT_CAP + 40

    store = Mem()
    pending = submit_command(
        store,
        _run("active-test", attestation=ATTEST),
        SCOPE,
        "dig www.example.com",
        workdir=tmp_path,
        confirmed=False,
        runner=huge,
    )
    assert pending["status"] == "pending"
    assert store.lines[-1]["status"] == "pending"

    calls = []

    def record(argv, _timeout, _folder):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    ran = submit_command(
        store,
        _run("passive"),
        SCOPE,
        "dig www.example.com",
        workdir=tmp_path,
        runner=record,
    )
    assert ran["status"] == "ok"
    assert calls and calls[0][0] == "dig"

    steps = {"n": 0}

    def decide(_observations):
        steps["n"] += 1
        return {"command": "dig www.example.com"}

    loop = react_loop(
        store,
        _run("passive"),
        SCOPE,
        decide,
        workdir=tmp_path,
        max_steps=20,
        runner=record,
        budget=ScanBudget(max_requests=3, max_seconds=30),
    )
    assert steps["n"] <= MAX_STEPS
    assert loop
    assert len(loop) <= MAX_STEPS
    assert loop[-1]["status"] == "refused"


def test_mcp_run_command_uses_the_same_refusal(client):
    from tests.test_api import DEMO, HEADERS

    started = client.post("/api/runs", headers=HEADERS, json=DEMO)
    assert started.status_code == 200, started.text
    run_id = started.json()["id"]
    refused = client.post(
        "/api/mcp",
        headers={"Authorization": "Bearer mcp-test-token"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"mission_id": run_id, "command": "curl https://payments.example.net"},
            },
        },
    )
    assert refused.status_code == 200, refused.text
    text = refused.json()["result"]["content"][0]["text"]
    assert "payments.example.net" in text
    assert "refused" in text
