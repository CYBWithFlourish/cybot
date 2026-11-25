import asyncio

from cybot.assist import guard_answer, template_answer
from cybot.playbook import template_playbook
from cybot.redact import redact
from cybot.report import finding_card_markdown
from cybot.service import Service
from cybot.store import Store, load_fernet
from tests.test_api import DEMO, HEADERS


def test_redact_strips_email_phone_jwt_and_cookie():
    raw = (
        "user ada@example.com called +1 415-555-1212 "
        "cookie=sessionid=abcDEF123 token=supersecretvalue "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    cleaned = redact(raw)
    assert "ada@example.com" not in cleaned
    assert "415-555-1212" not in cleaned
    assert "eyJhbGci" not in cleaned
    assert "sessionid=abcDEF123" not in cleaned
    assert "[redacted]" in cleaned


def test_card_markdown_redacts_evidence_and_lists_steps():
    finding = {
        "title": "Missing header",
        "severity": "low",
        "host": "www.example.com",
        "tool": "header_hygiene",
        "plain": "HSTS was absent.",
        "evidence": "set-cookie: session=abc123 token=sekretvalue email ada@example.com",
        "repro": "curl -sS https://www.example.com/",
        "confidence": "0.40",
        "needs_human": 1,
        "playbook": template_playbook(
            {"title": "Missing header", "host": "www.example.com", "tool": "header_hygiene", "evidence": ""}
        ),
    }
    text = finding_card_markdown(finding)
    assert "## Missing header" in text
    assert "### Steps to reproduce" in text
    assert "curl -sS https://www.example.com/" in text
    assert "sekretvalue" not in text
    assert "ada@example.com" not in text
    assert "Needs human validation: yes" in text
    assert "CWE-" in text


def test_guard_drops_exploit_text_off_the_local_demo():
    blocked = guard_answer("Run sqlmap and a waf bypass. <script>alert(1)</script>", "www.example.com")
    assert blocked == ""
    local = template_answer(
        "retest",
        {"title": "Demo", "host": "127.0.0.1", "severity": "info", "repro": "curl -sS 'http://127.0.0.1:8765/reflect?q=cybot'"},
        template_playbook({"title": "Demo", "host": "127.0.0.1", "tool": "local-demo", "evidence": ""}),
    )
    assert "curl -sS" in local
    assert "127.0.0.1" in local


def test_assist_endpoint_uses_model_then_falls_back(client):
    started = client.post("/api/runs", headers=HEADERS, json={**DEMO, "provider": "mock"})
    assert started.status_code == 200, started.text
    finding_id = client.get(f"/api/runs/{started.json()['id']}/findings", headers=HEADERS).json()["findings"][0]["id"]

    class Answer:
        name = "gemini"

        async def complete(self, system, user):
            return "Retest only this in-scope host by hand. Stay in scope."

    async def build_llm(provider=None, model=None):
        return Answer()

    client.app.state.service.build_llm = build_llm
    ok = client.post(
        f"/api/findings/{finding_id}/assist",
        headers=HEADERS,
        json={"action": "explain", "message": ""},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["source"] == "model"
    assert "scope" in ok.json()["answer"].lower()
    assert ok.json()["history"]

    class Down:
        name = "gemini"

        async def complete(self, system, user):
            raise RuntimeError("503")

    async def fail_llm(provider=None, model=None):
        return Down()

    client.app.state.service.build_llm = fail_llm
    failed = client.post(
        f"/api/findings/{finding_id}/assist",
        headers=HEADERS,
        json={"action": "impact", "message": "what is the impact"},
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["source"] == "template"
    assert "sqlmap" not in failed.json()["answer"].lower()
    markdown = client.get(f"/api/findings/{finding_id}/markdown", headers=HEADERS)
    assert markdown.status_code == 200
    assert "### Steps to reproduce" in markdown.text
    assert "### Suggested fix" in markdown.text


def test_service_assist_persists_when_the_provider_is_mock(cfg):
    store = Store(cfg.data_dir / "cybot.db", load_fernet(cfg.data_dir, None))
    service = Service(cfg, store)
    store.create_run(
        id="run-seed",
        created_at="2026-11-25T00:00:00+00:00",
        target="www.example.com",
        program="Example",
        intensity="passive",
        status="complete",
        provider="mock",
        model="",
        scope_json="{}",
        source="test",
        notion="no",
    )
    store.add_finding(
        id="finding-seed",
        run_id="run-seed",
        host="www.example.com",
        tool="header_hygiene",
        severity="info",
        title="Missing header",
        evidence="no HSTS",
        plain="A reconnaissance note.",
        created_at="2026-11-25T00:00:00+00:00",
        jev="",
    )
    result = asyncio.run(service.assist("finding-seed", "fix", ""))
    assert result["source"] == "template"
    assert store.chat("finding-seed")[-1]["role"] == "assistant"


def test_local_demo_cards_keep_http_port_and_cwe():
    reflected = {
        "title": "Reflected parameter on the local demo",
        "severity": "info",
        "host": "127.0.0.1",
        "tool": "local-demo",
        "plain": "The parameter came back.",
        "evidence": "marker reflected",
        "repro": "curl -sS 'http://127.0.0.1:8765/reflect?q=cybot'",
        "confidence": "0.72",
        "needs_human": 1,
    }
    reflected["playbook"] = template_playbook(reflected)
    text = finding_card_markdown(reflected)
    assert "CWE-79" in text
    assert "http://127.0.0.1:8765" in text
    assert "https://127.0.0.1" not in text
    boolean = {
        "title": "Boolean lookup difference on the local demo",
        "severity": "info",
        "host": "127.0.0.1",
        "tool": "local-demo",
        "plain": "The two responses differed.",
        "evidence": "boolean difference",
        "repro": "curl -sS 'http://127.0.0.1:8765/lookup?name=widget'",
        "needs_human": 1,
    }
    boolean["playbook"] = template_playbook(boolean)
    assert "CWE-89" in finding_card_markdown(boolean)
