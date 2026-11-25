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
    created = asyncio.run(service.start_run({**DEMO, "provider": "mock"}, "test"))
    finding_id = store.findings(created["id"])[0]["id"]
    result = asyncio.run(service.assist(finding_id, "fix", ""))
    assert result["source"] == "template"
    assert store.chat(finding_id)[-1]["role"] == "assistant"
