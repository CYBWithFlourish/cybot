import asyncio

from cybot.tools import PUBLIC_PATHS, ToolContext, ToolOutcome, cve_search, github_public_code, osint_search

HEADERS = {"X-CYBOT": "1"}

DEMO = {
    "program": "CYBOT demo",
    "include": ["example.com", "www.example.com"],
    "exclude": ["mail.example.com"],
    "authorization": "Demo fixture only. I am authorized to review this local fixture.",
    "target": "www.example.com",
    "intensity": "light",
    "active_approved": True,
    "demo": True,
}


def test_demo_run_refuses_out_of_scope_names_and_writes_a_report(client):
    refused = client.post(
        "/api/scope/check",
        headers=HEADERS,
        json={**DEMO, "target": "payments.example.net", "demo": False},
    )
    assert refused.status_code == 200
    assert refused.json()["allowed"] is False

    started = client.post("/api/runs", headers=HEADERS, json=DEMO)
    assert started.status_code == 200, started.text
    body = started.json()
    assert body["status"] == "complete"
    findings = client.get(f"/api/runs/{body['id']}/findings", headers=HEADERS).json()["findings"]
    assert findings
    hosts = {row["host"] for row in findings}
    assert "evil.not-example.test" not in hosts
    blob = " ".join(row["evidence"] + row["title"] + row["plain"] for row in findings).lower()
    assert "exploit" not in blob or "not" in blob
    report = client.get(f"/api/runs/{body['id']}/report.md", headers=HEADERS).text
    assert "not confirmed" in report.lower() or "not a confirmed" in report.lower()
    pdf = client.get(f"/api/runs/{body['id']}/report.pdf", headers=HEADERS)
    assert pdf.content.startswith(b"%PDF")
    audit = client.get("/api/audit", headers=HEADERS).json()["audit"]
    assert any(row["decision"] == "refused" for row in audit)
    assert any("authorization" in row["detail"].lower() or "auth=" in row["detail"] for row in audit)


def test_secret_is_encrypted_and_not_returned(client, cfg):
    saved = client.post(
        "/api/secrets",
        headers=HEADERS,
        json={"name": "gemini", "value": "AIzaSyTESTKEY1234567890"},
    )
    assert saved.status_code == 200
    assert "AIzaSyTESTKEY1234567890" not in saved.text
    settings = client.get("/api/settings", headers=HEADERS).text
    assert "AIzaSyTESTKEY1234567890" not in settings
    raw = (cfg.data_dir / "cybot.db").read_bytes()
    assert b"AIzaSyTESTKEY1234567890" not in raw


def test_mcp_lists_tools_and_rejects_a_missing_token(client):
    missing = client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert missing.status_code == 401
    listed = client.post(
        "/api/mcp",
        headers={"Authorization": "Bearer mcp-test-token"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert listed.status_code == 200
    names = [tool["name"] for tool in listed.json()["result"]["tools"]]
    assert {"start_recon", "get_status", "get_findings", "explain_finding", "get_report"} <= set(names)


def test_public_paths_are_not_secret_files():
    blob = " ".join(PUBLIC_PATHS)
    for banned in (".env", ".git", "admin", "wp-", "backup"):
        assert banned not in blob


def test_default_provider_is_opencode(client):
    settings = client.get("/api/settings", headers=HEADERS).json()["settings"]
    assert settings["provider"] == "opencode"
    assert settings["opencode_product"] == "go"


def test_search_routes_exa_for_discovery_and_tavily_for_facts():
    asyncio.run(_search_routes())


async def _search_routes():
    class Rec:
        def __init__(self):
            self.calls = []

        def find(self, *names):
            return object() if any(name in {"exa", "tavily"} for name in names) else None

        async def call(self, provider, method, path, **kwargs):
            self.calls.append((provider, method, path, kwargs.get("json") or {}))
            if path == "/contents":
                return {"results": [{"text": "Example Domain homepage"}]}
            if provider == "tavily":
                return {"answer": "Example is a documentation domain.", "results": []}
            return {"results": [{"title": "Example", "url": "https://www.example.com/"}]}

    gateway = Rec()
    ctx = ToolContext(net=None, host="www.example.com", gateway=gateway)
    await osint_search(ctx)
    kinds = [(item[0], item[2], item[3].get("type") or item[3].get("include_answer")) for item in gateway.calls]
    assert ("exa", "/search", "neural") in kinds
    assert ("tavily", "/search", True) in kinds
    assert ("exa", "/contents", None) in [(item[0], item[2], item[3].get("type")) for item in gateway.calls]

    cve = ToolContext(
        net=None,
        host="www.example.com",
        gateway=gateway,
        extra={"product": "nginx", "version": "1.25.3"},
    )
    before = len(gateway.calls)
    await cve_search(cve)
    factual = gateway.calls[before]
    assert factual[0] == "tavily"
    assert factual[3]["include_answer"] is True


def test_ollama_local_does_not_require_a_key(client):
    saved = client.put(
        "/api/settings",
        headers=HEADERS,
        json={"provider": "ollama-local", "model": "qwen2.5:1.5b"},
    )
    assert saved.status_code == 200
    assert saved.json()["settings"]["provider"] == "ollama-local"


def test_github_results_drop_secret_fragments():
    asyncio.run(_github_drops_secret())


async def _github_drops_secret():
    class FakeGateway:
        def find(self, *_names):
            return object()

        async def call(self, *_args, **_kwargs):
            return {
                "items": [
                    {
                        "path": "config/app.yml",
                        "html_url": "https://github.com/acme/app/blob/main/config/app.yml",
                        "text_matches": [{"fragment": "token=sk-supersecretkeyvalue123456"}],
                    }
                ]
            }

    ctx = ToolContext(net=None, host="www.example.com", extra={"github_org": "acme"}, gateway=FakeGateway())
    ctx.outcome = ToolOutcome()
    await github_public_code(ctx)
    evidence = ctx.outcome.observations[0].evidence
    assert "config/app.yml" in evidence
    assert "sk-supersecretkeyvalue123456" not in evidence


def test_demo_cannot_target_an_arbitrary_host(client):
    response = client.post(
        "/api/runs",
        headers=HEADERS,
        json={**DEMO, "target": "payments.example.net"},
    )
    assert response.status_code == 400
    assert "Demo mode" in response.text
