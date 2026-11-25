import httpx
from fastapi.testclient import TestClient

from cybot.app import create_app
from cybot.connectors import parse_gateway_list, prefer_model
from cybot.llm import _pick_gemini_text

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


async def _no_connectors(_url):
    return {"connections": []}


def test_connector_test_requires_sign_in(cfg):
    app = create_app(cfg, connector_fetch=_no_connectors)
    with TestClient(app) as raw:
        response = raw.post(
            "/api/connectors/test",
            headers=HEADERS,
            json={"provider": "gemini", "id": "Gem_1"},
        )
    assert response.status_code == 401


def test_connector_test_reports_not_granted_when_missing(client):
    response = client.post(
        "/api/connectors/test",
        headers=HEADERS,
        json={"provider": "gemini", "id": "missing"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "not_granted"
    assert body["name"] == "Google Gemini"
    assert "AIza" not in response.text


def test_connector_test_ok_denied_and_error(cfg):
    async def fetch(_url):
        return {
            "connections": [
                {
                    "id": "Gem_1",
                    "provider": "gemini",
                    "gateway_base_url": "https://api.sprites.dev/v1/gateway/gemini/Gem_1",
                },
                {
                    "id": "Not_1",
                    "provider": "notion",
                    "gateway_base_url": "https://api.sprites.dev/v1/gateway/notion/Not_1",
                },
                {
                    "id": "Fire_1",
                    "provider": "firecrawl",
                    "gateway_base_url": "https://api.sprites.dev/v1/gateway/firecrawl/Fire_1",
                },
            ]
        }

    app = create_app(cfg, connector_fetch=fetch)
    calls = []

    async def transport(method, url, **_kwargs):
        calls.append((method, url))
        request = httpx.Request(method, url)
        if "/notion/" in url:
            response = httpx.Response(403, request=request)
            raise httpx.HTTPStatusError("denied", request=request, response=response)
        if "/firecrawl/" in url:
            response = httpx.Response(500, request=request)
            raise httpx.HTTPStatusError("boom", request=request, response=response)
        return {"ok": True}

    with TestClient(app) as client:
        setup = client.post("/api/setup", headers=HEADERS, json={"password": "correct-horse"})
        assert setup.status_code == 200, setup.text
        app.state.service.probe_transport = transport
        ok = client.post("/api/connectors/test", headers=HEADERS, json={"provider": "gemini", "id": "Gem_1"})
        denied = client.post("/api/connectors/test", headers=HEADERS, json={"provider": "notion", "id": "Not_1"})
        failed = client.post("/api/connectors/test", headers=HEADERS, json={"provider": "firecrawl", "id": "Fire_1"})
        wrong_case = client.post(
            "/api/connectors/test", headers=HEADERS, json={"provider": "gemini", "id": "gem_1"}
        )

    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "ok"
    assert ok.json()["name"] == "Google Gemini"
    assert ok.json()["id"] == "Gem_1"
    assert denied.json()["status"] == "not_granted"
    assert failed.json()["status"] == "error"
    assert wrong_case.json()["status"] == "not_granted"
    assert any("/gemini/Gem_1/" in url for _method, url in calls)
    assert not any("/gemini/gem_1/" in url for _method, url in calls)


def test_connection_ids_keep_their_case():
    connectors = parse_gateway_list(
        {
            "connections": [
                {
                    "id": "Gem_AbC",
                    "provider": "gemini",
                    "gateway_base_url": "https://api.sprites.dev/v1/gateway/gemini/Gem_AbC",
                }
            ]
        }
    )
    chosen = prefer_model(connectors, "connector:Gemini:Gem_AbC")
    assert chosen is not None
    assert chosen.connection_id == "Gem_AbC"
    assert prefer_model(connectors, "connector:gemini:gem_abc") is None


def test_gemini_text_skips_thought_parts():
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"thought": True, "text": "hidden"},
                        {"text": "visible answer"},
                    ]
                }
            }
        ]
    }
    assert _pick_gemini_text(data) == "visible answer"


def test_finished_report_names_the_provider_that_answered(client):
    started = client.post("/api/runs", headers=HEADERS, json={**DEMO, "provider": "mock", "model": ""})
    assert started.status_code == 200, started.text
    body = started.json()
    assert body["status"] == "complete"
    assert body["provider"] == "mock"
    report = client.get(f"/api/runs/{body['id']}/report.md", headers=HEADERS).text
    assert "- Status: complete" in report
    assert "- Provider: mock" in report
