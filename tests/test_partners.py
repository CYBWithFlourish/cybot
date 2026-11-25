import pytest

from cybot.connectors import Connector, Gateway, GatewayError, assert_route
from cybot.partners import (
    apply_scope_gate,
    interpret_noul,
    jev_label,
    prior_match,
    program_namespace,
    remember,
    scope_decision,
    search_memory,
    stricter_severity,
)


def test_jev_cannot_override_a_deterministic_deny():
    allowed = interpret_noul(0.95)
    assert apply_scope_gate(False, allowed) == "deny"
    assert apply_scope_gate(True, interpret_noul(0.1)) == "deny"
    assert apply_scope_gate(True, interpret_noul(0.5)) == "ask"
    assert apply_scope_gate(True, interpret_noul(0.9)) == "allow"
    assert apply_scope_gate(True, None) == "allow"


def test_severity_only_moves_down():
    assert stricter_severity("high", {"band": "low", "low_confidence": False}) == "low"
    assert stricter_severity("low", {"band": "high", "low_confidence": False}) == "low"
    assert stricter_severity("medium", {"band": "info", "low_confidence": True}) == "medium"


def test_jev_label_for_a_likely_real_finding():
    assert jev_label(0.13, False) == "Jev: 0.87 likely real"
    assert "unsure" in jev_label(0.5, True)


def test_program_namespace_is_stable():
    assert program_namespace("Example Program!") == "example-program"


def test_partner_routes_reject_admin_paths():
    assert_route("pinecone", "POST", "/embed")
    assert_route("pinecone", "POST", "/indexes/cybot/query")
    assert_route("typesafe", "POST", "/v1/systemone")
    with pytest.raises(GatewayError):
        assert_route("pinecone", "DELETE", "/indexes/cybot")
    with pytest.raises(GatewayError):
        assert_route("typesafe", "POST", "/v1/other")


class _Partners:
    def __init__(self, names):
        self.names = set(names)
        self.calls = []

    def find(self, *wanted):
        return object() if any(name in self.names for name in wanted) else None

    async def call(self, provider, method, path, **kwargs):
        self.calls.append((provider, method, path, kwargs.get("json") or {}))
        if path == "/v1/systemone":
            return {"answers": {"in_scope": {"type": "noul", "noul": 0.12}}}
        if path == "/embed":
            return {"data": [{"values": [0.1, 0.2]}]}
        if path == "/indexes":
            return {"indexes": [{"name": "cybot"}]}
        if path.endswith("/query"):
            return {"matches": [{"id": "old", "score": 0.95, "metadata": {"title": "HTTP only", "status": "duplicate", "text": "seen"}}]}
        if path.endswith("/upsert"):
            return {"upserted": 1}
        return {}


def test_scope_decision_uses_systemone_and_can_deny():
    import asyncio

    gateway = _Partners({"typesafe"})
    decision = asyncio.run(scope_decision(gateway, {"jev_model": "jev-latest"}, "www.example.com", "*.example.com"))
    assert decision["stricter_deny"] is True
    assert gateway.calls[0][0] == "typesafe"
    assert gateway.calls[0][2] == "/v1/systemone"


def test_memory_is_skipped_without_pinecone():
    import asyncio

    result = asyncio.run(search_memory(_Partners(set()), {}, "nginx header", "Example", 3))
    assert result["configured"] is False
    assert result["matches"] == []


def test_memory_upserts_into_the_program_namespace():
    import asyncio

    gateway = _Partners({"pinecone"})
    stored = asyncio.run(
        remember(
            gateway,
            {},
            "Example",
            [{"id": "f1", "text": "HTTP only", "metadata": {"title": "HTTP only", "status": "new", "text": "note"}}],
        )
    )
    assert stored == 1
    upsert = [call for call in gateway.calls if call[2].endswith("/upsert")][0]
    assert upsert[3]["namespace"] == "example"
    found = asyncio.run(search_memory(gateway, {}, "HTTP", "Example", 3))
    assert found["matches"][0]["status"] == "duplicate"


def test_seen_before_requires_a_different_run():
    current = "run-new"
    assert prior_match([{"score": 1.0, "run_id": "", "title": "zero-vector ghost"}], current) is None
    assert prior_match([{"score": 0.99, "run_id": current, "title": "this run"}], current) is None
    assert prior_match([{"score": 0.91, "run_id": "run-old", "title": "close"}], current) is None
    hit = prior_match([{"score": 0.97, "run_id": "run-old", "title": "HTTP only", "status": "new"}], current)
    assert hit["title"] == "HTTP only"


def test_memory_query_excludes_the_current_run_before_upsert():
    import asyncio

    gateway = _Partners({"pinecone"})

    async def flow():
        found = await search_memory(gateway, {}, "HTTP", "Example", 3, run_id="run-new")
        stored = await remember(
            gateway,
            {},
            "Example",
            [{
                "id": "f1",
                "text": "HTTP only",
                "metadata": {"title": "HTTP only", "status": "new", "text": "note", "run_id": "run-new"},
            }],
        )
        return found, stored

    found, stored = asyncio.run(flow())
    assert stored == 1
    query = [call for call in gateway.calls if call[2].endswith("/query")][0]
    upsert = [call for call in gateway.calls if call[2].endswith("/upsert")][0]
    assert gateway.calls.index(query) < gateway.calls.index(upsert)
    assert query[3]["filter"] == {"run_id": {"$ne": "run-new"}}
    assert upsert[3]["vectors"][0]["metadata"]["run_id"] == "run-new"
    assert prior_match(found["matches"], "run-new") is None


def test_pinecone_header_has_a_version_and_no_key():
    import asyncio

    seen = {}

    async def transport(_method, url, **kwargs):
        seen["headers"] = kwargs["headers"]
        seen["url"] = url
        return {"indexes": []}

    gateway = Gateway(
        [Connector("pinecone", "pinecone", "conn_pc", "https://api.sprites.dev/v1/gateway/pinecone/conn_pc", "other")],
        transport=transport,
    )
    asyncio.run(gateway.call("pinecone", "GET", "/indexes"))
    assert seen["headers"]["X-Pinecone-Api-Version"] == "2026-07"
    assert "Api-Key" not in seen["headers"]
    assert "api_key" not in seen["url"]
