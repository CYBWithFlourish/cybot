import pytest

from cybot.connectors import Connector, Gateway, GatewayError, assert_route
from cybot.notion import NotionSkipped, list_programs, list_tracked, normalize_id, publish_run


def test_notion_routes_allow_pages_and_refuse_deletes():
    assert_route("notion", "POST", "/v1/pages")
    assert_route("notion", "POST", "/v1/data_sources/0123456789abcdef0123456789abcdef/query")
    with pytest.raises(GatewayError):
        assert_route("notion", "DELETE", "/v1/pages/0123456789abcdef0123456789abcdef")


def test_normalize_id_accepts_a_url_fragment():
    assert normalize_id("0123456789abcdef0123456789abcdef") == "01234567-89ab-cdef-0123-456789abcdef"


class _Store:
    def __init__(self):
        self.events = []

    def settings(self):
        return {
            "notion_reports_database": "0123456789abcdef0123456789abcdef",
            "notion_tracker_database": "abcdef0123456789abcdef0123456789",
            "notion_programs_database": "fedcba9876543210fedcba9876543210",
        }

    def event(self, _run_id, _level, message):
        self.events.append(message)


class _Notion:
    def __init__(self):
        self.calls = []

    def find(self, *names):
        return object() if "notion" in names else None

    async def call(self, _provider, method, path, **kwargs):
        self.calls.append((method, path, kwargs.get("json") or {}))
        if method == "GET" and "/databases/" in path:
            return {"data_sources": [{"id": "11111111-1111-1111-1111-111111111111"}]}
        if method == "GET" and "/data_sources/" in path:
            return {
                "properties": {
                    "Target": {"type": "title"},
                    "Program": {"type": "rich_text"},
                    "Status": {"type": "select"},
                    "Severity": {"type": "select"},
                    "Finding ID": {"type": "rich_text"},
                    "Include": {"type": "rich_text"},
                    "Authorization": {"type": "rich_text"},
                    "Active": {"type": "checkbox"},
                    "Name": {"type": "title"},
                }
            }
        if path.endswith("/query"):
            body = kwargs.get("json") or {}
            if "Finding ID" in str(body.get("filter")):
                return {"results": []}
            return {
                "results": [
                    {
                        "id": "page",
                        "url": "https://www.notion.so/page",
                        "properties": {
                            "Name": {"type": "title", "title": [{"plain_text": "Example"}]},
                            "Include": {"type": "rich_text", "rich_text": [{"plain_text": "*.example.com"}]},
                            "Authorization": {
                                "type": "rich_text",
                                "rich_text": [{"plain_text": "I am authorized to test the listed assets only."}],
                            },
                            "Active": {"type": "checkbox", "checkbox": True},
                            "Status": {"type": "select", "select": {"name": "triaged"}},
                            "Program": {"type": "rich_text", "rich_text": [{"plain_text": "Example"}]},
                        },
                    }
                ]
            }
        if path == "/v1/pages":
            return {"id": "new-page", "url": "https://www.notion.so/new-page"}
        return {}


def test_publish_creates_a_report_page_and_a_tracker_row():
    import asyncio

    gateway = _Notion()
    result = asyncio.run(
        publish_run(
            gateway,
            _Store(),
            {"id": "abc", "target": "www.example.com", "program": "Example", "intensity": "light", "created_at": "2026-11-24T00:00:00+00:00", "scope_json": "{}"},
            [{"id": "f1", "host": "www.example.com", "tool": "http_probe", "severity": "low", "title": "HTTP only", "plain": "TLS did not answer.", "evidence": "http"}],
        )
    )
    assert result["published"] is True
    assert result["tracked"] == 1
    pages = [call for call in gateway.calls if call[1] == "/v1/pages"]
    assert pages
    children = pages[0][2]["children"]
    assert any("not confirmed" in str(block).lower() or "not exploit" in str(block).lower() for block in children)
    assert all(call[0] != "DELETE" for call in gateway.calls)


def test_missing_connector_does_not_raise():
    import asyncio

    class Empty:
        def find(self, *_names):
            return None

    store = _Store()
    result = asyncio.run(publish_run(Empty(), store, {"id": "abc"}, []))
    assert result["published"] is False
    assert "not granted" in result["reason"]


def test_programs_and_tracker_reads():
    import asyncio

    gateway = _Notion()
    programs = asyncio.run(list_programs(gateway, _Store().settings()))
    assert programs["programs"][0]["program"] == "Example"
    assert programs["programs"][0]["include"] == ["*.example.com"]
    tracked = asyncio.run(list_tracked(gateway, _Store().settings(), status="triaged"))
    assert tracked["findings"][0]["status"] == "triaged"


def test_gateway_sends_the_notion_version_and_no_token():
    import asyncio

    seen = {}

    async def transport(method, url, **kwargs):
        seen["headers"] = kwargs["headers"]
        seen["url"] = url
        return {"data_sources": []}

    connector = Connector(
        "notion",
        "notion-community",
        "conn_notion",
        "https://api.sprites.dev/v1/gateway/notion/conn_notion",
        "other",
    )
    gateway = Gateway([connector], transport=transport)
    asyncio.run(gateway.call("notion", "GET", "/v1/databases/01234567-89ab-cdef-0123-456789abcdef"))
    assert seen["headers"]["Notion-Version"] == "2026-03-11"
    assert "Authorization" not in seen["headers"]
    assert "ntn_" not in seen["url"]
    assert NotionSkipped is not None
