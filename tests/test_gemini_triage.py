import asyncio
import json

import httpx

from cybot.llm import GeminiLLM, LLMError, _pick_gemini_text, parse_triage


def _response(status, payload):
    class Response:
        def __init__(self):
            self.status_code = status
            self._payload = payload
            self.request = httpx.Request("POST", "https://gemini.test/generate")

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "failed",
                    request=self.request,
                    response=httpx.Response(self.status_code, request=self.request),
                )

        def json(self):
            return self._payload

    return Response()


def test_triage_accepts_fenced_json_and_rejects_empty_gemini_candidates():
    raw = '```json\n{"items":[{"severity":"info","plain":"A note."}]}\n```'
    assert parse_triage(raw, 1)[0]["severity"] == "info"
    try:
        _pick_gemini_text({"promptFeedback": {"blockReason": "SAFETY"}})
    except LLMError as exc:
        assert "SAFETY" in str(exc)
    else:
        raise AssertionError("empty candidates should fail")


def test_gemini_triage_requests_json_chunks_and_retries_503(monkeypatch):
    calls = []

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def post(self, url, headers=None, json=None):
            calls.append(json)
            if len(calls) == 1:
                return _response(503, {})
            items = [{"severity": "low", "plain": "Plain note."} for _ in range(8)]
            if len(calls) > 2:
                items = items[:2]
            text = json_lib.dumps({"items": items})
            return _response(
                200,
                {"candidates": [{"content": {"parts": [{"text": text}]}}]},
            )

    json_lib = json
    monkeypatch.setattr("cybot.llm.httpx.AsyncClient", Client)
    llm = GeminiLLM("gemini", "https://gemini.test", "", "gemini-flash-lite-latest", connector=True)
    rows = [{"title": f"note {index}", "evidence": "header", "severity": "info"} for index in range(10)]
    reviewed = asyncio.run(llm.triage(rows))
    assert len(reviewed) == 10
    assert calls[0]["generationConfig"]["responseMimeType"] == "application/json"
    assert len(calls) == 3
