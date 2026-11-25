from __future__ import annotations

import json
import re
from typing import Protocol

import httpx

from cybot.connectors import connector_chat_url, connector_headers
from cybot.redact import redact

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)
_BANNED = (
    "<script",
    "union select",
    "/etc/passwd",
    "nc -e",
    "<?php",
    "javascript:",
    "onerror=",
    "sqlmap",
    "metasploit",
)

SYSTEM_PLAN = (
    "You are CYBOT's planner. Pick a subset of the approved tool names. "
    "You cannot add tools, change arguments, or name hosts that are out of scope. "
    "Do not ask for exploits, fuzzing, payloads, or credential attacks. "
    'Return only JSON: {"tools":["name"],"why":"one sentence"}.'
)

SYSTEM_TRIAGE = (
    "You rank reconnaissance notes for a bug bounty report. "
    "Severities are only info, low, medium, or high. Do not use critical. "
    "Do not give exploit steps, payloads, or reproduction beyond the observation itself. "
    "Unverified version matches stay unverified. "
    'Return only JSON: {"items":[{"severity":"info","plain":"one or two sentences"}]} '
    "with one item per input, same order."
)

SYSTEM_EXPLAIN = (
    "Explain this reconnaissance note in plain English for a student writing a bug bounty report. "
    "Say what was observed, why it might matter, and that it is not a confirmed vulnerability. "
    "Do not provide exploit steps, payloads, requests that attack the host, or tool flags."
)


class LLMError(RuntimeError):
    pass


class LLM(Protocol):
    name: str

    async def plan(self, names: list[str], context: str) -> list[str]: ...

    async def triage(self, rows: list[dict]) -> list[dict]: ...

    async def explain(self, finding: dict) -> str: ...


class MockLLM:
    name = "mock"

    async def plan(self, names: list[str], context: str) -> list[str]:
        return list(names)

    async def triage(self, rows: list[dict]) -> list[dict]:
        return [
            {
                "severity": row.get("severity", "info"),
                "plain": row.get("plain")
                or (
                    f"{row.get('title')} on {row.get('host')}. "
                    "This is a reconnaissance note, not a confirmed vulnerability."
                ),
            }
            for row in rows
        ]

    async def explain(self, finding: dict) -> str:
        return sanitize_explanation(
            f"{finding.get('title')} on {finding.get('host')} is a reconnaissance note from {finding.get('tool')}. "
            "It is not a confirmed vulnerability, and this note has no attack steps."
        )


def sanitize_explanation(text: str) -> str:
    cleaned = redact(text or "").strip()
    lowered = cleaned.lower()
    if "```" in cleaned or any(token in lowered for token in _BANNED):
        return (
            "CYBOT withheld this explanation because it contained content outside "
            "plain-language reconnaissance notes."
        )
    return cleaned[:2000]


def parse_tools(raw: str, allowed: list[str]) -> list[str]:
    data = _json(raw)
    names = data.get("tools") if isinstance(data, dict) else None
    if not isinstance(names, list):
        return list(allowed)
    allow = set(allowed)
    picked = [str(name) for name in names if str(name) in allow]
    return picked or list(allowed)


TRIAGE_CHUNK = 8


def triage_chunks(rows: list[dict], size: int = TRIAGE_CHUNK) -> list[list[dict]]:
    if size < 1:
        size = TRIAGE_CHUNK
    return [rows[index : index + size] for index in range(0, len(rows), size)]


def triage_brief(rows: list[dict]) -> list[dict]:
    return [
        {"title": row.get("title", ""), "evidence": str(row.get("evidence") or "")[:500], "heuristic": row.get("severity", "info")}
        for row in rows
    ]


async def triage_rows(complete, rows: list[dict]) -> list[dict]:
    reviewed: list[dict] = []
    for chunk in triage_chunks(rows):
        raw = await complete(SYSTEM_TRIAGE, json.dumps(triage_brief(chunk)))
        reviewed.extend(parse_triage(raw, len(chunk)))
    return reviewed


def parse_triage(raw: str, count: int) -> list[dict]:
    data = _json(raw)
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise LLMError("Triage response was not a list.")
    if len(items) != count:
        raise LLMError("Triage response length did not match the findings.")
    return items


def _json(raw: str) -> dict:
    text = raw.strip()
    fenced = _FENCE.search(text)
    if fenced:
        text = fenced.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise LLMError("Model did not return JSON.")
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError("Model returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise LLMError("Model JSON was not an object.")
    return data


def chat_completions_url(base: str) -> str:
    root = base.rstrip("/")
    if root.endswith("/chat/completions"):
        return root
    if root.endswith("/v1"):
        return root + "/chat/completions"
    return root + "/v1/chat/completions"


class OpenAICompatLLM:
    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str,
        model: str,
        *,
        connector: bool = False,
        extra_headers: dict | None = None,
    ):
        self.name = name
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.connector = connector
        self.extra_headers = extra_headers or {}

    async def complete(self, system: str, user: str) -> str:
        headers = connector_headers(self.connector, self.api_key, "bearer")
        headers.update(self.extra_headers)
        url = connector_chat_url(self.base_url, self.name) if self.connector else chat_completions_url(self.base_url)
        body = {
            "model": self.model,
            "temperature": 0.1,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        return await _post_text(
            url,
            headers,
            body,
            lambda data: data["choices"][0]["message"]["content"],
        )

    async def plan(self, names: list[str], context: str) -> list[str]:
        catalog = "\n".join(f"- {name}" for name in names)
        raw = await self.complete(SYSTEM_PLAN, f"Approved tools:\n{catalog}\n\nContext:\n{context}")
        return parse_tools(raw, names)

    async def triage(self, rows: list[dict]) -> list[dict]:
        return await triage_rows(self.complete, rows)

    async def explain(self, finding: dict) -> str:
        payload = {key: finding.get(key, "") for key in ("host", "tool", "title", "evidence", "severity")}
        raw = await self.complete(SYSTEM_EXPLAIN, json.dumps(payload))
        return sanitize_explanation(raw)


class AnthropicLLM(OpenAICompatLLM):
    async def complete(self, system: str, user: str) -> str:
        root = self.base_url.rstrip("/")
        url = root if root.endswith("/v1/messages") else root + "/v1/messages"
        headers = connector_headers(self.connector, self.api_key, "anthropic")
        body = {
            "model": self.model,
            "max_tokens": 1200,
            "temperature": 0.1,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        return await _post_text(url, headers, body, lambda data: data["content"][0]["text"])


class GeminiLLM(OpenAICompatLLM):
    async def complete(self, system: str, user: str, *, json_mode: bool = False) -> str:
        model = self.model
        root = self.base_url.rstrip("/")
        url = f"{root}/v1beta/models/{model}:generateContent"
        headers = connector_headers(self.connector, self.api_key, "gemini")
        generation = {"temperature": 0.1}
        if json_mode:
            generation["responseMimeType"] = "application/json"
        body = {
            "contents": [{"role": "user", "parts": [{"text": system + "\n\n" + user}]}],
            "generationConfig": generation,
        }
        return await _post_text(
            url,
            headers,
            body,
            _pick_gemini_text,
            retries=1,
        )

    async def triage(self, rows: list[dict]) -> list[dict]:
        async def complete(system: str, user: str) -> str:
            return await self.complete(system, user, json_mode=True)

        return await triage_rows(complete, rows)


def _pick_gemini_text(data: dict) -> str:
    if not isinstance(data, dict):
        raise LLMError("Gemini returned a response that was not JSON.")
    candidates = data.get("candidates") or []
    if not candidates:
        feedback = data.get("promptFeedback") if isinstance(data.get("promptFeedback"), dict) else {}
        reason = str(feedback.get("blockReason") or "no candidates")
        raise LLMError(f"Gemini returned no text ({reason}).")
    content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list) or not parts:
        finish = ""
        if isinstance(candidates[0], dict):
            finish = str(candidates[0].get("finishReason") or "")
        detail = finish or "empty content"
        raise LLMError(f"Gemini returned no text ({detail}).")
    for part in reversed(parts):
        if isinstance(part, dict) and not part.get("thought") and isinstance(part.get("text"), str):
            return part["text"]
    first = parts[0]
    if isinstance(first, dict) and isinstance(first.get("text"), str):
        return first["text"]
    raise LLMError("Gemini returned no text (no text part).")


class OllamaLocalLLM(OpenAICompatLLM):
    async def complete(self, system: str, user: str) -> str:
        root = self.base_url.rstrip("/")
        url = root + "/api/chat"
        body = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        return await _post_text(url, {"Content-Type": "application/json"}, body, lambda data: data["message"]["content"])


async def _post_text(url: str, headers: dict, body: dict, pick, retries: int = 0) -> str:
    import asyncio

    attempt = 0
    while True:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(url, headers=headers, json=body)
            if response.status_code in {429, 503} and attempt < retries:
                attempt += 1
                await asyncio.sleep(0.05)
                continue
            response.raise_for_status()
            data = response.json()
            text = pick(data)
        except LLMError:
            raise
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in {429, 503} and attempt < retries:
                attempt += 1
                await asyncio.sleep(0.05)
                continue
            raise LLMError(redact(f"{type(exc).__name__}: {exc}")[:300]) from None
        if not isinstance(text, str) or not text.strip():
            raise LLMError("Model returned an empty response.")
        return text
