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


GEMINI_MAX_OUTPUT_TOKENS = 8192
TRIAGE_CHUNK = 5

TRIAGE_SCHEMA = {
    "type": "ARRAY",
    "items": {
        "type": "OBJECT",
        "properties": {
            "severity": {"type": "STRING", "enum": ["info", "low", "medium", "high"]},
            "plain": {"type": "STRING"},
        },
        "required": ["severity", "plain"],
    },
}

NARRATIVE_SCHEMA = {
    "type": "ARRAY",
    "items": {
        "type": "OBJECT",
        "properties": {
            "why": {"type": "STRING"},
            "likelihood": {"type": "STRING"},
            "impact": {"type": "STRING"},
            "verify": {"type": "ARRAY", "items": {"type": "STRING"}},
            "evidence": {"type": "ARRAY", "items": {"type": "STRING"}},
            "false_positive": {"type": "ARRAY", "items": {"type": "STRING"}},
            "next_steps": {"type": "ARRAY", "items": {"type": "STRING"}},
        },
        "required": ["why", "next_steps"],
    },
}

STRICT_TRIAGE = (
    "Return only a JSON array. No markdown, no prose, and no code fences. "
    "One object per input, same order. Each object has severity and plain. "
    "severity is only info, low, medium, or high."
)

STRICT_NARRATIVE = (
    "Return only a JSON array. No markdown, no prose, and no code fences. "
    "One object per input, same order. Each object has why, likelihood, impact, "
    "verify, evidence, false_positive, and next_steps. Do not include URLs."
)


def snippet_text(raw: str, limit: int = 200) -> str:
    return " ".join((raw or "").split())[:limit]


class LLMError(RuntimeError):
    def __init__(self, message: str, *, snippet: str = ""):
        super().__init__(message)
        self.snippet = snippet_text(snippet) if snippet else ""


def failure_line(kind: str, name: str, exc: BaseException) -> str:
    """Log line for a model failure. The reason keeps a single trailing period."""
    reason = redact(str(exc)).replace("\n", " ").strip().rstrip(".")
    reason = reason[:120]
    if kind == "narrative":
        action = "playbook narrative failed"
        fallback = "Keeping the template."
    else:
        action = "triage failed"
        fallback = "Keeping heuristic triage."
    if reason:
        head = f"Model ({name}) {action}: {reason}. {fallback}"
    else:
        head = f"Model ({name}) {action}. {fallback}"
    snippet = snippet_text(getattr(exc, "snippet", "") or "")
    if not snippet:
        return head
    return f"{head} Snippet: {snippet}"


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
        user = json.dumps(triage_brief(chunk))
        raw = await complete(SYSTEM_TRIAGE, user)
        try:
            reviewed.extend(parse_triage(raw, len(chunk)))
            continue
        except LLMError:
            pass
        try:
            retried = await complete(STRICT_TRIAGE, user)
        except LLMError as exc:
            if not exc.snippet:
                exc.snippet = snippet_text(raw)
            raise
        try:
            reviewed.extend(parse_triage(retried, len(chunk)))
        except LLMError as exc:
            if not exc.snippet:
                exc.snippet = snippet_text(retried or raw)
            raise
    return reviewed


def parse_triage(raw: str, count: int) -> list[dict]:
    try:
        data = parse_model_json(raw, prefer="array")
    except LLMError:
        raise
    items = _triage_items(data)
    if not isinstance(items, list):
        raise LLMError("Triage response was not a list.", snippet=raw)
    if len(items) != count:
        raise LLMError("Triage response length did not match the findings.", snippet=raw)
    return items


def parse_model_json(raw: str, *, prefer: str | None = None):
    """Parse almost-JSON model text.

    Strips code fences, takes the first array or object, repairs trailing
    commas, and closes a truncated tail.
    """
    text = strip_fences(raw or "")
    if not text:
        raise LLMError("Model did not return JSON.", snippet=raw)
    found = None
    index = 0
    while index < len(text):
        if text[index] not in "{[":
            index += 1
            continue
        value, consumed = _parse_at(text, index)
        if value is None:
            index += 1
            continue
        found = value
        if prefer == "array" and isinstance(value, list):
            return value
        if prefer == "object" and isinstance(value, dict):
            return value
        if prefer is None:
            return value
        index = max(consumed, index + 1)
    if found is not None:
        return found
    raise LLMError("Model returned invalid JSON.", snippet=text)


def strip_fences(raw: str) -> str:
    text = (raw or "").strip()
    blocks = [block.strip() for block in _FENCE.findall(text) if block.strip()]
    for block in blocks:
        if "[" in block or "{" in block:
            return block
    if blocks:
        return blocks[0]
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def repair_trailing_commas(text: str) -> str:
    previous = None
    current = text
    while current != previous:
        previous = current
        current = re.sub(r",(\s*[\]}])", r"\1", current)
    return current


def close_truncated(text: str) -> str:
    body = text.rstrip()
    if body.endswith("\\"):
        body = body[:-1]
    body = re.sub(r",\s*$", "", body)
    in_string = False
    escape = False
    stack: list[str] = []
    for char in body:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append(char)
        elif char in "}]" and stack:
            stack.pop()
    if in_string:
        body += '"'
    for opener in reversed(stack):
        body += "}" if opener == "{" else "]"
    return repair_trailing_commas(body)


def _balanced_slice(text: str, start: int) -> str | None:
    stack: list[str] = []
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append(char)
        elif char in "}]":
            if not stack:
                return None
            opener = stack.pop()
            if (opener == "{" and char != "}") or (opener == "[" and char != "]"):
                return None
            if not stack:
                return text[start : index + 1]
    return None


def _parse_at(text: str, start: int) -> tuple:
    balanced = _balanced_slice(text, start)
    options = []
    consumed = start + 1
    if balanced is not None:
        options.append(balanced)
        options.append(repair_trailing_commas(balanced))
        consumed = start + len(balanced)
    else:
        closed = close_truncated(text[start:])
        options.append(closed)
        options.append(repair_trailing_commas(closed))
        consumed = len(text)
    for candidate in options:
        if not candidate:
            continue
        try:
            return json.loads(candidate), consumed
        except json.JSONDecodeError:
            continue
    return None, start


def _triage_items(data) -> list | None:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
        if "severity" in data or "plain" in data:
            return [data]
    return None


def _json(raw: str) -> dict:
    try:
        data = parse_model_json(raw, prefer="object")
    except LLMError:
        raise
    if not isinstance(data, dict):
        raise LLMError("Model JSON was not an object.", snippet=raw)
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
    async def complete(
        self,
        system: str,
        user: str,
        *,
        json_mode: bool = False,
        response_schema: dict | None = None,
        max_output_tokens: int = GEMINI_MAX_OUTPUT_TOKENS,
    ) -> str:
        model = self.model
        root = self.base_url.rstrip("/")
        url = f"{root}/v1beta/models/{model}:generateContent"
        headers = connector_headers(self.connector, self.api_key, "gemini")
        body = gemini_request_body(
            system + "\n\n" + user,
            json_mode=json_mode,
            response_schema=response_schema,
            max_output_tokens=max_output_tokens,
        )
        return await _post_text(
            url,
            headers,
            body,
            _pick_gemini_text,
            retries=1,
        )

    async def triage(self, rows: list[dict]) -> list[dict]:
        async def complete(system: str, user: str) -> str:
            return await self.complete(
                system,
                user,
                json_mode=True,
                response_schema=TRIAGE_SCHEMA,
                max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS,
            )

        return await triage_rows(complete, rows)


def gemini_request_body(
    text: str,
    *,
    json_mode: bool = False,
    response_schema: dict | None = None,
    max_output_tokens: int = GEMINI_MAX_OUTPUT_TOKENS,
) -> dict:
    generation: dict = {"temperature": 0.1, "maxOutputTokens": max_output_tokens}
    if json_mode or response_schema is not None:
        generation["responseMimeType"] = "application/json"
    if response_schema is not None:
        generation["responseSchema"] = response_schema
    return {
        "contents": [{"role": "user", "parts": [{"text": text}]}],
        "generationConfig": generation,
    }


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
    chunks = [
        part["text"]
        for part in parts
        if isinstance(part, dict) and not part.get("thought") and isinstance(part.get("text"), str) and part.get("text")
    ]
    if chunks:
        return "".join(chunks)
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
