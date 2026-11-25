import asyncio
import json

from cybot.engine import _triage
from cybot.llm import (
    GEMINI_MAX_OUTPUT_TOKENS,
    LLMError,
    TRIAGE_CHUNK,
    _pick_gemini_text,
    failure_line,
    gemini_request_body,
    parse_triage,
)
from cybot.playbook import apply_narratives, parse_narrative, template_playbook


def _row(index: int):
    return type(
        "Row",
        (),
        {
            "host": "www.example.com",
            "tool": "dns_records",
            "title": f"Note {index}",
            "evidence": "TXT record present",
            "severity": "info",
            "plain": "A DNS note, not a confirmed vulnerability.",
        },
    )()


def test_fenced_array_with_trailing_commas():
    raw = """Ranking:
```json
[
  {"severity": "low", "plain": "HSTS is missing on the homepage.",},
  {"severity": "info", "plain": "A TXT record is present.",}
]
```
"""
    items = parse_triage(raw, 2)
    assert items[0]["severity"] == "low"
    assert "HSTS" in items[0]["plain"]


def test_truncated_triage_array_is_repaired():
    raw = '[{"severity":"medium","plain":"The homepage names nginx/1.25'
    items = parse_triage(raw, 1)
    assert items[0]["severity"] == "medium"
    assert "nginx/1.25" in items[0]["plain"]


def test_prose_before_the_array_is_ignored():
    raw = 'I ranked them as follows: [{"severity":"info","plain":"Note."}] Done.'
    assert parse_triage(raw, 1)[0]["plain"] == "Note."


def test_invalid_json_keeps_a_short_snippet():
    raw = "Sorry, I cannot rank these. " + ("no json here. " * 30)
    try:
        parse_triage(raw, 1)
    except LLMError as exc:
        assert exc.snippet
        assert len(exc.snippet) <= 200
        assert "Sorry" in exc.snippet
    else:
        raise AssertionError("expected LLMError")


def test_truncated_narrative_repairs_and_drops_nothing_required():
    raw = '[{"why":"A person should retest this header","next_steps":["Open the homepage"'
    repaired = parse_narrative(raw, 1)
    assert repaired[0]["why"].startswith("A person should retest")
    assert "homepage" in repaired[0]["next_steps"][0]


def test_gemini_schema_and_joined_candidate_parts():
    body = gemini_request_body(
        "rank",
        json_mode=True,
        response_schema={"type": "ARRAY"},
        max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS,
    )
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"]["type"] == "ARRAY"
    assert config["maxOutputTokens"] == 8192
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"thought": True, "text": "hidden"},
                        {"text": '[{"severity":"info","plain":"hel'},
                        {"text": 'lo"}]'},
                    ]
                }
            }
        ]
    }
    joined = _pick_gemini_text(data)
    assert joined == '[{"severity":"info","plain":"hello"}]'
    assert parse_triage(joined, 1)[0]["plain"] == "hello"


def test_failure_line_does_not_double_the_period():
    exc = LLMError("Model returned invalid JSON.", snippet="[{" + ("nope " * 80))
    line = failure_line("triage", "gemini", exc)
    assert line.startswith("Model (gemini) triage failed: Model returned invalid JSON. Keeping heuristic triage.")
    assert "JSON.." not in line
    assert "triage.." not in line
    snippet = line.split("Snippet: ", 1)[1]
    assert len(snippet) <= 200
    narrative = failure_line("narrative", "gemini", exc)
    assert narrative.startswith(
        "Model (gemini) playbook narrative failed: Model returned invalid JSON. Keeping the template."
    )
    assert "JSON.." not in narrative


def test_gemini_triage_retries_a_bad_array_once():
    from cybot.llm import GeminiLLM

    llm = GeminiLLM("gemini", "https://example.invalid", "key", "gemini-flash-lite-latest")
    prompts = []

    async def complete(system, user, **kwargs):
        prompts.append(system)
        assert kwargs["response_schema"]["type"] == "ARRAY"
        assert kwargs["max_output_tokens"] == GEMINI_MAX_OUTPUT_TOKENS
        if len(prompts) == 1:
            return "```json\nnot-json\n```"
        return '[{"severity":"low","plain":"Header note."}]'

    llm.complete = complete  # type: ignore[method-assign]
    result = asyncio.run(llm.triage([{"title": "t", "evidence": "e", "severity": "info"}]))
    assert result[0]["severity"] == "low"
    assert len(prompts) == 2
    assert "JSON array" in prompts[1]


def test_engine_logs_a_short_snippet_without_a_double_period():
    assert TRIAGE_CHUNK == 5

    class Recorder:
        name = "gemini"

        async def triage(self, rows):
            raise LLMError("Model returned invalid JSON.", snippet="[{" + ("nope " * 40))

    class Mem:
        def __init__(self):
            self.events = []

        def event(self, run_id, level, message):
            self.events.append(message)

    store = Mem()
    output = asyncio.run(_triage(Recorder(), [_row(index) for index in range(6)], store=store, run_id="run1"))
    assert "JSON.." not in store.events[0]
    assert "Snippet:" in store.events[0]
    assert len(store.events[0].split("Snippet: ", 1)[1]) <= 200
    assert output[0].plain.startswith("A DNS note")
    assert len(output) == 6


def test_playbook_narrative_retries_malformed_gemini_output():
    finding = {
        "title": "Missing header",
        "host": "www.example.com",
        "evidence": "no HSTS",
        "tool": "header_hygiene",
    }
    book = template_playbook(finding)
    calls = []

    class Model:
        name = "gemini"

        async def complete(self, system, user, *, json_mode=False, response_schema=None, max_output_tokens=0):
            calls.append((system, response_schema, max_output_tokens))
            if len(calls) == 1:
                return "```json\n{broken,\n```"
            return json.dumps(
                [
                    {
                        "why": "The homepage response omitted HSTS.",
                        "likelihood": "possible",
                        "impact": "browsers may accept a downgrade",
                        "verify": ["Read the response headers."],
                        "evidence": ["No strict-transport-security header."],
                        "false_positive": ["A proxy may strip it."],
                        "next_steps": ["Compare a second request."],
                    }
                ]
            )

    failed = []
    books = asyncio.run(apply_narratives(Model(), [finding], [book], on_fail=failed.append))
    assert len(calls) == 2
    assert calls[0][1]["type"] == "ARRAY"
    assert calls[0][2] == GEMINI_MAX_OUTPUT_TOKENS
    assert "JSON array" in calls[1][0]
    assert books[0]["source"] == "model"
    assert failed == []
    assert "homepage response omitted HSTS" in books[0]["why"]
