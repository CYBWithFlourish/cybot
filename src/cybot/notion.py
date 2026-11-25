"""Notion via the Sprites community connector.

The token stays in Fly.io. Every call sends Notion-Version and no bearer token.
A connector with no access policy denies the Sprite; CYBOT records that and
keeps the local report.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from cybot.redact import redact

_RAW_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
NOTION_VERSION = "2026-03-11"
STATUSES = ("new", "triaged", "reported", "duplicate", "fixed")


def resolve_notion_choice(global_mode: str, requested, source: str) -> tuple[str, str]:
    """Return yes, no, or ask, plus a short note.

    yes is returned only for a global always, a dashboard yes, or MCP publish_to_notion true.
    """
    mode = (global_mode or "ask").strip().lower()
    if mode not in {"ask", "always", "never"}:
        mode = "ask"
    if mode == "never":
        return "no", "Notion publishing is turned off in settings."
    if mode == "always":
        return "yes", "Settings say to publish every finished run to Notion."
    if source == "mcp":
        if requested is True:
            return "yes", "This run will publish to Notion when it finishes."
        if requested is False:
            return "no", "Notion was not published."
        return (
            "no",
            "Notion was not published. Call publish_report_to_notion with this run_id after the run finishes.",
        )
    if source == "telegram":
        return "ask", "Telegram will ask with Yes and No after the summary."
    if requested in {"yes", True}:
        return "yes", "This run will publish to Notion when it finishes."
    if requested == "no":
        return "no", "Notion was not published."
    return "ask", "Confirm a Notion page after the run finishes."


class NotionSkipped(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize_id(value: str) -> str:
    raw = (value or "").strip()
    if _UUID.match(raw):
        return raw.lower()
    compact = raw.replace("-", "")
    if not _RAW_ID.match(compact):
        raise ValueError("Paste the database id from the Notion URL (32 letters and numbers).")
    compact = compact.lower()
    return f"{compact[0:8]}-{compact[8:12]}-{compact[12:16]}-{compact[16:20]}-{compact[20:32]}"


def notion_headers() -> dict[str, str]:
    return {"Notion-Version": NOTION_VERSION, "Content-Type": "application/json"}


async def publish_run(gateway, store, run: dict, findings: list[dict]) -> dict:
    """Create one report page and one tracker row per finding. Never raises."""
    try:
        result = await _publish(gateway, store.settings(), run, findings)
    except NotionSkipped as exc:
        store.event(run.get("id") or "", "info", exc.reason)
        return {"published": False, "reason": exc.reason}
    except Exception as exc:
        reason = f"Notion publish failed ({type(exc).__name__}). The local report is unchanged."
        store.event(run.get("id") or "", "warn", reason)
        return {"published": False, "reason": reason}
    store.event(
        run.get("id") or "",
        "ok",
        f"Notion report page created. Tracker rows: {result.get('tracked', 0)}.",
    )
    return result


async def _publish(gateway, settings: dict, run: dict, findings: list[dict]) -> dict:
    _require(gateway)
    reports_id = (settings.get("notion_reports_database") or "").strip()
    tracker_id = (settings.get("notion_tracker_database") or "").strip()
    if not reports_id and not tracker_id:
        raise NotionSkipped(
            "Notion connector is granted. Add the reports and tracker database ids to publish."
        )
    tracked = 0
    report_page = None
    if reports_id:
        source = await _source(gateway, reports_id)
        schema = await _schema(gateway, source)
        report_page = await gateway.call(
            "notion",
            "POST",
            "/v1/pages",
            json={
                "parent": {"data_source_id": source},
                "properties": _report_properties(schema, run, findings),
                "children": _report_blocks(findings),
            },
        )
    if tracker_id:
        source = await _source(gateway, tracker_id)
        schema = await _schema(gateway, source)
        for finding in findings[:40]:
            if await _already_tracked(gateway, source, schema, finding.get("id") or ""):
                continue
            await gateway.call(
                "notion",
                "POST",
                "/v1/pages",
                json={
                    "parent": {"data_source_id": source},
                    "properties": _tracker_properties(schema, run, finding),
                },
            )
            tracked += 1
    return {"published": True, "tracked": tracked, "report": _page_ref(report_page)}


async def list_programs(gateway, settings: dict) -> dict:
    try:
        _require(gateway)
    except NotionSkipped as exc:
        return {"configured": False, "reason": exc.reason, "programs": []}
    database = (settings.get("notion_programs_database") or "").strip()
    if not database:
        return {
            "configured": False,
            "reason": "Set the Programs & Scope database id to read scope from Notion.",
            "programs": [],
        }
    try:
        source = await _source(gateway, database)
        payload = await gateway.call(
            "notion",
            "POST",
            f"/v1/data_sources/{source}/query",
            json={"page_size": 20},
        )
    except Exception as exc:
        return {
            "configured": True,
            "reason": f"Could not read Programs & Scope ({type(exc).__name__}).",
            "programs": [],
        }
    programs = []
    for page in (payload or {}).get("results") or []:
        props = page.get("properties") or {}
        name = _text(props, "name", "program", "title")
        if not name:
            name = _title_text(props)
        include = _lines(_text(props, "include", "in scope", "scope"))
        exclude = _lines(_text(props, "exclude", "excluded"))
        authorization = _text(props, "authorization")
        active = _checkbox(props, "active", default=True)
        if name:
            programs.append(
                {
                    "program": name,
                    "include": include,
                    "exclude": exclude,
                    "authorization": authorization,
                    "active": active,
                }
            )
    return {"configured": True, "reason": "", "programs": programs}


async def list_tracked(gateway, settings: dict, *, status: str = "", program: str = "") -> dict:
    try:
        _require(gateway)
    except NotionSkipped as exc:
        return {"configured": False, "reason": exc.reason, "findings": []}
    database = (settings.get("notion_tracker_database") or "").strip()
    if not database:
        return {
            "configured": False,
            "reason": "Set the findings tracker database id to read Notion.",
            "findings": [],
        }
    if status and status not in STATUSES:
        return {"configured": True, "reason": "Status must be new, triaged, reported, duplicate, or fixed.", "findings": []}
    try:
        source = await _source(gateway, database)
        schema = await _schema(gateway, source)
        body: dict = {"page_size": 25}
        if status and _has(schema, "status"):
            body["filter"] = {"property": _real_name(schema, "status"), "select": {"equals": status}}
        payload = await gateway.call("notion", "POST", f"/v1/data_sources/{source}/query", json=body)
    except Exception as exc:
        return {"configured": True, "reason": f"Could not read the tracker ({type(exc).__name__}).", "findings": []}
    rows = []
    for page in (payload or {}).get("results") or []:
        props = page.get("properties") or {}
        item = {
            "id": page.get("id") or "",
            "url": page.get("url") or "",
            "title": _title_text(props),
            "status": _text(props, "status") or "new",
            "severity": _text(props, "severity"),
            "program": _text(props, "program"),
            "host": _text(props, "host"),
            "finding_id": _text(props, "finding id", "finding_id"),
            "created": _text(props, "created", "date"),
        }
        if status and item["status"] != status:
            continue
        if program and item["program"].casefold() != program.casefold():
            continue
        rows.append(item)
    return {"configured": True, "reason": "", "findings": rows}


def scope_from_programs(programs: list[dict], program: str) -> dict:
    for row in programs:
        if row.get("active", True) and str(row.get("program") or "").casefold() == program.casefold():
            return row
    raise NotionSkipped(f"No active Notion program named {program}.")


async def _source(gateway, database_id: str) -> str:
    nid = normalize_id(database_id)
    try:
        database = await gateway.call("notion", "GET", f"/v1/databases/{nid}")
    except Exception:
        database = None
    sources = (database or {}).get("data_sources") if isinstance(database, dict) else None
    if sources and isinstance(sources, list) and sources[0].get("id"):
        return str(sources[0]["id"])
    return nid


async def _schema(gateway, source_id: str) -> dict:
    try:
        payload = await gateway.call("notion", "GET", f"/v1/data_sources/{source_id}")
    except Exception:
        return {}
    properties = payload.get("properties") if isinstance(payload, dict) else None
    return properties if isinstance(properties, dict) else {}


async def _already_tracked(gateway, source: str, schema: dict, finding_id: str) -> bool:
    if not finding_id or not _has(schema, "finding id"):
        return False
    payload = await gateway.call(
        "notion",
        "POST",
        f"/v1/data_sources/{source}/query",
        json={
            "page_size": 1,
            "filter": {
                "property": _real_name(schema, "finding id"),
                "rich_text": {"equals": finding_id},
            },
        },
    )
    return bool((payload or {}).get("results"))


def _require(gateway) -> None:
    if gateway is None or gateway.find("notion") is None:
        raise NotionSkipped("Notion connector is not granted. The report stays on the Sprite.")


def _report_properties(schema: dict, run: dict, findings: list[dict]) -> dict:
    counts = Counter(row.get("severity") or "info" for row in findings)
    title = _real_name(schema, "target") or _title_property(schema) or "Target"
    fields = {title: _title(str(run.get("target") or "recon"))}
    _put(fields, schema, "program", _rich(str(run.get("program") or "")))
    scope = run.get("scope_json") or ""
    _put(fields, schema, "scope", _rich(scope[:1800]))
    _put(fields, schema, "intensity", _rich(str(run.get("intensity") or "")))
    _put(fields, schema, "run", _rich(str(run.get("id") or "")))
    started = str(run.get("created_at") or "")[:10]
    if started:
        _put(fields, schema, "started", {"date": {"start": started}})
    for name in ("high", "medium", "low", "info"):
        _put(fields, schema, name, {"number": int(counts.get(name, 0))})
    return fields


def _tracker_properties(schema: dict, run: dict, finding: dict) -> dict:
    title = _title_property(schema) or "Finding"
    fields = {title: _title(str(finding.get("title") or "Finding")[:200])}
    _put(fields, schema, "status", {"select": {"name": "new"}})
    if finding.get("severity"):
        _put(fields, schema, "severity", {"select": {"name": str(finding["severity"])}})
    _put(fields, schema, "program", _rich(str(run.get("program") or "")))
    _put(fields, schema, "host", _rich(str(finding.get("host") or "")))
    _put(fields, schema, "tool", _rich(str(finding.get("tool") or "")))
    _put(fields, schema, "finding id", _rich(str(finding.get("id") or "")))
    book = finding.get("playbook")
    if isinstance(book, str):
        try:
            book = json.loads(book)
        except json.JSONDecodeError:
            book = None
    if isinstance(book, dict):
        steps = "; ".join(str(item) for item in (book.get("next_steps") or [])[:4])
        refs = "; ".join(
            f"{item.get('label')}: {item.get('url')}" for item in (book.get("references") or [])[:6] if item.get("url")
        )
        _put(fields, schema, "next steps", _rich(steps))
        _put(fields, schema, "references", _rich(refs))
        epss = book.get("epss")
        _put(fields, schema, "epss", _rich(str(epss) if epss else "not available"))
        kev = book.get("kev")
        kev_text = "unknown" if kev is None else ("listed" if kev else "not listed")
        _put(fields, schema, "kev", _rich(kev_text))
    started = str(run.get("created_at") or "")[:10]
    if started:
        _put(fields, schema, "created", {"date": {"start": started}})
    return fields


def _report_blocks(findings: list[dict]) -> list[dict]:
    blocks = [
        _paragraph(
            "Reconnaissance notes. These are not confirmed vulnerabilities and they are not exploit steps."
        )
    ]
    for finding in findings[:30]:
        blocks.append(_heading(f"[{finding.get('severity') or 'info'}] {finding.get('title') or ''}"))
        body = redact(
            f"{finding.get('host') or ''} - {finding.get('tool') or ''}. "
            f"{finding.get('plain') or finding.get('evidence') or ''}"
        )
        blocks.append(_paragraph(body))
        repro = redact(str(finding.get("repro") or ""))[:300]
        if repro:
            blocks.append(_paragraph(f"Reproduce: {repro}"))
        book = finding.get("playbook")
        if isinstance(book, str):
            try:
                book = json.loads(book)
            except json.JSONDecodeError:
                book = None
        if isinstance(book, dict):
            step = "; ".join(str(item) for item in (book.get("next_steps") or [])[:3])
            refs = "; ".join(str(item.get("url") or "") for item in (book.get("references") or [])[:4])
            blocks.append(_paragraph(f"Next steps: {step}"))
            if refs:
                blocks.append(_paragraph(f"References: {refs}"))
    return blocks


def _put(fields: dict, schema: dict, wanted: str, value: dict) -> None:
    if schema and not _has(schema, wanted):
        return
    fields[_real_name(schema, wanted) or wanted.title()] = value


def _has(schema: dict, wanted: str) -> bool:
    return _real_name(schema, wanted) is not None


def _real_name(schema: dict, wanted: str) -> str | None:
    folded = wanted.casefold()
    for name in schema:
        if name.casefold() == folded:
            return name
    return None


def _title_property(schema: dict) -> str | None:
    for name, spec in schema.items():
        if isinstance(spec, dict) and spec.get("type") == "title":
            return name
    return None


def _title(text: str) -> dict:
    return {"title": [{"type": "text", "text": {"content": text[:200]}}]}


def _rich(text: str) -> dict:
    return {"rich_text": [{"type": "text", "text": {"content": text[:1800]}}]}


def _paragraph(text: str) -> dict:
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": [{"type": "text", "text": {"content": text[:1800]}}]},
    }


def _heading(text: str) -> dict:
    return {
        "object": "block",
        "type": "heading_3",
        "heading_3": {"rich_text": [{"type": "text", "text": {"content": text[:1800]}}]},
    }


def _title_text(properties: dict) -> str:
    for prop in properties.values():
        if isinstance(prop, dict) and prop.get("type") == "title":
            return "".join(part.get("plain_text", "") for part in prop.get("title") or [])
    return ""


def _text(properties: dict, *names: str) -> str:
    wanted = {name.casefold() for name in names}
    for key, prop in properties.items():
        if key.casefold() not in wanted or not isinstance(prop, dict):
            continue
        kind = prop.get("type")
        if kind in {"title", "rich_text"}:
            return "".join(part.get("plain_text", "") for part in prop.get(kind) or [])
        if kind == "select":
            return str((prop.get("select") or {}).get("name") or "")
        if kind == "date":
            return str((prop.get("date") or {}).get("start") or "")
    return ""


def _checkbox(properties: dict, name: str, *, default: bool) -> bool:
    for key, prop in properties.items():
        if key.casefold() == name.casefold() and isinstance(prop, dict) and prop.get("type") == "checkbox":
            return bool(prop.get("checkbox"))
    return default


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.replace(",", "\n").splitlines() if line.strip()]


def _page_ref(page) -> dict | None:
    if not isinstance(page, dict):
        return None
    return {"id": page.get("id") or "", "url": page.get("url") or ""}
