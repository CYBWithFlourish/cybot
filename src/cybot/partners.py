"""Pinecone memory and TypeSafeAI Jev, both through the Sprites gateway.

Neither connector is required. A missing connector, index, or model skips that
step and leaves the deterministic scope check in charge. Jev can refuse a host
or an active tool the scope check allowed. It cannot allow a host the scope
check refused.
"""

from __future__ import annotations

import re

LOW_BAND = (0.35, 0.65)
CHOICE_CONFIDENCE = 0.6
DEDUPE_SCORE = 0.92
SEVERITIES = ("info", "low", "medium", "high")


def program_namespace(program: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (program or "program").lower()).strip("-")[:40]
    return slug or "program"


def interpret_noul(probability: float) -> dict:
    low = LOW_BAND[0] <= probability <= LOW_BAND[1]
    return {
        "probability": round(probability, 2),
        "confidence": round(abs(probability - 0.5) * 2, 2),
        "yes": probability > LOW_BAND[1],
        "low_confidence": low,
        "stricter_deny": probability < LOW_BAND[0],
    }


def jev_label(false_positive: float, low_confidence: bool) -> str:
    if low_confidence:
        return f"Jev: unsure ({false_positive:.2f}, low confidence). Review this card."
    if false_positive >= LOW_BAND[1]:
        return f"Jev: {false_positive:.2f} likely false positive"
    likely = 1 - false_positive
    return f"Jev: {likely:.2f} likely real"


def apply_scope_gate(allowed: bool, jev: dict | None) -> str:
    """Jev never turns a deterministic deny into an allow."""
    if not allowed:
        return "deny"
    if not jev:
        return "allow"
    if jev.get("stricter_deny"):
        return "deny"
    if jev.get("low_confidence"):
        return "ask"
    return "allow" if jev.get("yes") else "deny"


def log_line(name: str, detail: dict) -> str:
    probability = detail.get("probability")
    confidence = detail.get("confidence")
    bits = [name]
    if probability is not None:
        bits.append(f"p={probability:.2f}")
    if confidence is not None:
        bits.append(f"confidence={confidence:.2f}")
    if detail.get("low_confidence"):
        bits.append("low confidence, asking you to review")
    elif detail.get("stricter_deny"):
        bits.append("stricter deny")
    elif detail.get("yes"):
        bits.append("allow")
    else:
        bits.append("skip")
    return "Jev " + " ".join(bits)


async def scope_decision(gateway, settings: dict, host: str, scope_text: str) -> dict | None:
    payload = await _ask(
        gateway,
        settings,
        f"Host: {host}\nScope text:\n{scope_text[:4000]}",
        {
            "in_scope": {
                "type": "noul",
                "instructions": "Is this host inside the written scope? Answer yes only if the text explicitly includes it.",
            }
        },
    )
    return _noul(payload, "in_scope") if payload else None


async def active_tool_decision(gateway, settings: dict, host: str, intensity: str, tools: list[str]) -> dict | None:
    payload = await _ask(
        gateway,
        settings,
        f"Host: {host}\nApproved intensity: {intensity}\nTools: {', '.join(tools)}",
        {
            "run_tools": {
                "type": "noul",
                "instructions": "Should these active checks run at this intensity against this host? They are HTTP, fixed web ports, and public paths only.",
            }
        },
    )
    return _noul(payload, "run_tools") if payload else None


async def finding_decision(gateway, settings: dict, finding: dict, memory: str) -> dict | None:
    state = (
        f"Host: {finding.get('host')}\nTitle: {finding.get('title')}\n"
        f"Evidence: {finding.get('evidence')}\nNotes: {finding.get('plain')}\n"
        f"Past matches:\n{memory or 'none'}"
    )
    payload = await _ask(
        gateway,
        settings,
        state[:6000],
        {
            "false_positive": {
                "type": "noul",
                "instructions": "Is this reconnaissance note likely a false positive or a duplicate of a past note that was already marked duplicate or fixed?",
            },
            "severity": {
                "type": "score",
                "instructions": "How much attention does this unverified note deserve? Do not treat it as a confirmed vulnerability.",
                "criteria": [
                    "Info. Inventory only.",
                    "Low. Hardening or an extra open web port.",
                    "Medium. An unverified lead worth a closer look.",
                    "High. Unverified, but the upstream score is severe.",
                ],
            },
        },
    )
    if not payload:
        return None
    false_positive = _noul(payload, "false_positive")
    score = _score(payload, "severity")
    if not false_positive:
        return None
    label = jev_label(false_positive["probability"], false_positive["low_confidence"])
    return {"false_positive": false_positive, "severity": score, "label": label}


def stricter_severity(current: str, score: dict | None) -> str:
    if not score or score.get("low_confidence"):
        return current
    order = list(SEVERITIES)
    if current not in order:
        return current
    suggested = score.get("band")
    if suggested not in order:
        return current
    if order.index(suggested) < order.index(current):
        return suggested
    return current


def prior_match(matches: list[dict], run_id: str, threshold: float = DEDUPE_SCORE) -> dict | None:
    """A seen-before hit is a different run above the threshold.

    A high cosine score is not enough. An empty namespace, a zero vector, or
    the current run's own notes can still come back with a large score.
    """
    current = str(run_id or "")
    for match in matches or []:
        if not isinstance(match, dict):
            continue
        try:
            score = float(match.get("score") or 0)
        except (TypeError, ValueError):
            continue
        past = str(match.get("run_id") or "")
        if score >= threshold and past and past != current:
            return match
    return None


async def search_memory(gateway, settings: dict, query: str, program: str, top_k: int = 5, run_id: str = "") -> dict:
    if gateway is None or gateway.find("pinecone") is None:
        return {"configured": False, "reason": "Pinecone connector is not granted.", "matches": []}
    try:
        index = await _index(gateway, settings)
        if not index:
            return {"configured": False, "reason": "No Pinecone index is available.", "matches": []}
        vectors = await embed(gateway, settings, [query], "query")
        if not vectors:
            return {"configured": True, "reason": "Embeddings were not available.", "matches": []}
        matches = await _query(gateway, index, program_namespace(program), vectors[0], top_k, run_id=run_id)
    except Exception as exc:
        return {"configured": True, "reason": f"Pinecone search failed ({type(exc).__name__}).", "matches": []}
    return {"configured": True, "reason": "", "matches": matches}


async def recall(gateway, settings: dict, program: str, text: str, run_id: str = "") -> list[dict]:
    found = await search_memory(gateway, settings, text, program, 3, run_id=run_id)
    return found.get("matches") or []


async def remember(gateway, settings: dict, program: str, rows: list[dict]) -> int:
    if not rows or gateway is None or gateway.find("pinecone") is None:
        return 0
    try:
        index = await _index(gateway, settings)
        if not index:
            return 0
        vectors = await embed(gateway, settings, [row["text"] for row in rows], "passage")
        if not vectors:
            return 0
        payload = []
        for row, values in zip(rows, vectors):
            payload.append(
                {
                    "id": row["id"][:80],
                    "values": values,
                    "metadata": {key: str(value)[:200] for key, value in row.get("metadata", {}).items()},
                }
            )
        await gateway.call(
            "pinecone",
            "POST",
            f"/indexes/{index}/vectors/upsert",
            json={"namespace": program_namespace(program), "vectors": payload[:20]},
        )
        return len(payload[:20])
    except Exception:
        return 0


async def embed(gateway, settings: dict, texts: list[str], input_type: str) -> list[list[float]] | None:
    clean = [text[:1000] for text in texts if text]
    if not clean:
        return None
    if gateway is not None and gateway.find("pinecone") is not None:
        try:
            data = await gateway.call(
                "pinecone",
                "POST",
                "/embed",
                json={
                    "model": settings.get("pinecone_embed_model") or "multilingual-e5-large",
                    "parameters": {"input_type": input_type, "truncate": "END"},
                    "inputs": [{"text": text} for text in clean],
                },
            )
            values = [row.get("values") for row in (data or {}).get("data") or [] if isinstance(row, dict)]
            if values and all(isinstance(item, list) and item for item in values):
                return values
        except Exception:
            pass
    if gateway is not None and gateway.find("openai") is not None:
        try:
            data = await gateway.call(
                "openai",
                "POST",
                "/v1/embeddings",
                json={"model": "text-embedding-3-small", "input": clean},
            )
            rows = (data or {}).get("data") or []
            values = [row.get("embedding") for row in rows if isinstance(row, dict)]
            if values and all(isinstance(item, list) and item for item in values):
                return values
        except Exception:
            pass
    return None


async def _index(gateway, settings: dict) -> str:
    chosen = (settings.get("pinecone_index") or "").strip()
    if chosen and re.fullmatch(r"[A-Za-z0-9-]{1,45}", chosen):
        return chosen
    data = await gateway.call("pinecone", "GET", "/indexes")
    indexes = []
    if isinstance(data, dict):
        indexes = data.get("indexes") or []
    elif isinstance(data, list):
        indexes = data
    for item in indexes:
        name = item.get("name") if isinstance(item, dict) else str(item)
        if name and re.fullmatch(r"[A-Za-z0-9-]{1,45}", str(name)):
            return str(name)
    return ""


async def _query(gateway, index: str, namespace: str, vector: list[float], top_k: int, run_id: str = "") -> list[dict]:
    body = {
        "namespace": namespace,
        "topK": max(1, min(top_k, 8)),
        "vector": vector,
        "includeMetadata": True,
    }
    if run_id:
        body["filter"] = {"run_id": {"$ne": run_id}}
    data = await gateway.call(
        "pinecone",
        "POST",
        f"/indexes/{index}/query",
        json=body,
    )
    matches = []
    for row in (data or {}).get("matches") or []:
        if not isinstance(row, dict):
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        matches.append(
            {
                "id": str(row.get("id") or ""),
                "score": float(row.get("score") or 0),
                "title": str(metadata.get("title") or ""),
                "status": str(metadata.get("status") or ""),
                "text": str(metadata.get("text") or "")[:240],
                "run_id": str(metadata.get("run_id") or ""),
            }
        )
    return matches


async def _ask(gateway, settings: dict, state: str, questions: dict) -> dict | None:
    if gateway is None or gateway.find("typesafe") is None:
        return None
    try:
        return await gateway.call(
            "typesafe",
            "POST",
            "/v1/systemone",
            json={"model": settings.get("jev_model") or "jev-latest", "state": state, "questions": questions},
        )
    except Exception:
        return None


def _noul(payload: dict, name: str) -> dict | None:
    answer = ((payload or {}).get("answers") or {}).get(name) or {}
    if answer.get("type") != "noul":
        return None
    try:
        probability = float(answer.get("noul"))
    except (TypeError, ValueError):
        return None
    return interpret_noul(probability)


def _score(payload: dict, name: str) -> dict | None:
    answer = ((payload or {}).get("answers") or {}).get(name) or {}
    if answer.get("type") != "score":
        return None
    try:
        score = float(answer.get("score"))
        confidence = float(answer.get("confidence") or 0)
    except (TypeError, ValueError):
        return None
    band = SEVERITIES[max(0, min(len(SEVERITIES) - 1, round(score)))]
    return {
        "score": score,
        "confidence": confidence,
        "band": band,
        "low_confidence": confidence < CHOICE_CONFIDENCE,
    }
