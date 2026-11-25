"""Vendored knowledge base for playbook guidance.

Documents are embedded with the existing Pinecone path and stored in the
namespace ``cybot-kb``, separate from per-program memory. Links shown to a
person come only from the catalog.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from cybot.partners import _index, embed

KB_NAMESPACE = "cybot-kb"
SOURCE = "CYBWithFlourish/Awesome-Hacking-with-AI"
REQUIRED = (
    "name",
    "canonical_url",
    "type",
    "catalog_section",
    "maintainer_source",
    "effects",
    "adoption_boundary",
)
_HEADING = re.compile(r"^(#{1,3}) +(.+)$", re.M)


def knowledge_dir() -> Path:
    import os

    override = os.environ.get("CYBOT_KB_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "data" / "knowledge"


def load_catalog(path: Path | None = None) -> list[dict]:
    root = path or knowledge_dir()
    data = json.loads((root / "resource-catalog.json").read_text(encoding="utf-8"))
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("Knowledge catalog is empty.")
    cleaned = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Knowledge catalog has a row that is not an object.")
        for key in REQUIRED:
            if not str(entry.get(key) or "").strip():
                raise ValueError(f"Catalog entry {entry.get('name') or '?'} is missing {key}.")
        url = str(entry["canonical_url"]).strip()
        if not url.startswith("http"):
            raise ValueError(f"Catalog URL is not absolute: {url}")
        cleaned.append(entry)
    return cleaned


def catalog_urls(entries: list[dict] | None = None) -> set[str]:
    rows = entries if entries is not None else load_catalog()
    return {str(row["canonical_url"]).strip() for row in rows}


def stable_id(kind: str, key: str) -> str:
    digest = hashlib.sha256(f"{kind}:{key}".encode()).hexdigest()[:20]
    return f"kb-{kind}-{digest}"


def catalog_documents(entries: list[dict] | None = None) -> list[dict]:
    rows = entries if entries is not None else load_catalog()
    documents = []
    for entry in rows:
        name = str(entry["name"]).strip()
        url = str(entry["canonical_url"]).strip()
        section = str(entry["catalog_section"]).strip()
        kind = str(entry["type"]).strip()
        extra = str(entry.get("status") or entry.get("terms_and_status") or "")
        text = "\n".join(
            [
                name,
                name,
                section,
                kind,
                str(entry.get("effects") or ""),
                str(entry.get("adoption_boundary") or ""),
                extra,
            ]
        )
        documents.append(
            {
                "id": stable_id("catalog", url),
                "text": text[:1000],
                "metadata": {
                    "title": name[:200],
                    "url": url[:500],
                    "type": kind[:80],
                    "section": section[:120],
                    "source": SOURCE,
                },
            }
        )
    return documents


def guide_documents(root: Path | None = None) -> list[dict]:
    folder = root or knowledge_dir()
    documents = []
    for path in sorted(folder.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        parts = _chunk_markdown(text)
        for index, (title, body) in enumerate(parts):
            documents.append(
                {
                    "id": stable_id("guide", f"{path.name}:{index}:{title}"),
                    "text": f"{title}\n{body}"[:1000],
                    "metadata": {
                        "title": title[:200],
                        "url": "",
                        "type": "guide",
                        "section": path.name[:120],
                        "source": SOURCE,
                    },
                }
            )
    return documents


def _chunk_markdown(text: str) -> list[tuple[str, str]]:
    matches = list(_HEADING.finditer(text))
    if not matches:
        return [("Guide", text.strip()[:1000])] if text.strip() else []
    chunks = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        title = match.group(2).strip()
        body = text[start:end].strip()
        if not body:
            continue
        for piece in _split_long(body, 900):
            chunks.append((title, piece))
    return chunks


def _split_long(body: str, limit: int) -> list[str]:
    if len(body) <= limit:
        return [body]
    pieces = []
    start = 0
    while start < len(body):
        pieces.append(body[start : start + limit])
        start += limit
    return pieces


def all_documents() -> list[dict]:
    return catalog_documents() + guide_documents()


async def ingest(gateway, settings: dict) -> dict:
    """Upsert by stable id. A second run overwrites the same ids."""
    if gateway is None or gateway.find("pinecone") is None:
        return {"ok": False, "upserted": 0, "reason": "Pinecone connector is not granted."}
    index = await _index(gateway, settings)
    if not index:
        return {"ok": False, "upserted": 0, "reason": "No Pinecone index is available."}
    documents = all_documents()
    upserted = 0
    for start in range(0, len(documents), 20):
        batch = documents[start : start + 20]
        vectors = await embed(gateway, settings, [row["text"] for row in batch], "passage")
        if not vectors or len(vectors) != len(batch):
            return {"ok": False, "upserted": upserted, "reason": "Embeddings were not available."}
        payload = [
            {"id": row["id"], "values": vector, "metadata": row["metadata"]}
            for row, vector in zip(batch, vectors)
        ]
        await gateway.call(
            "pinecone",
            "POST",
            f"/indexes/{index}/vectors/upsert",
            json={"namespace": KB_NAMESPACE, "vectors": payload},
        )
        upserted += len(payload)
    return {"ok": True, "upserted": upserted, "namespace": KB_NAMESPACE, "ids": [row["id"] for row in documents]}


async def search(gateway, settings: dict, query: str, k: int = 5) -> list[dict]:
    if gateway is None or gateway.find("pinecone") is None:
        return []
    text = (query or "").strip()
    if not text:
        return []
    index = await _index(gateway, settings)
    if not index:
        return []
    vectors = await embed(gateway, settings, [text], "query")
    if not vectors:
        return []
    data = await gateway.call(
        "pinecone",
        "POST",
        f"/indexes/{index}/query",
        json={
            "namespace": KB_NAMESPACE,
            "topK": max(1, min(int(k), 8)),
            "vector": vectors[0],
            "includeMetadata": True,
        },
    )
    allowed = catalog_urls()
    matches = []
    for row in (data or {}).get("matches") or []:
        if not isinstance(row, dict):
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        url = str(metadata.get("url") or "")
        if url and url not in allowed:
            continue
        matches.append(
            {
                "id": str(row.get("id") or ""),
                "score": float(row.get("score") or 0),
                "title": str(metadata.get("title") or ""),
                "url": url,
                "type": str(metadata.get("type") or ""),
                "section": str(metadata.get("section") or ""),
                "source": str(metadata.get("source") or ""),
            }
        )
    return matches


async def further_reading(gateway, settings: dict, finding: dict, book: dict, k: int = 4) -> list[dict]:
    """Catalog links only. The model does not choose these URLs."""
    query = " ".join(
        [
            str(finding.get("title") or ""),
            str(book.get("class") or ""),
            str(book.get("why") or ""),
        ]
    )[:500]
    try:
        matches = await search(gateway, settings, query, k=k)
    except Exception:
        return []
    allowed = catalog_urls()
    reading = []
    seen = set()
    for match in matches:
        url = match.get("url") or ""
        if url not in allowed or url in seen:
            continue
        seen.add(url)
        reading.append({"label": match.get("title") or url, "url": url})
    return reading[:k]
