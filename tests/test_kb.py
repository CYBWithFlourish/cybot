import asyncio
import hashlib
import re

from cybot.kb import (
    KB_NAMESPACE,
    SOURCE,
    catalog_documents,
    further_reading,
    guide_documents,
    ingest,
    load_catalog,
    search,
    stable_id,
)
from cybot.playbook import prepare_playbooks, render_playbook_markdown


def _hash_embed(text: str, dim: int = 32) -> list[float]:
    """Lexical stand-in for an embedding model. An exact phrase dominates."""
    lowered = text.lower()
    vector = [0.0] * dim
    vector[0] = lowered.count("mitre atlas") * 10
    tokens = re.findall(r"[A-Za-z0-9]+", lowered)
    for token in tokens:
        bucket = 1 + (int(hashlib.sha256(token.encode()).hexdigest()[:2], 16) % (dim - 1))
        vector[bucket] += 1.0
    norm = sum(value * value for value in vector) ** 0.5 or 1.0
    return [value / norm for value in vector]


class FakePinecone:
    def __init__(self):
        self.namespaces = {}
        self.upserts = []

    def find(self, name):
        return {"provider": name} if name == "pinecone" else None

    async def call(self, provider, method, path, json=None, **_kwargs):
        if path == "/embed":
            values = [_hash_embed(item["text"]) for item in json["inputs"]]
            return {"data": [{"values": row} for row in values]}
        if path == "/indexes":
            return {"indexes": [{"name": "cybot"}]}
        if path.endswith("/vectors/upsert"):
            assert json["namespace"] == KB_NAMESPACE
            self.upserts.append(json["namespace"])
            bucket = self.namespaces.setdefault(json["namespace"], {})
            for vector in json["vectors"]:
                bucket[vector["id"]] = vector
            return {"upsertedCount": len(json["vectors"])}
        if path.endswith("/query"):
            assert json["namespace"] == KB_NAMESPACE
            bucket = self.namespaces.get(json["namespace"], {})
            query = json["vector"]
            scored = []
            for vector in bucket.values():
                score = sum(left * right for left, right in zip(query, vector["values"]))
                scored.append((score, vector))
            scored.sort(key=lambda item: item[0], reverse=True)
            top = scored[: json["topK"]]
            return {
                "matches": [
                    {"id": vector["id"], "score": score, "metadata": vector["metadata"]}
                    for score, vector in top
                ]
            }
        raise AssertionError(path)


def test_catalog_loads_and_documents_keep_metadata():
    entries = load_catalog()
    assert len(entries) == 156
    urls = {row["canonical_url"] for row in entries}
    assert len(urls) == 156
    assert all(url.startswith("http") for url in urls)
    docs = catalog_documents(entries)
    atlas = next(row for row in docs if row["metadata"]["title"] == "MITRE ATLAS")
    assert atlas["metadata"]["url"] == "https://atlas.mitre.org/"
    assert atlas["metadata"]["type"] == "Threat knowledge base"
    assert atlas["metadata"]["section"] == "Primary Guidance and Threat Knowledge"
    assert atlas["metadata"]["source"] == SOURCE
    assert atlas["id"] == stable_id("catalog", "https://atlas.mitre.org/")
    guides = guide_documents()
    assert guides
    assert guides[0]["metadata"]["type"] == "guide"
    assert guides[0]["metadata"]["url"] == ""


def test_search_returns_the_seeded_catalog_entry_and_ingest_is_idempotent():
    gateway = FakePinecone()
    settings = {"pinecone_index": "cybot", "pinecone_embed_model": "multilingual-e5-large"}
    first = asyncio.run(ingest(gateway, settings))
    second = asyncio.run(ingest(gateway, settings))
    assert first["ok"] and second["ok"]
    assert first["ids"] == second["ids"]
    assert len(gateway.namespaces[KB_NAMESPACE]) == len(set(first["ids"]))
    assert set(gateway.upserts) == {KB_NAMESPACE}
    # A URL that is not in the catalog is dropped even if a vector carries it.
    gateway.namespaces[KB_NAMESPACE]["bogus"] = {
        "id": "bogus",
        "values": _hash_embed("MITRE ATLAS"),
        "metadata": {"title": "Invented", "url": "https://evil.example/atlas", "type": "note", "section": "x", "source": SOURCE},
    }
    matches = asyncio.run(search(gateway, settings, "MITRE ATLAS", k=5))
    assert matches
    assert matches[0]["title"] == "MITRE ATLAS"
    assert matches[0]["url"] == "https://atlas.mitre.org/"
    assert all(row["url"] != "https://evil.example/atlas" for row in matches)


def test_playbook_lists_catalog_links_apart_from_cve_references():
    gateway = FakePinecone()
    settings = {"pinecone_index": "cybot", "pinecone_embed_model": "multilingual-e5-large"}
    asyncio.run(ingest(gateway, settings))
    finding = {
        "host": "www.example.com",
        "tool": "nvd_cves",
        "title": "Unverified note to compare with MITRE ATLAS",
        "evidence": "CVSS unknown; keyword nginx; not confirmed on this host",
        "severity": "info",
        "plain": "NVD keyword hit only.",
    }

    class Mock:
        name = "mock"

    _notes, enriched = asyncio.run(
        prepare_playbooks(Mock(), gateway, {"program": "Example", "scope_json": "{}"}, [finding], fetch=False, settings=settings)
    )
    book = enriched[0]["playbook"]
    assert any(link["url"] == "https://atlas.mitre.org/" for link in book["further_reading"])
    rendered = "\n".join(render_playbook_markdown(book))
    references, further = rendered.split("- Further reading / techniques:")
    assert "https://nvd.nist.gov/vuln/detail/" not in further or "CVE" in references
    assert "https://atlas.mitre.org/" in further
    assert "https://atlas.mitre.org/" not in references
    assert "- References:" in references
