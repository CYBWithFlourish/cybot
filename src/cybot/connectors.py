"""Sprites connectors.

A connector is configured in the Fly.io dashboard (organization, Sprites,
Connectors). The credential stays in the control plane. From inside an
authorized Sprite, CYBOT calls:

    https://api.sprites.dev/v1/gateway/<provider>/<connection_id>/<path>

with no provider key. A connector that has no access policy denies every Sprite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

_GATEWAY = re.compile(
    r"https://api\.sprites\.dev/v1/gateway/([a-z0-9_-]+)/([A-Za-z0-9_-]+)",
    re.I,
)

# Canonical provider name -> chat style. "other" means not a model.
MODEL_STYLE = {
    "ollama": "openai",
    "openai": "openai",
    "openrouter": "openai",
    "anthropic": "anthropic",
    "gemini": "gemini",
}

# First granted model connector wins. OpenRouter is how Grok is reached:
# there is no xAI connector, so a Grok model id is an OpenRouter model.
MODEL_PREFERENCE = ("ollama", "openrouter", "anthropic", "openai", "gemini")

CANONICAL = {
    "ollama-cloud": "ollama",
    "google-gemini": "gemini",
    "google": "gemini",
    "claude": "anthropic",
    "notion-community": "notion",
    "typesafeai": "typesafe",
    "type-safe-ai": "typesafe",
    "s3-compatible": "s3",
    "s3-compatible-object-store": "s3",
    "object-store": "s3",
}

# method, path regex. Anything else is refused before it leaves the process.
ROUTES: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "ollama": [
        ("POST", re.compile(r"^/v1/chat/completions$")),
        ("POST", re.compile(r"^/api/chat$")),
    ],
    "openrouter": [("POST", re.compile(r"^/api/v1/chat/completions$"))],
    "openai": [
        ("POST", re.compile(r"^/v1/chat/completions$")),
        ("POST", re.compile(r"^/v1/embeddings$")),
    ],
    "anthropic": [("POST", re.compile(r"^/v1/messages$"))],
    "gemini": [("POST", re.compile(r"^/v1beta/models/[A-Za-z0-9._-]+:generateContent$"))],
    "pushover": [("POST", re.compile(r"^/1/messages\.json$"))],
    "tigris": [("PUT", re.compile(r"^/cybot/reports/[a-f0-9]+\.md$"))],
    "s3": [("PUT", re.compile(r"^/cybot/reports/[a-f0-9]+\.md$"))],
    "firecrawl": [("POST", re.compile(r"^/v2/scrape$"))],
    "exa": [
        ("POST", re.compile(r"^/search$")),
        ("POST", re.compile(r"^/contents$")),
    ],
    "tavily": [("POST", re.compile(r"^/search$"))],
    "linkup": [("POST", re.compile(r"^/v1/search$"))],
    "kagi": [("GET", re.compile(r"^/api/v0/search$"))],
    "github": [
        ("GET", re.compile(r"^/search/code$")),
        ("PUT", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/contents/cybot-reports/[a-f0-9]+\.md$")),
    ],
    "notion": [
        ("GET", re.compile(r"^/v1/users/me$")),
        ("GET", re.compile(r"^/v1/databases/[0-9a-fA-F-]{32,36}$")),
        ("GET", re.compile(r"^/v1/data_sources/[0-9a-fA-F-]{32,36}$")),
        ("POST", re.compile(r"^/v1/data_sources/[0-9a-fA-F-]{32,36}/query$")),
        ("POST", re.compile(r"^/v1/pages$")),
    ],
    "pinecone": [
        ("GET", re.compile(r"^/indexes$")),
        ("POST", re.compile(r"^/embed$")),
        ("POST", re.compile(r"^/indexes/[A-Za-z0-9-]{1,45}/query$")),
        ("POST", re.compile(r"^/indexes/[A-Za-z0-9-]{1,45}/vectors/upsert$")),
    ],
    "typesafe": [
        ("GET", re.compile(r"^/v1/models$")),
        ("POST", re.compile(r"^/v1/systemone$")),
    ],
}

SEARCH_PROVIDERS = ("exa", "tavily", "linkup", "kagi")
STORAGE_PROVIDERS = ("tigris", "s3")
ALERT_PROVIDERS = ("pushover",)


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class Connector:
    provider: str
    raw_provider: str
    connection_id: str
    gateway_base: str
    style: str
    snippet: str = ""

    def chat_base(self) -> str:
        return self.gateway_base.rstrip("/")


def canonical(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return CANONICAL.get(slug, slug)


def parse_gateway_list(payload) -> list[Connector]:
    items: list[dict] = []
    if isinstance(payload, list):
        items = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        for key in ("connections", "connectors", "providers", "connected", "available"):
            value = payload.get(key)
            if isinstance(value, list):
                items.extend(item for item in value if isinstance(item, dict))
    found: list[Connector] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        connector = _one(item)
        if connector is None:
            continue
        key = (connector.provider, connector.connection_id)
        if key in seen:
            continue
        seen.add(key)
        found.append(connector)
    return found


def _one(item: dict) -> Connector | None:
    raw = str(item.get("provider") or item.get("name") or "").strip().lower()
    connection_id = str(item.get("id") or item.get("connection_id") or "").strip()
    snippet = str(item.get("usage_snippet") or "")
    base = str(item.get("gateway_base_url") or item.get("base_url") or "").strip()
    if not raw or not connection_id:
        match = _GATEWAY.search(snippet) or _GATEWAY.search(base)
        if not match:
            return None
        raw = raw or match.group(1).lower()
        connection_id = connection_id or match.group(2)
    provider = canonical(raw)
    if not base:
        base = f"https://api.sprites.dev/v1/gateway/{raw}/{connection_id}"
    else:
        base = base.rstrip("/")
        marker = f"/v1/gateway/{raw}/{connection_id}"
        index = base.lower().find(marker.lower())
        if index != -1:
            base = base[: index + len(marker)]
    style = MODEL_STYLE.get(provider, "other")
    return Connector(provider, raw, connection_id, base, style, snippet[:180])


def pick(connectors: list[Connector], provider: str, connection_id: str = "") -> Connector | None:
    provider = canonical(provider)
    connection_id = connection_id.strip()
    matches = [item for item in connectors if item.provider == provider]
    if connection_id:
        for item in matches:
            if item.connection_id == connection_id:
                return item
        return None
    return matches[0] if matches else None


DISPLAY_NAMES = {
    "gemini": "Google Gemini",
    "ollama": "Ollama Cloud",
    "openrouter": "OpenRouter",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "firecrawl": "Firecrawl",
    "notion": "Notion",
    "pinecone": "Pinecone",
    "exa": "Exa",
    "tavily": "Tavily",
    "linkup": "Linkup",
    "kagi": "Kagi",
    "github": "GitHub",
    "tigris": "Tigris",
    "s3": "S3",
    "pushover": "Pushover",
    "typesafe": "TypeSafeAI Jev",
}


def display_name(provider: str) -> str:
    key = canonical(provider)
    return DISPLAY_NAMES.get(key, key.replace("-", " ").title() or "Connector")


def prefer_model(connectors: list[Connector], provider: str, connection_id: str = "") -> Connector | None:
    """Choose a model connector. `auto` walks Ollama, OpenRouter, Anthropic, OpenAI, Gemini."""
    raw = (provider or "auto").strip()
    provider = raw.lower()
    if provider.startswith("connector:"):
        parts = raw.split(":")
        name = parts[1].lower() if len(parts) > 1 else "ollama"
        cid = parts[2] if len(parts) > 2 else connection_id
        chosen = pick(connectors, name, cid)
        return chosen if chosen and chosen.style != "other" else None
    if provider in {"auto", "sprites"}:
        if connection_id:
            for name in MODEL_PREFERENCE:
                chosen = pick(connectors, name, connection_id)
                if chosen and chosen.style != "other":
                    return chosen
        for name in MODEL_PREFERENCE:
            chosen = pick(connectors, name, "")
            if chosen and chosen.style != "other":
                return chosen
        return None
    chosen = pick(connectors, provider, connection_id)
    if chosen and chosen.style != "other":
        return chosen
    return None


def connector_chat_url(base: str, provider: str) -> str:
    root = base.rstrip("/")
    if canonical(provider) == "openrouter":
        return root + "/api/v1/chat/completions"
    if root.endswith("/chat/completions"):
        return root
    if root.endswith("/v1"):
        return root + "/chat/completions"
    return root + "/v1/chat/completions"


def connector_headers(connector: bool, api_key: str = "", kind: str = "bearer") -> dict[str, str]:
    """Connector calls must not carry a provider key. The gateway attaches it."""
    headers = {"Content-Type": "application/json"}
    if connector:
        if kind == "anthropic":
            headers["anthropic-version"] = "2023-06-01"
        return headers
    if kind == "bearer":
        headers["Authorization"] = f"Bearer {api_key}"
    elif kind == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
    elif kind == "gemini":
        headers["x-goog-api-key"] = api_key
    return headers


def assert_route(provider: str, method: str, path: str) -> None:
    rules = ROUTES.get(canonical(provider))
    if not rules:
        raise GatewayError(f"CYBOT has no allowlisted route for {provider}.")
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    for allowed_method, pattern in rules:
        if method.upper() == allowed_method and pattern.match(path):
            return
    raise GatewayError(f"{method} {path} is not an allowlisted {provider} path.")


class Gateway:
    def __init__(self, connectors: list[Connector], transport=None):
        self.connectors = connectors
        self.transport = transport or _http_transport

    def find(self, *providers: str) -> Connector | None:
        for provider in providers:
            chosen = pick(self.connectors, provider)
            if chosen:
                return chosen
        return None

    def roles(self) -> set[str]:
        found: set[str] = set()
        if prefer_model(self.connectors, "auto"):
            found.add("model")
        if self.find(*SEARCH_PROVIDERS):
            found.add("search")
        if self.find("github"):
            found.add("github")
        if self.find("firecrawl"):
            found.add("crawl")
        if self.find(*STORAGE_PROVIDERS):
            found.add("storage")
        if self.find(*ALERT_PROVIDERS):
            found.add("alert")
        return found

    async def call(
        self,
        provider: str,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        content: bytes | None = None,
        content_type: str | None = None,
        target: Connector | None = None,
    ):
        connector = target or self.find(provider)
        if connector is None:
            raise GatewayError(f"No granted {provider} connector.")
        assert_route(connector.provider, method, path)
        url = connector.gateway_base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if connector.provider == "github":
            headers["Accept"] = "application/vnd.github+json"
            headers["User-Agent"] = "CYBOT/0.1"
        if connector.provider == "notion":
            headers["Notion-Version"] = "2026-03-11"
            headers["Content-Type"] = "application/json"
        if connector.provider == "pinecone":
            headers["X-Pinecone-Api-Version"] = "2026-07"
            headers["Content-Type"] = "application/json"
        return await self.transport(
            method.upper(),
            url,
            json=json,
            params=params,
            content=content,
            headers=headers,
        )


async def _http_transport(method, url, *, json=None, params=None, content=None, headers=None):
    # No Authorization header is added here. Identity comes from the Sprite.
    async with httpx.AsyncClient(timeout=45, follow_redirects=False) as client:
        response = await client.request(
            method,
            url,
            json=json,
            params=params,
            content=content,
            headers=headers or {},
        )
        response.raise_for_status()
        if not response.content:
            return {}
        content_type = response.headers.get("content-type", "")
        if "json" in content_type or response.content[:1] in (b"{", b"["):
            return response.json()
        return {"text": response.text[:2000]}


def describe(connectors: list[Connector]) -> dict:
    preferred = prefer_model(connectors, "auto")
    gateway = Gateway(connectors)
    return {
        "preferred_model": None
        if preferred is None
        else {
            "provider": preferred.provider,
            "id": preferred.connection_id,
            "style": preferred.style,
            "gateway_base": preferred.gateway_base,
        },
        "roles": sorted(gateway.roles()),
        "connectors": [
            {
                "provider": item.provider,
                "name": display_name(item.provider),
                "raw_provider": item.raw_provider,
                "id": item.connection_id,
                "style": item.style,
                "gateway_base": item.gateway_base,
            }
            for item in connectors
        ],
    }


def probe_request(connector: Connector) -> tuple[str, str, dict | None, dict | None, bytes | None, str | None]:
    """A small gateway call that does not scan a target or change program data."""
    provider = connector.provider
    if provider == "notion":
        return "GET", "/v1/users/me", None, None, None, None
    if provider == "pinecone":
        return "GET", "/indexes", None, None, None, None
    if provider == "typesafe":
        return "GET", "/v1/models", None, None, None, None
    if provider == "kagi":
        return "GET", "/api/v0/search", None, {"q": "example"}, None, None
    if provider == "github":
        return "GET", "/search/code", None, {"q": "example"}, None, None
    if provider == "gemini":
        return (
            "POST",
            "/v1beta/models/gemini-flash-lite-latest:generateContent",
            {
                "contents": [{"role": "user", "parts": [{"text": "Reply with ok."}]}],
                "generationConfig": {"maxOutputTokens": 8, "temperature": 0},
            },
            None,
            None,
            None,
        )
    if provider == "anthropic":
        return (
            "POST",
            "/v1/messages",
            {"model": "claude-3-5-haiku-latest", "max_tokens": 1, "messages": [{"role": "user", "content": "ok"}]},
            None,
            None,
            None,
        )
    if provider == "openrouter":
        return (
            "POST",
            "/api/v1/chat/completions",
            {"model": "openrouter/auto", "max_tokens": 1, "messages": [{"role": "user", "content": "ok"}]},
            None,
            None,
            None,
        )
    if provider in {"ollama", "openai"}:
        model = "llama3.2" if provider == "ollama" else "gpt-4o-mini"
        return (
            "POST",
            "/v1/chat/completions",
            {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "ok"}]},
            None,
            None,
            None,
        )
    if provider == "firecrawl":
        return "POST", "/v2/scrape", {"url": "https://example.com", "formats": ["markdown"]}, None, None, None
    if provider == "exa":
        return "POST", "/search", {"query": "example.com", "type": "neural", "numResults": 1}, None, None, None
    if provider == "tavily":
        return "POST", "/search", {"query": "example.com", "max_results": 1}, None, None, None
    if provider == "linkup":
        return "POST", "/v1/search", {"q": "example.com"}, None, None, None
    if provider == "pushover":
        return "POST", "/1/messages.json", {"message": "CYBOT connector test", "title": "CYBOT"}, None, None, None
    if provider in {"tigris", "s3"}:
        return "PUT", "/cybot/reports/c0bb07e5.md", None, None, b"CYBOT connector test\n", "text/markdown; charset=utf-8"
    raise GatewayError(f"CYBOT has no harmless probe for {provider}.")


async def run_probe(gateway: Gateway, connector: Connector):
    method, path, payload, params, content, content_type = probe_request(connector)
    return await gateway.call(
        connector.provider,
        method,
        path,
        json=payload,
        params=params,
        content=content,
        content_type=content_type,
        target=connector,
    )


def classify_probe_error(exc: Exception) -> tuple[str, str]:
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status in {401, 403}:
        return (
            "not_granted",
            "The gateway denied this Sprite. Add an access policy for the connector in Fly.io.",
        )
    if isinstance(exc, GatewayError) and "granted" in str(exc).lower():
        return "not_granted", "This connector is not granted to this machine."
    return "error", f"The check failed ({type(exc).__name__})."


async def publish_report(gateway: Gateway | None, store, run: dict, markdown: str) -> None:
    """Store the report and send one short alert. Failures are logged, not fatal."""
    if gateway is None:
        return
    run_id = str(run.get("id") or "")
    if not re.fullmatch(r"[a-f0-9]{8,32}", run_id):
        return
    settings = store.settings()
    storage = gateway.find(*STORAGE_PROVIDERS)
    if storage:
        try:
            await gateway.call(
                storage.provider,
                "PUT",
                f"/cybot/reports/{run_id}.md",
                content=markdown.encode("utf-8"),
                content_type="text/markdown; charset=utf-8",
            )
            store.event(run_id, "ok", f"Report stored through the {storage.provider} connector.")
        except Exception as exc:
            store.event(run_id, "warn", f"{storage.provider} store failed ({type(exc).__name__}). The local report is kept.")
    await _alert(gateway, store, run, settings)
    if settings.get("github_export") == "1":
        await _export_github(gateway, store, run_id, markdown, settings)


async def _alert(gateway: Gateway, store, run: dict, settings: dict) -> None:
    summary = (
        f"CYBOT {run.get('status', 'finished')} {run.get('target', '')} "
        f"({run.get('intensity', '')}). Open the dashboard for the report."
    )[:900]
    if gateway.find("pushover") is None:
        return
    body = {"message": summary, "title": "CYBOT"}
    user = store.get_secret("pushover_user")
    if user:
        body["user"] = user
    try:
        await gateway.call("pushover", "POST", "/1/messages.json", json=body)
        store.event(run["id"], "ok", "Pushover alert sent. Telegram remains the chat channel.")
    except Exception as exc:
        store.event(run["id"], "warn", f"Pushover failed ({type(exc).__name__}).")


async def _export_github(gateway: Gateway, store, run_id: str, markdown: str, settings: dict) -> None:
    import base64

    repo = (settings.get("github_repo") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        store.event(run_id, "warn", "GitHub export skipped: set owner/repo.")
        return
    if gateway.find("github") is None:
        return
    owner, name = repo.split("/", 1)
    path = f"/repos/{owner}/{name}/contents/cybot-reports/{run_id}.md"
    try:
        await gateway.call(
            "github",
            "PUT",
            path,
            json={
                "message": f"CYBOT report {run_id}",
                "content": base64.b64encode(markdown.encode("utf-8")).decode("ascii"),
            },
        )
        store.event(run_id, "ok", f"Report exported to {repo} through the GitHub connector.")
    except Exception as exc:
        store.event(run_id, "warn", f"GitHub export failed ({type(exc).__name__}).")


