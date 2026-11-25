from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from cybot import __version__
from cybot.auth import hash_password, issue_session, session_valid, verify_password
from cybot.catalog import CONSIDERED
from cybot.connectors import Gateway, describe
from cybot.config import Config
from cybot.mcp_server import MCPServer
from cybot.report import render_pdf
from cybot.service import Service
from cybot.store import SECRET_NAMES, Store, load_fernet
from cybot.telegram import poll_forever

STATIC = Path(__file__).resolve().parent / "web" / "static"
COOKIE = "cybot_session"


class PasswordIn(BaseModel):
    password: str = Field(min_length=10, max_length=200)


class SettingsIn(BaseModel):
    provider: str | None = None
    model: str | None = None
    sprites_provider: str | None = None
    sprites_connection_id: str | None = None
    ollama_host: str | None = None
    opencode_product: str | None = None
    provider_order: str | None = None
    github_org: str | None = None
    github_repo: str | None = None
    github_export: str | None = None
    notion_reports_database: str | None = None
    notion_tracker_database: str | None = None
    notion_programs_database: str | None = None
    notion_publish: str | None = None
    pinecone_index: str | None = None
    pinecone_embed_model: str | None = None
    jev_model: str | None = None


class SecretIn(BaseModel):
    name: str
    value: str = ""


class ScopeIn(BaseModel):
    program: str
    include: list[str]
    exclude: list[str] = []
    authorization: str = ""
    target: str


class RunIn(ScopeIn):
    intensity: str = "passive"
    active_approved: bool | None = None
    demo: bool = False
    use_notion_scope: bool = False
    notion: str = "ask"
    provider: str = ""
    model: str = ""
    mode: str = ""
    attestation: str = ""


class AssistIn(BaseModel):
    action: str = "ask"
    message: str = ""


class TerminalIn(BaseModel):
    command: str = ""
    confirm: bool = False
    deny: bool = False


class ConnectorTestIn(BaseModel):
    provider: str
    id: str = ""


class MCPIn(BaseModel):
    servers: list[dict]


def create_app(config: Config | None = None, connector_fetch=None) -> FastAPI:
    config = config or Config.from_env()
    fernet = load_fernet(config.data_dir, config.master_key)
    store = Store(config.data_dir / "cybot.db", fernet)
    store.fail_stuck_runs()
    service = Service(config, store, connector_fetch=connector_fetch)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.telegram_task = None
        if config.telegram:
            app.state.telegram_task = asyncio.create_task(poll_forever(service))
        yield
        task = app.state.telegram_task
        if task is not None:
            task.cancel()
        for pending in list(service.tasks):
            pending.cancel()
        store.close()

    app = FastAPI(title="CYBOT", version=__version__, lifespan=lifespan)
    app.state.config = config
    app.state.store = store
    app.state.service = service
    app.state.session_secret = _session_secret(store)
    app.state.login_hits: dict[str, list[float]] = {}
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if (
            request.method in {"POST", "PUT", "DELETE", "PATCH"}
            and request.url.path.startswith("/api/")
            and request.url.path != "/api/mcp"
        ):
            if request.headers.get("x-cybot") != "1":
                return JSONResponse({"detail": "Missing X-CYBOT header."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    def authed(request: Request) -> None:
        if not session_valid(app.state.session_secret, request.cookies.get(COOKIE)):
            raise HTTPException(status_code=401, detail="Sign in.")

    def set_cookie(response: Response, request: Request) -> None:
        secure = config.cookie_secure
        if secure is None:
            secure = request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(
            COOKIE,
            issue_session(app.state.session_secret),
            httponly=True,
            samesite="strict",
            secure=bool(secure),
            max_age=12 * 3600,
            path="/",
        )

    @app.get("/api/health")
    def health():
        return {"ok": True, "demo": config.demo, "version": __version__}

    @app.get("/api/me")
    def me(request: Request):
        needs_setup = store.password_hash() is None
        if needs_setup:
            return {"needs_setup": True, "authed": False, "demo": config.demo}
        if not session_valid(app.state.session_secret, request.cookies.get(COOKIE)):
            return JSONResponse(
                {"needs_setup": False, "authed": False, "demo": config.demo},
                status_code=401,
            )
        return {"needs_setup": False, "authed": True, "demo": config.demo}

    @app.post("/api/setup")
    def setup(body: PasswordIn, request: Request):
        if store.password_hash():
            raise HTTPException(status_code=409, detail="Password is already set.")
        store.set_password(hash_password(body.password))
        response = JSONResponse({"ok": True})
        set_cookie(response, request)
        return response

    @app.post("/api/login")
    def login(body: PasswordIn, request: Request):
        _limit_login(app, request)
        stored = store.password_hash()
        if not stored or not verify_password(body.password, stored):
            raise HTTPException(status_code=401, detail="Wrong password.")
        response = JSONResponse({"ok": True})
        set_cookie(response, request)
        return response

    @app.post("/api/logout")
    def logout():
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.get("/api/settings")
    def get_settings(request: Request):
        authed(request)
        return {"settings": store.settings(), "secrets": store.secret_names()}

    @app.put("/api/settings")
    def put_settings(body: SettingsIn, request: Request):
        authed(request)
        if body.provider and not _known_provider(body.provider):
            raise HTTPException(status_code=400, detail="Unknown provider.")
        if body.ollama_host and not body.ollama_host.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Ollama host must be an http URL.")
        if body.opencode_product and body.opencode_product not in {"go", "zen"}:
            raise HTTPException(status_code=400, detail="OpenCode product must be go or zen.")
        if body.notion_publish and body.notion_publish not in {"ask", "always", "never"}:
            raise HTTPException(status_code=400, detail="Notion publish must be ask, always, or never.")
        from cybot.notion import normalize_id

        for field_name in (
            "notion_reports_database",
            "notion_tracker_database",
            "notion_programs_database",
        ):
            value = getattr(body, field_name)
            if value:
                try:
                    normalize_id(value)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"settings": store.save_settings(body.model_dump())}

    @app.post("/api/secrets")
    def put_secret(body: SecretIn, request: Request):
        authed(request)
        if body.name not in SECRET_NAMES:
            raise HTTPException(status_code=400, detail="Unknown secret name.")
        try:
            store.set_secret(body.name, body.value.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"secrets": store.secret_names()}

    @app.delete("/api/secrets/{name}")
    def delete_secret(name: str, request: Request):
        authed(request)
        store.delete_secret(name)
        return {"secrets": store.secret_names()}

    @app.get("/api/connectors")
    async def connectors(request: Request):
        authed(request)
        found, error = await service.connectors()
        summary = describe(found)
        return {
            "ok": not error,
            "error": error,
            **summary,
            "note": (
                "The Sprites gateway injects the provider key. CYBOT does not ask for that key when the connector is granted. "
                "A connector with no access policy denies every Sprite. "
                "OpenCode is the primary provider. Google Gemini is the active model connector on the live Sprite. "
                "Ollama Cloud is supported and optional."
            ),
        }

    @app.post("/api/connectors/test")
    async def test_connector(body: ConnectorTestIn, request: Request):
        authed(request)
        try:
            return await service.test_connector(body.provider, body.id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/scope/check")
    async def scope_check(body: ScopeIn, request: Request):
        authed(request)
        try:
            return await service.check_scope(body.model_dump())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/runs")
    async def create_run(body: RunIn, request: Request):
        authed(request)
        if body.provider and not _known_provider(body.provider):
            raise HTTPException(status_code=400, detail="Unknown provider.")
        try:
            return await service.start_run(body.model_dump(), source="dashboard")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/runs")
    def list_runs(request: Request):
        authed(request)
        return {"runs": store.list_runs()}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, request: Request):
        authed(request)
        try:
            return service.status(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/terminal")
    def get_terminal(run_id: str, request: Request):
        authed(request)
        try:
            return service.terminal_view(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/runs/{run_id}/terminal")
    def post_terminal(run_id: str, body: TerminalIn, request: Request):
        authed(request)
        try:
            return service.run_terminal(run_id, body.command, confirmed=body.confirm, denied=body.deny)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/events")
    async def events(run_id: str, request: Request):
        authed(request)
        if not store.get_run(run_id):
            raise HTTPException(status_code=404, detail="Unknown run.")

        async def stream():
            last = 0
            quiet = 0
            while quiet < 400:
                if await request.is_disconnected():
                    break
                rows = store.events_after(run_id, last)
                for row in rows:
                    last = row["id"]
                    yield f"data: {json.dumps(row)}\n\n"
                run = store.get_run(run_id)
                if not rows:
                    quiet += 1
                else:
                    quiet = 0
                if run and run["status"] != "running" and not rows:
                    yield "event: done\ndata: {}\n\n"
                    break
                await asyncio.sleep(0.25)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/api/runs/{run_id}/findings")
    def get_findings(run_id: str, request: Request):
        authed(request)
        try:
            return {"findings": service.findings(run_id)}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/findings/{finding_id}/assist")
    async def assist(finding_id: str, body: AssistIn, request: Request):
        authed(request)
        try:
            return await service.assist(finding_id, body.action, body.message)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/findings/{finding_id}/markdown")
    def finding_markdown(finding_id: str, request: Request):
        authed(request)
        try:
            text = service.finding_markdown(finding_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(content=text, media_type="text/markdown; charset=utf-8")

    @app.post("/api/findings/{finding_id}/explain")
    async def explain(finding_id: str, request: Request):
        authed(request)
        try:
            return await service.explain(finding_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/report.md")
    def report_md(run_id: str, request: Request):
        authed(request)
        try:
            text = service.report_markdown(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        run = store.get_run(run_id) or {}
        host = re.sub(r"[^A-Za-z0-9._-]+", "-", str(run.get("target") or "run")).strip("-")[:80] or "run"
        filename = f"cybot-{host}-{run_id}.md"
        return PlainTextResponse(
            text,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/runs/{run_id}/report.pdf")
    def report_pdf(run_id: str, request: Request):
        authed(request)
        try:
            text = service.report_markdown(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            render_pdf(text),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="cybot-{run_id}.pdf"'},
        )

    @app.get("/api/notion/programs")
    async def notion_programs(request: Request):
        authed(request)
        return await service.notion_programs()

    @app.get("/api/notion/findings")
    async def notion_findings(request: Request, status: str = "", program: str = ""):
        authed(request)
        return await service.notion_findings(status=status, program=program)

    @app.post("/api/runs/{run_id}/notion")
    async def publish_notion(run_id: str, request: Request):
        authed(request)
        try:
            return await service.publish_to_notion(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/runs/{run_id}/notion/decline")
    def decline_notion(run_id: str, request: Request):
        authed(request)
        try:
            return service.decline_notion(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/audit")
    def audit(request: Request):
        authed(request)
        return {"audit": store.recent_audit()}

    @app.get("/api/catalog")
    def catalog(request: Request):
        authed(request)
        return {"catalog": CONSIDERED}

    @app.get("/api/tools")
    async def tools(request: Request):
        authed(request)
        found, _error = await service.connectors()
        return {"tools": service.tool_catalog(Gateway(found).roles())}

    @app.get("/api/mcp/servers")
    def get_mcp(request: Request):
        authed(request)
        return {"servers": service.mcp_servers()}

    @app.put("/api/mcp/servers")
    def put_mcp(body: MCPIn, request: Request):
        authed(request)
        try:
            servers = service.save_mcp(json.dumps({"servers": body.servers}))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"servers": servers}

    @app.post("/api/mcp/discover")
    async def discover_mcp(request: Request):
        authed(request)
        return await service.discover_mcp()

    @app.post("/api/mcp")
    async def mcp(request: Request):
        token = request.headers.get("authorization", "")
        expected = config.mcp_token or ""
        presented = token[7:] if token.lower().startswith("bearer ") else ""
        if not expected or not presented or not hmac.compare_digest(presented, expected):
            raise HTTPException(status_code=401, detail="MCP bearer token required.")
        try:
            message = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="MCP body must be JSON.") from exc
        response = await MCPServer(service).handle(message)
        if response is None:
            return Response(status_code=202)
        return response

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    return app


def _known_provider(value: str) -> bool:
    if value in {
        "auto",
        "mock",
        "sprites",
        "ollama",
        "ollama-local",
        "opencode",
        "ollama_cloud",
        "gemini",
        "grok",
        "anthropic",
        "openai",
        "openrouter",
    }:
        return True
    if value.startswith("direct-"):
        return value[7:] in {"ollama_cloud", "openrouter", "gemini", "grok", "anthropic", "openai"}
    if value.startswith("connector:"):
        name = value.split(":")[1] if ":" in value else ""
        return bool(name)
    return False


def _session_secret(store: Store) -> bytes:
    current = store.meta_get("session_secret")
    if current:
        return bytes.fromhex(current)
    import os

    raw = os.urandom(32)
    store.meta_set("session_secret", raw.hex())
    return raw


def _limit_login(app: FastAPI, request: Request) -> None:
    host = request.client.host if request.client else "local"
    now = time.monotonic()
    hits = [stamp for stamp in app.state.login_hits.get(host, []) if now - stamp < 600]
    if len(hits) >= 8:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Wait a few minutes.")
    hits.append(now)
    app.state.login_hits[host] = hits
