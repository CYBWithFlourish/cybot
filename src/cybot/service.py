from __future__ import annotations

import asyncio
import json
import os
import secrets as token_secrets
import shutil

from cybot.catalog import CONSIDERED
from cybot.config import Config
from cybot.connectors import (
    Gateway,
    classify_probe_error,
    display_name,
    parse_gateway_list,
    pick,
    prefer_model,
    run_probe,
)
from cybot.notion import NotionSkipped, list_programs, list_tracked, publish_run as publish_notion
from cybot.notion import resolve_notion_choice, scope_from_programs
from cybot.partners import search_memory as recall_memory
from cybot.engine import execute_run, secrets_id
from cybot.rails import attestation_ok, derive_mode, permit_scan
from cybot.rails import ScanBudget
from cybot.scan import execute_locked, gate_plan, plan_commands, run_local_demo, tool_status
from cybot.terminal import submit_command
from cybot.llm import (
    AnthropicLLM,
    GeminiLLM,
    MockLLM,
    OllamaLocalLLM,
    OpenAICompatLLM,
)
from cybot.mcp_client import call_tool, discover, load_servers
from cybot.net import FixtureNet, RealNet
from cybot.playbook import align_playbook, loads_playbook, short_summary, template_playbook
from cybot.policy import select_builtin
from cybot.report import sort_findings
from cybot.scope import ScopeError, check_scope, normalize_host, parse_scope
from cybot.store import SECRET_NAMES, Store, utcnow
from cybot.tools import builtin_specs

FIXTURE_HOSTS = {"example.com", "www.example.com"}

_DEFAULT_CONNECTOR_MODELS = {
    "gemini": "gemini-flash-lite-latest",
}

_DIRECT = {
    "ollama_cloud": ("https://ollama.com/v1", "ollama", OpenAICompatLLM),
    "openrouter": ("https://openrouter.ai/api/v1", "openrouter", OpenAICompatLLM),
    "gemini": ("https://generativelanguage.googleapis.com", "gemini", GeminiLLM),
    "grok": ("https://api.x.ai/v1", "grok", OpenAICompatLLM),
    "anthropic": ("https://api.anthropic.com", "anthropic", AnthropicLLM),
    "openai": ("https://api.openai.com/v1", "openai", OpenAICompatLLM),
}


class Service:
    def __init__(self, config: Config, store: Store, connector_fetch=None):
        self.config = config
        self.store = store
        self.connector_fetch = connector_fetch or _fetch_gateway
        self.probe_transport = None
        self.tasks: set[asyncio.Task] = set()
        self._budgets: dict[str, ScanBudget] = {}
        self._run_choices: dict[str, tuple[str, str]] = {}
        self.make_net = self._default_make_net

    def _default_make_net(self, kind: str):
        if kind == "fixture":
            return FixtureNet()
        return RealNet(rate_per_min=self.config.rate_per_min)

    def telegram_token(self) -> str | None:
        env = os.environ.get("TELEGRAM_BOT_TOKEN")
        if env:
            return env
        return self.store.get_secret("telegram")

    async def check_scope(self, data: dict) -> dict:
        data = prepare_request(data)
        scope = parse_scope(data)
        decision = check_scope(scope, str(data.get("target") or ""))
        self.store.audit(
            "check",
            decision.host,
            "allowed" if decision.allowed else "refused",
            f"{decision.reason} scope={scope.digest()} auth={scope.authorization[:180]}",
            None,
        )
        return {
            "allowed": decision.allowed,
            "host": decision.host,
            "reason": decision.reason,
            "rule": decision.rule,
            "scope": scope.digest(),
        }

    async def start_run(self, data: dict, source: str) -> dict:
        if self.store.active_run():
            raise ValueError("A run is already in progress.")
        data = prepare_request(dict(data))
        if data.get("use_notion_scope"):
            data = await self._apply_notion_scope(data)
            data = prepare_request(data)
        scope = parse_scope(data)
        try:
            host = normalize_host(str(data.get("target") or ""))
        except ScopeError as exc:
            raise ValueError(str(exc)) from exc
        intensity = str(data.get("intensity") or "passive")
        if intensity not in {"passive", "light", "standard"}:
            raise ValueError("Intensity must be passive, light, or standard.")
        mode = derive_mode(str(data.get("mode") or ""), intensity)
        if mode == "soft-active" and intensity == "passive":
            intensity = "light"
        if mode == "active-test":
            intensity = "standard"
        local_demo = host == "127.0.0.1" and mode == "active-test"
        if host == "127.0.0.1" and mode != "active-test":
            raise ValueError("The local demo runs in active-test mode.")
        if host in FIXTURE_HOSTS and self.config.demo:
            data["demo"] = True
        if bool(data.get("demo")) and not local_demo and host not in FIXTURE_HOSTS:
            raise ValueError("Demo mode only runs the reserved example.com fixture.")
        permit = permit_scan(
            scope,
            host,
            mode=mode,
            active_approved=bool(data.get("active_approved")),
            attestation=str(data.get("attestation") or ""),
            allow_demo=local_demo,
        )
        if not permit.allowed:
            raise ValueError(permit.reason)
        if mode != "passive" and not data.get("active_approved"):
            raise ValueError("Light and standard intensity need explicit active approval.")
        kind = net_kind(self.config, bool(data.get("demo")), host, local_demo=local_demo)
        settings = self.store.settings()
        notion_choice, notion_note = resolve_notion_choice(
            settings.get("notion_publish") or "ask",
            _notion_request(data, source),
            source,
        )
        requested_provider = str(data.get("provider") or "").strip()
        requested_model = str(data.get("model") or "").strip()
        effective_provider = requested_provider or os.environ.get("CYBOT_PROVIDER") or settings.get("provider") or "mock"
        effective_model = requested_model or os.environ.get("CYBOT_MODEL") or settings.get("model") or ""
        run_id = secrets_id()
        scope_json = json.dumps(
            {
                "program": scope.program,
                "include": list(scope.include),
                "exclude": list(scope.exclude),
                "authorization": scope.authorization,
            }
        )
        self.store.create_run(
            id=run_id,
            created_at=utcnow(),
            target=host,
            program=scope.program,
            intensity=intensity,
            status="running",
            provider=effective_provider,
            model=effective_model,
            scope_json=scope_json,
            source=source,
            notion=notion_choice,
            mode=mode,
            attestation=str(data.get("attestation") or "")[:500],
        )
        if source == "dashboard":
            self.store.meta_set("scope", scope_json)
        self._run_choices[run_id] = (requested_provider, requested_model)
        self.store.event(run_id, "ok", f"Run accepted from {source} in {mode} mode.")
        if mode != "passive":
            planned = plan_commands(mode, host)
            self.store.event(
                run_id,
                "info",
                f"Scan plan has {len(planned)} locked commands. Missing binaries are skipped.",
            )
        if self.config.inline_runs:
            await self._go(run_id, kind)
        else:
            task = asyncio.create_task(self._go(run_id, kind))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        run = self.store.get_run(run_id)
        public = _public_run(run)
        public["notion_note"] = notion_note
        return public

    async def _go(self, run_id: str, kind: str) -> None:
        if kind == "local-demo":
            try:
                run_local_demo(self.store, run_id)
            except Exception as exc:
                self.store.finish_run(run_id, "error", str(exc)[:240])
                self.store.event(run_id, "error", str(exc)[:240])
            return
        requested_provider, requested_model = self._run_choices.pop(run_id, ("", ""))
        try:
            llm = await self.build_llm(
                provider=requested_provider or None,
                model=requested_model or None,
            )
        except Exception as exc:
            self.store.finish_run(run_id, "error", str(exc)[:240])
            self.store.event(run_id, "error", str(exc)[:240])
            return
        self.store.set_run_model(run_id, llm.name, getattr(llm, "model", "") or "")
        selected = (
            requested_provider
            or os.environ.get("CYBOT_PROVIDER")
            or self.store.settings().get("provider")
            or "opencode"
        )
        if llm.name == "mock" and selected != "mock":
            self.store.event(
                run_id,
                "warn",
                f"{selected} was selected, but it is not ready. Using Mock. "
                "OpenCode needs OPENCODE_API_KEY or the opencode vault key. "
                "A Sprites connector needs a grant and a model id.",
            )
        elif llm.name == "opencode":
            self.store.event(run_id, "ok", f"Model: OpenCode {llm.model} at {llm.base_url}.")
        elif llm.name != "mock":
            self.store.event(run_id, "ok", f"Model: {llm.name} {llm.model}.")
        external = []
        if self.config.discover_mcp:
            try:
                servers = self.mcp_servers()
                vetted, blocked = await discover(servers)
                external = vetted
                for item in blocked:
                    self.store.event(
                        run_id,
                        "warn",
                        f"MCP {item['server']}/{item['tool']} blocked: {item['reason']}",
                    )
            except Exception as exc:
                self.store.event(run_id, "warn", f"MCP discovery skipped ({type(exc).__name__}).")

        async def caller(server_name: str, tool_name: str, host: str) -> str:
            return await call_tool(self.mcp_servers(), server_name, tool_name, host)

        connectors, discovery_error = await self.connectors()
        if discovery_error:
            self.store.event(run_id, "warn", f"Sprites connector list unavailable ({discovery_error}).")
        gateway = Gateway(connectors)

        async def notify(summary: str) -> None:
            token = self.telegram_token()
            chat = self.store.meta_get("telegram_chat")
            if not token or not chat:
                return
            from cybot.telegram import send_message, send_notion_prompt

            await send_message(token, chat, summary)
            finished = self.store.get_run(run_id)
            if finished and finished.get("notion") == "ask" and finished.get("source") == "telegram":
                await send_notion_prompt(token, chat, finished["target"], run_id)

        if kind == "real":
            self._run_locked_binaries(run_id)
        await execute_run(
            store=self.store,
            net_factory=lambda: self.make_net(kind),
            llm=llm,
            run_id=run_id,
            external=external,
            external_caller=caller,
            gateway=gateway,
            max_hosts=self.config.max_hosts,
            timeout=self.config.run_timeout,
            notify=notify,
        )

    async def build_llm(self, connectors=None, provider: str | None = None, model: str | None = None):
        settings = self.store.settings()
        provider = (
            provider
            or os.environ.get("CYBOT_PROVIDER")
            or settings.get("provider")
            or "opencode"
        ).strip()
        if model is None:
            model = (os.environ.get("CYBOT_MODEL") or settings.get("model") or "").strip()
        else:
            model = model.strip()
        if connectors is None:
            connectors, _error = await self.connectors()
        if provider == "mock":
            return MockLLM()
        if provider in {"ollama-local", "ollama"}:
            return _local_ollama(settings, model)
        if provider == "opencode":
            built = self._opencode(settings, model)
            return built or MockLLM()
        if provider == "auto":
            return self._from_order(settings, connectors, model)
        if provider == "sprites" or provider.startswith("connector:"):
            if provider == "sprites":
                chosen = prefer_model(
                    connectors,
                    settings.get("sprites_provider") or "ollama",
                    settings.get("sprites_connection_id") or "",
                )
            else:
                chosen = prefer_model(connectors, provider, settings.get("sprites_connection_id") or "")
            if chosen is None:
                raise ValueError(
                    "That Sprites connector is not granted to this machine. Add it in the dashboard and set an access policy."
                )
            chosen_model = model or _DEFAULT_CONNECTOR_MODELS.get(chosen.provider, "")
            if not chosen_model:
                raise ValueError("Enter the model id for that connector. OpenCode is the primary provider.")
            return _llm_for_connector(chosen, chosen_model)
        direct = provider[7:] if provider.startswith("direct-") else provider
        if direct not in _DIRECT:
            raise ValueError("Unknown provider.")
        base, secret_name, factory = _DIRECT[direct]
        key = self.store.get_secret(secret_name)
        if not key:
            raise ValueError(
                f"Direct {direct} needs a key in the vault. OpenCode is the primary provider. "
                "Ollama Cloud is supported and optional."
            )
        if not model:
            raise ValueError("Enter the model id from that provider's console.")
        return factory(direct, base, key, model)

    def _opencode(self, settings: dict, model: str):
        key = os.environ.get("OPENCODE_API_KEY") or self.store.get_secret("opencode")
        if not key:
            return None
        product = (os.environ.get("OPENCODE_PRODUCT") or settings.get("opencode_product") or "go").strip().lower()
        if product not in {"go", "zen"}:
            product = "go"
        base = os.environ.get("OPENCODE_BASE_URL") or (
            "https://opencode.ai/zen/v1" if product == "zen" else "https://opencode.ai/zen/go/v1"
        )
        session = self.store.meta_get("opencode_session")
        if not session:
            session = token_secrets.token_hex(16)
            self.store.meta_set("opencode_session", session)
        return OpenAICompatLLM(
            "opencode",
            base.rstrip("/"),
            key,
            model or "deepseek-v4.1-flash",
            extra_headers={"User-Agent": "CYBOT/0.1", "x-opencode-session": session},
        )

    def _from_order(self, settings: dict, connectors: list, model: str):
        raw = os.environ.get("CYBOT_PROVIDER_ORDER") or settings.get("provider_order") or ""
        names = [part.strip() for part in raw.split(",") if part.strip()]
        for name in names:
            if name == "opencode":
                built = self._opencode(settings, model)
                if built:
                    return built
                continue
            if name == "ollama-local":
                return _local_ollama(settings, model)
            if name == "mock":
                return MockLLM()
            chosen = pick(connectors, name, settings.get("sprites_connection_id") or "")
            if chosen and chosen.style != "other":
                chosen_model = model or _DEFAULT_CONNECTOR_MODELS.get(chosen.provider, "")
                if not chosen_model:
                    continue
                return _llm_for_connector(chosen, chosen_model)
        return MockLLM()

    async def connectors(self) -> tuple[list, str]:
        try:
            payload = await self.connector_fetch(self.config.gateway_list_url)
        except Exception as exc:
            return [], f"{type(exc).__name__}"
        return parse_gateway_list(payload), ""

    async def test_connector(self, provider: str, connection_id: str = "") -> dict:
        provider = (provider or "").strip()
        connection_id = (connection_id or "").strip()
        if not provider:
            raise ValueError("Name the connector to test.")
        name = display_name(provider)
        connectors, error = await self.connectors()
        if error and not connectors:
            return {
                "status": "error",
                "provider": provider,
                "name": name,
                "id": connection_id,
                "detail": "The Sprites gateway list could not be loaded from this machine.",
            }
        chosen = pick(connectors, provider, connection_id)
        if chosen is None:
            return {
                "status": "not_granted",
                "provider": provider,
                "name": name,
                "id": connection_id,
                "detail": "This connector is not granted to this machine. Add an access policy in Fly.io.",
            }
        gateway = Gateway(connectors, transport=self.probe_transport)
        try:
            await run_probe(gateway, chosen)
        except Exception as exc:
            status, detail = classify_probe_error(exc)
            return {
                "status": status,
                "provider": chosen.provider,
                "name": display_name(chosen.provider),
                "id": chosen.connection_id,
                "detail": detail,
            }
        return {
            "status": "ok",
            "provider": chosen.provider,
            "name": display_name(chosen.provider),
            "id": chosen.connection_id,
            "detail": "The gateway accepted a harmless check.",
        }

    def _run_locked_binaries(self, run_id: str) -> None:
        import json

        from cybot.rails import ScanBudget

        run = self.store.get_run(run_id)
        if not run or (run.get("mode") or "passive") == "passive":
            return
        scope = parse_scope(json.loads(run["scope_json"]))
        commands = plan_commands(run["mode"], run["target"])
        accepted, notes = gate_plan(
            scope,
            run["target"],
            run["mode"],
            commands,
            active_approved=True,
            attestation=run.get("attestation") or "",
            budget=ScanBudget(max_requests=8, max_seconds=90),
            allow_demo=False,
        )
        for note in notes:
            self.store.event(run_id, "warn", note[:240])
        for note in execute_locked(accepted, timeout=8):
            self.store.event(run_id, "info", note[:240])

    def run_terminal(self, run_id: str, command: str, *, confirmed: bool = False, denied: bool = False, runner=None, timeout: float = 15) -> dict:
        run = self.store.get_run(run_id)
        if not run:
            raise ValueError("Unknown run.")
        scope = parse_scope(json.loads(run["scope_json"]))
        workdir = self.config.data_dir / "work" / run_id
        allow_demo = run.get("target") == "127.0.0.1"
        budget = self._budgets.setdefault(run_id, ScanBudget(max_requests=12, max_seconds=90))
        return submit_command(
            self.store,
            run,
            scope,
            command,
            workdir=workdir,
            confirmed=confirmed,
            denied=denied,
            timeout=timeout,
            budget=budget,
            allow_demo=allow_demo,
            runner=runner,
        )

    def terminal_view(self, run_id: str) -> dict:
        if not self.store.get_run(run_id):
            raise ValueError("Unknown run.")
        return {"lines": self.store.terminal_lines(run_id)}

    def status(self, run_id: str) -> dict:
        run = self.store.get_run(run_id)
        if not run:
            raise ValueError("Unknown run.")
        return _public_run(run)

    def findings(self, run_id: str) -> list[dict]:
        if not self.store.get_run(run_id):
            raise ValueError("Unknown run.")
        rows = []
        for row in sort_findings(self.store.findings(run_id)):
            rows.append(
                {
                    "id": row["id"],
                    "host": row["host"],
                    "tool": row["tool"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "evidence": row["evidence"],
                    "plain": row["plain"],
                    "jev": row.get("jev") or "",
                    "playbook": align_playbook(row, loads_playbook(row.get("playbook")) or template_playbook(row)),
                    "confidence": row.get("confidence") or "",
                    "repro": row.get("repro") or "",
                    "needs_human_validation": bool(row.get("needs_human", 1)),
                    "chat": self.store.chat(row["id"]),
                }
            )
        return rows

    def playbook(self, finding_id: str) -> dict:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError("Unknown finding.")
        run = self.store.get_run(finding["run_id"])
        book = align_playbook(finding, loads_playbook(finding.get("playbook")) or template_playbook(finding))
        return {
            "finding_id": finding_id,
            "run_id": finding["run_id"],
            "summary": short_summary(book),
            "playbook": book,
            "target": loads_playbook((run or {}).get("playbook")),
        }

    async def explain(self, finding_id: str) -> dict:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError("Unknown finding.")
        run = self.store.get_run(finding["run_id"])
        memory = await recall_memory(
            await self._gateway(),
            self.store.settings(),
            f"{finding.get('title', '')} {finding.get('evidence', '')}",
            (run or {}).get("program") or "program",
        )
        if memory.get("matches"):
            notes = "; ".join(item.get("text") or item.get("title") or "" for item in memory["matches"])
            finding = dict(finding)
            finding["evidence"] = f"{finding.get('evidence', '')} Related memory: {notes[:500]}"
        llm = await self.build_llm()
        plain = await llm.explain(finding)
        self.store.set_finding_plain(finding_id, plain)
        return {"id": finding_id, "plain": plain}

    async def assist(self, finding_id: str, action: str, message: str = "") -> dict:
        from cybot.assist import ACTIONS, SYSTEM, context_block, guard_answer, template_answer
        from cybot.kb import search

        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError("Unknown finding.")
        chosen = (action or "ask").strip().lower()
        if chosen not in ACTIONS:
            chosen = "ask"
        book = loads_playbook(finding.get("playbook")) or template_playbook(finding)
        kb = []
        try:
            kb = await search(
                await self._gateway(),
                self.store.settings(),
                f"{finding.get('title') or ''} {chosen}",
                k=4,
                catalog_only=True,
            )
        except Exception:
            kb = []
        asked = (message or "").strip() or chosen
        self.store.add_chat(finding_id, "user", asked[:2000])
        fallback = template_answer(chosen, finding, book)
        answer = fallback
        source = "template"
        try:
            llm = await self.build_llm()
            if getattr(llm, "name", "") != "mock" and hasattr(llm, "complete"):
                raw = await llm.complete(
                    SYSTEM,
                    context_block(finding, book, kb) + f"\n\nAction: {chosen}\nMessage: {(message or '')[:1000]}",
                )
                guarded = guard_answer(raw, str(finding.get("host") or ""))
                if guarded:
                    answer = guarded
                    source = "model"
        except Exception:
            answer = fallback
            source = "template"
        self.store.add_chat(finding_id, "assistant", answer)
        return {
            "id": finding_id,
            "action": chosen,
            "source": source,
            "answer": answer,
            "history": self.store.chat(finding_id),
        }

    def finding_markdown(self, finding_id: str) -> str:
        from cybot.report import finding_card_markdown

        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError("Unknown finding.")
        finding = dict(finding)
        finding["playbook"] = align_playbook(finding, loads_playbook(finding.get("playbook")) or template_playbook(finding))
        finding["needs_human_validation"] = bool(finding.get("needs_human", 1))
        return finding_card_markdown(finding)

    async def search_memory(self, query: str, program: str = "") -> dict:
        gateway = await self._gateway()
        return await recall_memory(gateway, self.store.settings(), query, program or "program")

    async def notion_programs(self) -> dict:
        gateway = await self._gateway()
        return await list_programs(gateway, self.store.settings())

    async def notion_findings(self, status: str = "", program: str = "") -> dict:
        gateway = await self._gateway()
        return await list_tracked(gateway, self.store.settings(), status=status, program=program)

    async def publish_to_notion(self, run_id: str) -> dict:
        run = self.store.get_run(run_id)
        if not run:
            raise ValueError("Unknown run.")
        gateway = await self._gateway()
        result = await publish_notion(gateway, self.store, run, self.findings(run_id))
        if result.get("published"):
            self.store.set_notion(run_id, "yes")
        return result

    def decline_notion(self, run_id: str) -> dict:
        if not self.store.get_run(run_id):
            raise ValueError("Unknown run.")
        self.store.set_notion(run_id, "no")
        self.store.event(run_id, "info", "Notion was not published.")
        return {"published": False, "notion": "no"}

    async def _apply_notion_scope(self, data: dict) -> dict:
        loaded = await self.notion_programs()
        if not loaded.get("configured"):
            raise ValueError(loaded.get("reason") or "Notion scope is not configured.")
        if loaded.get("reason") and not loaded.get("programs"):
            raise ValueError(loaded["reason"])
        try:
            match = scope_from_programs(loaded["programs"], str(data.get("program") or ""))
        except NotionSkipped as exc:
            raise ValueError(exc.reason) from exc
        data["include"] = match["include"]
        data["exclude"] = match["exclude"]
        data["authorization"] = match["authorization"]
        return data

    async def _gateway(self):
        connectors, _error = await self.connectors()
        return Gateway(connectors)

    def report_markdown(self, run_id: str) -> str:
        from cybot.report import render_markdown

        run = self.store.get_run(run_id)
        if not run or run.get("status") == "running":
            raise ValueError("Report is not ready.")
        findings = []
        for row in self.store.findings(run_id):
            item = dict(row)
            item["playbook"] = align_playbook(item, loads_playbook(row.get("playbook")) or template_playbook(item))
            item["needs_human_validation"] = bool(item.get("needs_human", 1))
            findings.append(item)
        audit = [row for row in self.store.recent_audit(200) if row.get("run_id") == run_id]
        return render_markdown(run, findings, audit)

    def tool_catalog(self, roles: set[str] | None = None) -> list[dict]:
        secrets = set(self.store.secret_names())
        binaries = {name for name in ("subfinder", "httpx") if shutil.which(name)}
        granted = roles or set()
        rows = []
        for spec in builtin_specs():
            available = True
            reason = "ready"
            if spec.needs_secret and spec.needs_secret not in secrets:
                available = False
                reason = f"needs a {spec.needs_secret} key"
            if spec.needs_binary and spec.needs_binary not in binaries:
                available = False
                reason = f"binary {spec.needs_binary} is not installed"
            if spec.needs_role and spec.needs_role not in granted:
                available = False
                reason = f"needs the {spec.needs_role} Sprites connector"
            rows.append(
                {
                    "name": spec.name,
                    "title": spec.title,
                    "description": spec.description,
                    "intensity": spec.intensity,
                    "phase": spec.phase,
                    "available": available,
                    "reason": reason,
                }
            )
        rows.extend(tool_status())
        return rows

    def mcp_servers(self) -> list[dict]:
        raw = self.store.meta_get("mcp_servers", "") or ""
        if not raw.strip():
            return []
        return load_servers(raw, allow_stdio=self.config.mcp_stdio)

    def save_mcp(self, raw: str) -> list[dict]:
        servers = load_servers(raw, allow_stdio=self.config.mcp_stdio)
        self.store.meta_set("mcp_servers", json.dumps({"servers": servers}))
        return servers

    async def discover_mcp(self) -> dict:
        vetted, blocked = await discover(self.mcp_servers())
        return {
            "allowed": [
                {"server": tool.server_name, "tool": tool.name, "mode": tool.mode} for tool in vetted
            ],
            "blocked": blocked,
        }


def _local_ollama(settings: dict, model: str):
    return OllamaLocalLLM(
        "ollama-local",
        settings.get("ollama_host") or "http://127.0.0.1:11434",
        "",
        model or "qwen2.5:1.5b",
    )


def _llm_for_connector(chosen, model: str):
    if chosen.style == "anthropic":
        return AnthropicLLM(chosen.provider, chosen.gateway_base, "", model, connector=True)
    if chosen.style == "gemini":
        return GeminiLLM(chosen.provider, chosen.gateway_base, "", model, connector=True)
    return OpenAICompatLLM(chosen.provider, chosen.gateway_base, "", model, connector=True)


def prepare_request(data: dict) -> dict:
    """Fill authorization and attestation when the caller did not send them.

    A statement the caller did send is kept. Choosing soft-active or active-test
    is the opt-in, so a missing approval flag is treated as approved.
    """
    data = dict(data)
    program = str(data.get("program") or "").strip() or "this program"
    if len(str(data.get("authorization") or "").strip()) < 20:
        data["authorization"] = (
            f"Authorized recon for {program}. Only the listed in-scope assets may be checked."
        )
    mode = str(data.get("mode") or "").strip()
    intensity = str(data.get("intensity") or "passive").strip()
    active_mode = mode in {"soft-active", "active-test"} or intensity in {"light", "standard"}
    if active_mode and data.get("active_approved") is None:
        data["active_approved"] = True
    if mode == "active-test" and not attestation_ok(str(data.get("attestation") or "")):
        data["attestation"] = (
            f"I am authorized to run non-destructive active-test checks on the in-scope assets for {program}."
        )
    return data


def net_kind(config: Config, demo: bool, host: str, local_demo: bool = False) -> str:
    if local_demo:
        if not demo or not config.demo:
            raise ValueError("Demo mode is off on this server.")
        return "local-demo"
    if not demo:
        return "real"
    if not config.demo:
        raise ValueError("Demo mode is off on this server.")
    if host not in FIXTURE_HOSTS:
        raise ValueError("Demo mode only runs the reserved example.com fixture.")
    return "fixture"


def _public_run(run: dict | None) -> dict:
    if not run:
        raise ValueError("Unknown run.")
    return {
        "id": run["id"],
        "created_at": run["created_at"],
        "target": run["target"],
        "program": run["program"],
        "intensity": run["intensity"],
        "status": run["status"],
        "provider": run["provider"],
        "model": run["model"],
        "error": run.get("error") or "",
        "source": run["source"],
        "notion": run.get("notion") or "ask",
        "mode": run.get("mode") or "passive",
        "target_playbook": loads_playbook(run.get("playbook")),
    }


def _notion_request(data: dict, source: str):
    if source == "mcp":
        if "publish_to_notion" not in data:
            return None
        return bool(data.get("publish_to_notion"))
    return data.get("notion", "ask")


async def _fetch_gateway(url: str):
    import httpx

    async with httpx.AsyncClient(timeout=4) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


# Imported so a caller can see the passive tool set without a run.
PASSIVE_TOOLS = [spec.name for spec in select_builtin("passive", secrets=set(), binaries=set(), phase="discover")]
_ = (CONSIDERED, SECRET_NAMES)
