from __future__ import annotations

import json
import secrets
from typing import Awaitable, Callable

from cybot.connectors import publish_report
from cybot.notion import publish_run as publish_notion
from cybot.partners import (
    active_tool_decision,
    apply_scope_gate,
    finding_decision,
    log_line,
    recall,
    remember,
    scope_decision,
    stricter_severity,
)
from cybot.partners import prior_match
from cybot.playbook import prepare_playbooks
from cybot.llm import LLM, failure_line, sanitize_explanation
from cybot.policy import external_specs, rank, select_builtin
from cybot.redact import redact
from cybot.report import render_markdown, sort_findings
from cybot.scope import Scope, ScopeBlocked, check_scope, parse_scope
from cybot.store import Store, utcnow
from cybot.tools import Observation, ToolContext, ToolOutcome, ToolSpec, run_builtin

Notify = Callable[[str], Awaitable[None]]


async def execute_run(
    *,
    store: Store,
    net_factory,
    llm: LLM,
    run_id: str,
    external: list | None = None,
    external_caller=None,
    gateway=None,
    max_hosts: int = 20,
    timeout: float = 120,
    notify: Notify | None = None,
) -> None:
    import asyncio

    try:
        async with asyncio.timeout(timeout):
            async with net_factory() as net:
                await _body(
                    store=store,
                    net=net,
                    llm=llm,
                    run_id=run_id,
                    external=external or [],
                    external_caller=external_caller,
                    gateway=gateway,
                    max_hosts=max_hosts,
                )
    except TimeoutError:
        store.finish_run(run_id, "error", "Run stopped: time budget exceeded.")
        store.event(run_id, "error", "Run stopped because it exceeded the time budget.")
    except Exception as exc:
        message = redact(f"{type(exc).__name__}: {exc}")[:240]
        store.finish_run(run_id, "error", message)
        store.event(run_id, "error", message)
    else:
        run = store.get_run(run_id)
        if notify and run and run["status"] == "complete":
            findings = store.findings(run_id)
            summary = (
                f"CYBOT finished {run['target']} ({run['intensity']}). "
                f"{len(findings)} notes. Open the dashboard for the report."
            )
            try:
                await notify(summary)
            except Exception:
                store.event(run_id, "warn", "Telegram notification failed.")


async def _body(
    *,
    store: Store,
    net,
    llm: LLM,
    run_id: str,
    external: list,
    external_caller,
    gateway,
    max_hosts: int,
) -> None:
    run = store.get_run(run_id)
    if not run:
        return
    scope = parse_scope(json_scope(run["scope_json"]))
    decision = check_scope(scope, run["target"])
    _audit(store, run_id, scope, decision, "start")
    if not decision.allowed:
        store.event(run_id, "refused", decision.reason)
        store.finish_run(run_id, "refused", decision.reason)
        return
    store.event(run_id, "ok", f"In scope ({decision.rule}). Authorization logged.")
    try:
        await net.assert_public(decision.host)
    except ScopeBlocked as exc:
        reason = str(exc)
        store.audit("resolve", decision.host, "refused", reason, run_id)
        store.event(run_id, "refused", reason)
        store.finish_run(run_id, "refused", reason)
        return

    secrets = set(store.secret_names())
    settings = store.settings()
    skip_active = False
    scope_jev = await scope_decision(gateway, settings, decision.host, scope.canonical())
    gate = apply_scope_gate(True, scope_jev)
    if scope_jev:
        store.event(run_id, "info", log_line("scope", scope_jev))
    if gate == "deny":
        reason = (
            f"Jev refused {decision.host} as outside the written scope "
            f"(p={scope_jev['probability']:.2f}). The deterministic check had allowed it."
        )
        store.audit("jev", decision.host, "refused", reason, run_id)
        store.event(run_id, "refused", reason)
        store.finish_run(run_id, "refused", reason)
        return
    if gate == "ask":
        skip_active = True
        store.event(
            run_id,
            "info",
            "Jev is unsure this host is in scope. Active checks are skipped. Passive notes can still be collected.",
        )
    roles = gateway.roles() if gateway is not None else set()
    binaries = set()
    for binary in ("subfinder", "httpx"):
        if await net.which(binary):
            binaries.add(binary)
    observations = []
    products: list[tuple[str, str]] = []
    hosts = [decision.host]
    cache: dict = {}

    discover = select_builtin(
        run["intensity"], secrets=secrets, binaries=binaries, phase="discover", roles=roles
    )
    discover += external_specs(external, run["intensity"], "discover")
    chosen = await _choose(
        llm, discover, f"target {decision.host}; phase discover; intensity {run['intensity']}", store=store, run_id=run_id
    )
    for spec in chosen:
        _gate(spec, run["intensity"])
        store.event(run_id, "tool", f"{spec.name}: start")
        outcome = await _invoke(
            store, net, spec, decision.host, cache, run["intensity"], run_id, external_caller, gateway, settings
        )
        if outcome is None:
            continue
        observations.extend(outcome.observations)
        products.extend(outcome.products)
        accepted, refused = _filter_hosts(store, scope, outcome.hosts, run_id, hosts, max_hosts)
        hosts.extend(accepted)
        if accepted or refused:
            store.event(
                run_id,
                "ok",
                f"{spec.name}: kept {len(accepted)} in-scope names, refused {refused}.",
            )
        for note in outcome.notes:
            store.event(run_id, "info", f"{spec.name}: {note}")

    if run["intensity"] != "passive" and not skip_active:
        probe = select_builtin(
            run["intensity"], secrets=secrets, binaries=binaries, phase="probe", roles=roles
        )
        probe += external_specs(external, run["intensity"], "probe")
        # Homepage probe first so fingerprint and hygiene can reuse it.
        probe.sort(key=lambda spec: 0 if spec.name == "http_probe" else 1)
        chosen = await _choose(
            llm,
            probe,
            f"target {decision.host}; hosts {', '.join(hosts[:8])}; phase probe; intensity {run['intensity']}",
            store=store,
            run_id=run_id,
        )
        for host in list(hosts):
            again = check_scope(scope, host)
            _audit(store, run_id, scope, again, "probe")
            if not again.allowed:
                continue
            try:
                await net.assert_public(host)
            except ScopeBlocked as exc:
                store.audit("resolve", host, "refused", str(exc), run_id)
                store.event(run_id, "refused", str(exc))
                continue
            host_cache = cache.setdefault(host, {})
            tool_gate = await active_tool_decision(
                gateway, settings, host, run["intensity"], [spec.name for spec in chosen]
            )
            if tool_gate:
                store.event(run_id, "info", log_line(f"active tools for {host}", tool_gate))
                if not tool_gate["yes"]:
                    if tool_gate["low_confidence"]:
                        store.event(run_id, "info", f"Jev is unsure about active checks on {host}. They were skipped.")
                    continue
            for spec in chosen:
                _gate(spec, run["intensity"])
                store.event(run_id, "tool", f"{spec.name}: {host}")
                outcome = await _invoke(
                    store,
                    net,
                    spec,
                    host,
                    host_cache,
                    run["intensity"],
                    run_id,
                    external_caller,
                    gateway,
                    settings,
                )
                if outcome is None:
                    continue
                observations.extend(outcome.observations)
                products.extend(outcome.products)
                for note in outcome.notes:
                    store.event(run_id, "info", f"{spec.name}: {note}")

    if products and rank(run["intensity"]) >= rank("light"):
        seen = set()
        for product, version in products:
            if (product, version) in seen:
                continue
            seen.add((product, version))
            if len(seen) > 2:
                break
            spec = next(item for item in select_builtin("light", secrets=secrets, binaries=set(), phase="enrich"))
            store.event(run_id, "tool", f"nvd_cves: {product} {version}")
            ctx = ToolContext(
                net=net,
                host=decision.host,
                secret=store.get_secret("nvd"),
                extra={"product": product, "version": version, "github_org": settings.get("github_org") or ""},
                gateway=gateway,
            )
            try:
                outcome = await run_builtin(spec, ctx)
            except ScopeBlocked as exc:
                store.event(run_id, "warn", str(exc))
                continue
            except Exception as exc:
                store.event(run_id, "warn", redact(f"nvd_cves failed: {type(exc).__name__}"))
                continue
            observations.extend(outcome.observations)
            if "search" in roles:
                search_spec = next(
                    item
                    for item in select_builtin(
                        "light", secrets=secrets, binaries=set(), phase="enrich", roles=roles
                    )
                    if item.name == "cve_search"
                )
                try:
                    searched = await run_builtin(search_spec, ctx)
                except Exception as exc:
                    store.event(run_id, "warn", redact(f"cve_search failed: {type(exc).__name__}"))
                else:
                    observations.extend(searched.observations)

    deduped = _dedupe(observations)
    # Look up memory before this run's vectors are upserted, and ignore the current run_id.
    for row in deduped[:8]:
        matches = await recall(gateway, settings, run["program"], f"{row.title} {row.evidence}", run_id=run_id)
        past = prior_match(matches, run_id)
        if past:
            row.title = "Seen before: " + row.title
            row.plain = (
                f"{row.plain} Seen before (score {past['score']:.2f}): {past['title']} "
                f"status {past['status'] or 'unknown'}."
            ).strip()
        row.memory = "; ".join(
            f"{item['title']} ({item['status'] or 'no status'})" for item in matches if item.get("title")
        )
    triaged = await _triage(llm, deduped, store=store, run_id=run_id)
    for row in triaged:
        decided = await finding_decision(
            gateway, settings, {"host": row.host, "title": row.title, "evidence": row.evidence, "plain": row.plain}, getattr(row, "memory", "")
        )
        jev = ""
        if decided:
            false_positive = decided["false_positive"]
            store.event(run_id, "info", log_line(f"finding {row.title[:80]}", false_positive))
            if false_positive["low_confidence"]:
                store.event(run_id, "info", f"Jev is unsure about this finding. Review the card. {decided['label']}")
            elif false_positive["yes"]:
                row.severity = "info"
            row.severity = stricter_severity(row.severity, decided["severity"])
            jev = decided["label"]
        store.add_finding(
            id=secrets_id(),
            run_id=run_id,
            host=row.host,
            tool=row.tool,
            severity=row.severity,
            title=row.title,
            evidence=row.evidence,
            plain=row.plain,
            jev=jev,
            created_at=utcnow(),
        )
    saved = sort_findings(store.findings(run_id))
    memory_rows = [
        {
            "id": row["id"],
            "text": f"{row['title']} {row['evidence']}",
            "metadata": {
                "title": row["title"],
                "status": "new",
                "text": row["plain"],
                "kind": "finding",
                "run_id": run_id,
            },
        }
        for row in saved[:20]
    ]
    for row in deduped:
        if row.tool in {"osint_search", "cve_search", "nvd_cves"}:
            memory_rows.append(
                {
                    "id": "note-" + secrets_id(),
                    "text": f"{row.title} {row.evidence}",
                    "metadata": {
                        "title": row.title,
                        "status": "",
                        "text": row.evidence,
                        "kind": "research",
                        "run_id": run_id,
                    },
                }
            )
    stored = await remember(gateway, settings, run["program"], memory_rows[:20])
    if stored:
        store.event(run_id, "info", f"Stored {stored} notes in Pinecone namespace {run['program']}.")
    saved = sort_findings(store.findings(run_id))
    finished = store.get_run(run_id)
    assert finished is not None
    finished = dict(finished)
    finished["status"] = "complete"
    try:
        def _narrative_failed(exc: BaseException) -> None:
            store.event(run_id, "warn", failure_line("narrative", llm.name, exc))

        notes, enriched = await prepare_playbooks(
            llm, gateway, finished, saved, fetch=None, on_fail=_narrative_failed
        )
        store.set_run_playbook(run_id, json.dumps(notes))
        for row in enriched:
            store.set_finding_playbook(row["id"], json.dumps(row.get("playbook") or {}))
        finished["playbook"] = json.dumps(notes)
        saved = sort_findings(store.findings(run_id))
    except Exception as exc:
        store.event(run_id, "warn", redact(f"Research playbook skipped ({type(exc).__name__}).")[:200])
    markdown = render_markdown(finished, saved, store.recent_audit(80))
    store.save_report(run_id, markdown)
    store.event(run_id, "ok", f"Report ready with {len(saved)} notes.")
    published = dict(finished)
    published["status"] = "complete"
    await publish_report(gateway, store, published, markdown)
    choice = (finished.get("notion") or "ask").strip().lower()
    if choice == "yes":
        await publish_notion(gateway, store, published, saved)
    elif choice == "ask":
        store.event(run_id, "info", "Notion was not published. Confirm with Yes to create the page.")
    else:
        store.event(run_id, "info", "Notion was not published.")
    store.finish_run(run_id, "complete", "")


def _gate(spec: ToolSpec, intensity: str) -> None:
    if rank(spec.intensity) > rank(intensity):
        raise ScopeBlocked(f"{spec.name} is above the approved intensity.")


async def _invoke(
    store, net, spec: ToolSpec, host: str, cache: dict, intensity: str, run_id: str, external_caller, gateway, settings
):
    if spec.external:
        return await _invoke_external(store, spec, host, run_id, external_caller)
    ctx = ToolContext(
        net=net,
        host=host,
        secret=store.get_secret(spec.needs_secret) if spec.needs_secret else None,
        cache=cache,
        extra={"intensity": intensity, "github_org": (settings or {}).get("github_org") or ""},
        gateway=gateway,
    )
    try:
        return await run_builtin(spec, ctx)
    except ScopeBlocked as exc:
        store.audit("tool", host, "refused", f"{spec.name}: {exc}", run_id)
        store.event(run_id, "refused", f"{spec.name}: {exc}")
        return None
    except Exception as exc:
        store.event(run_id, "warn", redact(f"{spec.name} failed: {type(exc).__name__}")[:240])
        return None


async def _invoke_external(store, spec: ToolSpec, host: str, run_id: str, external_caller):
    if external_caller is None:
        store.event(run_id, "warn", f"{spec.name} skipped: no MCP caller configured.")
        return None
    try:
        text = await external_caller(spec.server_name, spec.remote_name, host)
    except ScopeBlocked as exc:
        store.audit("tool", host, "refused", f"{spec.remote_name}: {exc}", run_id)
        store.event(run_id, "refused", f"{spec.remote_name}: {exc}")
        return None
    except Exception as exc:
        store.event(run_id, "warn", redact(f"{spec.remote_name} failed: {type(exc).__name__}")[:240])
        return None
    outcome = ToolOutcome()
    outcome.observations.append(
        Observation(
            host=host,
            tool=spec.name,
            severity="info",
            title=f"Attached tool {spec.remote_name}",
            evidence=redact(str(text))[:400] or "empty response",
            plain=(
                f"{spec.remote_name} ran through an attached MCP server with only the in-scope host as its argument. "
                "Treat the text as unconfirmed notes from that server."
            ),
        )
    )
    return outcome


async def _choose(
    llm: LLM, specs: list[ToolSpec], context: str, *, store: Store | None = None, run_id: str = ""
) -> list[ToolSpec]:
    if not specs:
        return []
    names = [spec.name for spec in specs]
    try:
        picked = await llm.plan(names, context)
    except Exception as exc:
        picked = names
        if store is not None and run_id and llm.name != "mock":
            store.event(run_id, "warn", redact(f"Model ({llm.name}) plan failed ({type(exc).__name__}); using default tools.")[:240])
    else:
        if store is not None and run_id and llm.name != "mock":
            store.event(run_id, "ok", f"Model ({llm.name}) planned {len(picked)} tools.")
    allow = set(names)
    ordered = [name for name in picked if name in allow] or names
    by_name = {spec.name: spec for spec in specs}
    return [by_name[name] for name in ordered]


def _filter_hosts(store, scope: Scope, names: list[str], run_id: str, existing: list[str], max_hosts: int):
    accepted = []
    refused = 0
    seen = set(existing)
    for name in names:
        if name in seen:
            continue
        decision = check_scope(scope, name)
        _audit(store, run_id, scope, decision, "discover")
        if not decision.allowed:
            refused += 1
            store.event(run_id, "refused", decision.reason)
            continue
        if len(existing) + len(accepted) >= max_hosts:
            refused += 1
            store.event(run_id, "warn", f"Host cap reached, skipping {name}.")
            continue
        accepted.append(decision.host)
        seen.add(decision.host)
    return accepted, refused


async def _triage(llm: LLM, rows: list, *, store: Store | None = None, run_id: str = "") -> list:
    if not rows:
        return []
    payload = [
        {
            "host": row.host,
            "tool": row.tool,
            "title": row.title,
            "evidence": row.evidence,
            "severity": row.severity,
            "plain": row.plain,
        }
        for row in rows
    ]
    try:
        reviewed = await llm.triage(payload)
    except Exception as exc:
        reviewed = []
        if store is not None and run_id and llm.name != "mock":
            store.event(run_id, "warn", failure_line("triage", llm.name, exc))
    else:
        if store is not None and run_id and llm.name != "mock":
            store.event(run_id, "ok", f"Model ({llm.name}) triaged {len(reviewed)} notes.")
    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    output = []
    for index, row in enumerate(rows):
        extra = reviewed[index] if index < len(reviewed) and isinstance(reviewed[index], dict) else {}
        severity = str(extra.get("severity") or row.severity)
        if severity not in order:
            severity = row.severity
        if order[severity] > order[row.severity] + 1:
            severity = row.severity
        if severity == "high" and not (row.tool == "nvd_cves" and _cvss_high(row.evidence)):
            severity = "medium" if order[row.severity] >= 1 else row.severity
        plain = sanitize_explanation(str(extra.get("plain") or row.plain))
        if row.tool == "nvd_cves" and "not confirmed" not in plain.lower() and "unverified" not in plain.lower():
            plain = "Unverified version correlation, not a confirmed vulnerability on this host. " + plain
        row.severity = severity
        row.plain = plain
        output.append(row)
    return output


def _cvss_high(evidence: str) -> bool:
    if "CVSS 9" in evidence or "CVSS 10" in evidence:
        return True
    return False


def _dedupe(rows: list) -> list:
    seen = set()
    output = []
    for row in rows:
        key = (row.host, row.tool, row.title)
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output[:80]


def _audit(store: Store, run_id: str, scope: Scope, decision, action: str) -> None:
    detail = f"{decision.reason} scope={scope.digest()} auth={scope.authorization[:180]}"
    store.audit(action, decision.host, "allowed" if decision.allowed else "refused", detail, run_id)


def json_scope(raw: str) -> dict:
    import json

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Stored scope is invalid.")
    return data


def secrets_id() -> str:
    return secrets.token_hex(8)
