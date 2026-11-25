from __future__ import annotations

import asyncio

import httpx

from cybot.redact import redact
from cybot.scope import ScopeError, normalize_host, parse_scope


HELP = (
    "CYBOT on Telegram.\n"
    "/recon host - passive recon using the scope saved on the dashboard.\n"
    "/scan host - same passive rail. Soft-active and active-test stay on the dashboard.\n"
    "/status - latest run.\n"
    "/findings - short list. Each note still needs a person to retest it.\n"
    "/report - summary. The full Markdown and PDF are on the dashboard.\n"
    "Active-test needs the dashboard attestation. Telegram cannot widen scope."
)


def parse_command(text: str) -> tuple[str, str]:
    parts = (text or "").strip().split()
    if not parts:
        return "", ""
    command = parts[0].split("@", 1)[0].lower()
    argument = parts[1] if len(parts) > 1 else ""
    if len(parts) > 2:
        return command, "TOO_MANY"
    return command, argument


async def handle_text(service, chat_id: str, text: str) -> str:
    command, argument = parse_command(text)
    service.store.meta_set("telegram_chat", str(chat_id))
    if command in {"/start", "/help"}:
        return HELP
    if command in {"/recon", "/scan"}:
        if argument in {"", "TOO_MANY"}:
            return "Usage: /recon host\nTelegram starts passive recon only."
        raw = service.store.meta_get("scope")
        if not raw:
            return "Save a scope on the dashboard first. Telegram cannot widen scope."
        try:
            import json

            scope = parse_scope(json.loads(raw))
            host = normalize_host(argument)
        except (ScopeError, json.JSONDecodeError, ValueError) as exc:
            return str(exc)
        try:
            created = await service.start_run(
                {
                    "program": scope.program,
                    "include": list(scope.include),
                    "exclude": list(scope.exclude),
                    "authorization": scope.authorization,
                    "target": host,
                    "intensity": "passive",
                    "active_approved": False,
                    "demo": False,
                },
                source="telegram",
            )
        except ValueError as exc:
            return str(exc)
        return f"Started passive run {created['id']} for {host}. I will message you when it finishes."
    if command == "/status":
        runs = service.store.list_runs(1)
        if not runs:
            return "No runs yet."
        run = runs[0]
        return f"{run['id']} {run['status']} {run['target']} ({run['intensity']})"
    if command == "/findings":
        runs = service.store.list_runs(1)
        if not runs:
            return "No runs yet."
        findings = service.findings(runs[0]["id"])[:8]
        if not findings:
            return "No findings on the latest run."
        from cybot.playbook import loads_playbook, short_summary

        lines = []
        for row in findings[:5]:
            book = row.get("playbook") if isinstance(row.get("playbook"), dict) else loads_playbook(row.get("playbook"))
            flag = ""
            if row.get("needs_human_validation", True):
                flag = " (needs human validation)"
            lines.append(f"{row['severity']}: {row['title']}{flag}")
            lines.append(short_summary(book)[:180])
        lines.append("Only test in-scope assets. CYBOT only suggests, never runs exploits.")
        return "\n".join(lines)
    if command == "/report":
        runs = service.store.list_runs(1)
        if not runs:
            return "No runs yet."
        report = service.store.get_report(runs[0]["id"]) or "Report is not ready."
        return report[:3500]
    return HELP


async def poll_forever(service) -> None:
    offset = 0
    while True:
        token = service.telegram_token()
        if not token:
            await asyncio.sleep(5)
            continue
        try:
            async with httpx.AsyncClient(timeout=40) as client:
                response = await client.get(
                    f"https://api.telegram.org/bot{token}/getUpdates",
                    params={"timeout": 25, "offset": offset},
                )
                response.raise_for_status()
                data = response.json()
        except Exception:
            await asyncio.sleep(5)
            continue
        for update in data.get("result") or []:
            offset = int(update.get("update_id", offset)) + 1
            callback = update.get("callback_query") or {}
            if callback:
                try:
                    await handle_callback(service, token, callback)
                except Exception as exc:
                    await answer_callback(token, callback.get("id"), redact(type(exc).__name__))
                continue
            message = update.get("message") or {}
            chat = (message.get("chat") or {}).get("id")
            text = message.get("text") or ""
            if chat is None:
                continue
            try:
                reply = await handle_text(service, str(chat), text)
            except Exception as exc:
                reply = redact(f"Command failed: {type(exc).__name__}")
            await send_message(token, chat, reply)


def notion_prompt(target: str, run_id: str) -> dict:
    return {
        "text": f"Create a Notion page for {target}?",
        "reply_markup": {
            "inline_keyboard": [
                [
                    {"text": "Yes", "callback_data": f"notion:yes:{run_id}"},
                    {"text": "No", "callback_data": f"notion:no:{run_id}"},
                ]
            ]
        },
    }


def parse_notion_callback(data: str) -> tuple[str, str] | None:
    parts = (data or "").split(":")
    if len(parts) == 3 and parts[0] == "notion" and parts[1] in {"yes", "no"} and parts[2]:
        return parts[1], parts[2]
    return None


async def handle_callback(service, token: str, callback: dict) -> None:
    parsed = parse_notion_callback(str(callback.get("data") or ""))
    if parsed is None:
        await answer_callback(token, callback.get("id"), "Unknown button.")
        return
    choice, run_id = parsed
    if choice == "yes":
        result = await service.publish_to_notion(run_id)
        text = "Notion page created." if result.get("published") else result.get("reason") or "Notion was not published."
    else:
        service.decline_notion(run_id)
        text = "Notion was not published."
    await answer_callback(token, callback.get("id"), text[:180])
    message = callback.get("message") or {}
    chat = (message.get("chat") or {}).get("id")
    if chat is not None:
        await send_message(token, chat, text)


async def send_notion_prompt(token: str, chat_id, target: str, run_id: str) -> None:
    payload = notion_prompt(target, run_id)
    async with httpx.AsyncClient(timeout=20) as client:
        await client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": payload["text"], "reply_markup": payload["reply_markup"]},
        )


async def answer_callback(token: str, callback_id, text: str) -> None:
    if not callback_id:
        return
    async with httpx.AsyncClient(timeout=20) as client:
        await client.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text[:180]},
        )


async def send_message(token: str, chat_id, text: str) -> None:
    async with httpx.AsyncClient(timeout=20) as client:
        await client.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text[:4000]},
        )
