from __future__ import annotations

import argparse
import asyncio
import os

from cybot.config import Config
from cybot.service import Service
from cybot.store import Store, load_fernet


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cybot", description="Scope-gated bug bounty recon agent.")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the dashboard, API, and optional Telegram poller.")
    serve.add_argument("--host", default=os.environ.get("CYBOT_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("CYBOT_PORT", "8641")))
    sub.add_parser("mcp", help="Speak MCP on stdin/stdout for a local agent.")
    kb = sub.add_parser("kb", help="Ingest or search the vendored knowledge base.")
    kb_sub = kb.add_subparsers(dest="kb_command", required=True)
    kb_sub.add_parser("ingest", help="Embed the catalog and guides into the cybot-kb namespace.")
    kb_search = kb_sub.add_parser("search", help="Search the cybot-kb namespace.")
    kb_search.add_argument("query")
    kb_search.add_argument("-k", type=int, default=5)
    args = parser.parse_args(argv)
    if args.command == "serve":
        import uvicorn

        uvicorn.run(
            "cybot.app:create_app",
            factory=True,
            host=args.host,
            port=args.port,
        )
        return
    if args.command == "mcp":
        asyncio.run(_mcp())
        return
    if args.command == "kb":
        asyncio.run(_kb(args))


async def _kb(args) -> None:
    from cybot.kb import ingest, search

    config = Config.from_env()
    store = Store(config.data_dir / "cybot.db", load_fernet(config.data_dir, config.master_key))
    service = Service(config, store)
    gateway = await service._gateway()
    settings = store.settings()
    if args.kb_command == "ingest":
        result = await ingest(gateway, settings)
        print(f"namespace={result.get('namespace') or 'cybot-kb'} upserted={result.get('upserted', 0)} ok={result.get('ok')}")
        if result.get("reason"):
            print(result["reason"])
        return
    rows = await search(gateway, settings, args.query, args.k)
    if not rows:
        print("No knowledge-base matches.")
        return
    for row in rows:
        print(f"{row['title']}\t{row['url']}")


async def _mcp() -> None:
    from cybot.mcp_server import stdio_main

    config = Config.from_env()
    config.telegram = False
    store = Store(config.data_dir / "cybot.db", load_fernet(config.data_dir, config.master_key))
    service = Service(config, store)
    await stdio_main(service)


if __name__ == "__main__":
    main()
