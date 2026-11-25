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


async def _mcp() -> None:
    from cybot.mcp_server import stdio_main

    config = Config.from_env()
    config.telegram = False
    store = Store(config.data_dir / "cybot.db", load_fernet(config.data_dir, config.master_key))
    service = Service(config, store)
    await stdio_main(service)


if __name__ == "__main__":
    main()
