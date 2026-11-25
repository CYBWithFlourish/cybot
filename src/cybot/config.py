from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    data_dir: Path
    demo: bool = False
    master_key: str | None = None
    mcp_token: str | None = None
    telegram: bool = False
    gateway_list_url: str = "https://api.sprites.dev/v1/gateway/list"
    ollama_host: str = "http://127.0.0.1:11434"
    max_hosts: int = 20
    rate_per_min: int = 20
    run_timeout: float = 120
    inline_runs: bool = False
    discover_mcp: bool = True
    mcp_stdio: bool = False
    cookie_secure: bool | None = None

    @classmethod
    def from_env(cls) -> Config:
        secure = os.environ.get("CYBOT_COOKIE_SECURE")
        cookie_secure: bool | None
        if secure == "1":
            cookie_secure = True
        elif secure == "0":
            cookie_secure = False
        else:
            cookie_secure = None
        return cls(
            data_dir=Path(os.environ.get("CYBOT_DATA_DIR", "data")),
            demo=os.environ.get("CYBOT_DEMO", "") == "1",
            master_key=os.environ.get("CYBOT_MASTER_KEY") or None,
            mcp_token=os.environ.get("CYBOT_MCP_TOKEN") or None,
            telegram=os.environ.get("CYBOT_TELEGRAM", "1") != "0",
            gateway_list_url=os.environ.get(
                "SPRITES_GATEWAY_LIST", "https://api.sprites.dev/v1/gateway/list"
            ),
            ollama_host=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
            max_hosts=int(os.environ.get("CYBOT_MAX_HOSTS", "20")),
            rate_per_min=int(os.environ.get("CYBOT_RATE_PER_MIN", "20")),
            run_timeout=float(os.environ.get("CYBOT_RUN_TIMEOUT", "120")),
            inline_runs=False,
            discover_mcp=True,
            mcp_stdio=os.environ.get("CYBOT_MCP_STDIO", "") == "1",
            cookie_secure=cookie_secure,
        )
