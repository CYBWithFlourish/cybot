from __future__ import annotations

import asyncio
import json
import os
from urllib.parse import urlparse

import httpx

from cybot.policy import ExternalTool, vet_external
from cybot.redact import redact
from cybot.scope import ScopeBlocked

_INTENSITY = {"passive", "light", "standard"}


def load_servers(raw: str, *, allow_stdio: bool) -> list[dict]:
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("MCP config is not valid JSON.") from exc
    servers = data.get("servers") if isinstance(data, dict) else None
    if not isinstance(servers, list):
        raise ValueError("MCP config needs a servers list.")
    if len(servers) > 5:
        raise ValueError("Attach at most 5 MCP servers.")
    cleaned = []
    for item in servers:
        cleaned.append(validate_server(item, allow_stdio=allow_stdio))
    return cleaned


def validate_server(item: dict, *, allow_stdio: bool) -> dict:
    if not isinstance(item, dict):
        raise ValueError("Each MCP server must be an object.")
    name = str(item.get("name") or "").strip()
    if not name or not name.replace("-", "").isalnum() or len(name) > 40:
        raise ValueError("MCP server name must be short and alphanumeric.")
    transport = str(item.get("transport") or "http")
    mode = str(item.get("mode") or "passive")
    if mode not in _INTENSITY:
        raise ValueError("MCP server mode must be passive, light, or standard.")
    allow = item.get("allow") or []
    if not isinstance(allow, list) or not all(isinstance(entry, str) for entry in allow):
        raise ValueError("MCP allow list must be a list of tool names.")
    if len(allow) > 20:
        raise ValueError("MCP allow lists are capped at 20 names.")
    server = {"name": name, "transport": transport, "mode": mode, "allow": allow[:20]}
    if transport == "http":
        url = str(item.get("url") or "")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{name}: URL must be http or https.")
        host = (parsed.hostname or "").lower()
        if host in {"metadata.google.internal", "metadata"} or host.endswith(".internal"):
            raise ValueError(f"{name}: that MCP host is blocked.")
        server["url"] = url
        token_env = str(item.get("token_env") or "")
        if token_env and not token_env.replace("_", "").isalnum():
            raise ValueError(f"{name}: token_env must be an environment variable name.")
        server["token_env"] = token_env
    elif transport == "stdio":
        if not allow_stdio:
            raise ValueError(f"{name}: stdio MCP servers are off until CYBOT_MCP_STDIO=1.")
        command = item.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
            raise ValueError(f"{name}: stdio command must be an argv list, not a shell string.")
        if len(command) > 12:
            raise ValueError(f"{name}: command is too long.")
        server["command"] = command
    else:
        raise ValueError(f"{name}: transport must be http or stdio.")
    return server


async def discover(servers: list[dict]) -> tuple[list[ExternalTool], list[dict]]:
    vetted: list[ExternalTool] = []
    blocked: list[dict] = []
    for server in servers:
        try:
            result = await rpc(server, "tools/list", {})
        except Exception as exc:
            blocked.append(
                {
                    "server": server["name"],
                    "tool": "*",
                    "reason": redact(f"unreachable ({type(exc).__name__})"),
                }
            )
            continue
        tools = []
        if isinstance(result, dict):
            tools = result.get("tools") or []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "")
            description = str(tool.get("description") or "")
            ok, reason = vet_external(name, description, server.get("allow") or [])
            if ok:
                vetted.append(
                    ExternalTool(
                        name=name,
                        description=description[:300],
                        server_name=server["name"],
                        mode=server.get("mode") or "passive",
                        server=server,
                    )
                )
            else:
                blocked.append({"server": server["name"], "tool": name, "reason": reason})
    return vetted, blocked


async def call_tool(servers: list[dict], server_name: str, tool_name: str, host: str) -> str:
    server = next((item for item in servers if item["name"] == server_name), None)
    if server is None:
        raise ScopeBlocked("Attached MCP server is not in the saved config.")
    description = ""
    ok, reason = vet_external(tool_name, description, server.get("allow") or [])
    if not ok:
        raise ScopeBlocked(reason)
    result = await rpc(
        server,
        "tools/call",
        {"name": tool_name, "arguments": {"target": host}},
    )
    if isinstance(result, dict) and result.get("isError"):
        raise RuntimeError("Attached tool reported an error.")
    return _text(result)


async def rpc(server: dict, method: str, params: dict):
    if server["transport"] == "stdio":
        return await _rpc_stdio(server["command"], method, params)
    return await _rpc_http(server, method, params)


async def _rpc_http(server: dict, method: str, params: dict):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    token_env = server.get("token_env") or ""
    if token_env:
        token = os.environ.get(token_env, "")
        if not token:
            raise RuntimeError(f"missing {token_env}")
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
        response = await client.post(server["url"], headers=headers, json=body)
        response.raise_for_status()
        data = _decode_http(response)
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError("MCP error")
    if isinstance(data, dict):
        return data.get("result")
    raise RuntimeError("MCP response was empty")


def _decode_http(response: httpx.Response):
    content_type = response.headers.get("content-type", "")
    if "json" in content_type or response.text.lstrip().startswith("{"):
        return response.json()
    for line in response.text.splitlines():
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                return json.loads(payload)
    raise RuntimeError("MCP response was not JSON")


async def _rpc_stdio(command: list[str], method: str, params: dict):
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdin and proc.stdout

    async def send(message: dict) -> None:
        proc.stdin.write(_frame(message))
        await proc.stdin.drain()

    try:
        await send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "cybot", "version": "0.1.0"},
                },
            }
        )
        await _read_frame(proc.stdout)
        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        await send({"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
        message = await _read_frame(proc.stdout)
    finally:
        proc.kill()
        await proc.wait()
    if message.get("error"):
        raise RuntimeError("MCP error")
    return message.get("result")


def _frame(message: dict) -> bytes:
    body = json.dumps(message).encode()
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


async def _read_frame(reader: asyncio.StreamReader) -> dict:
    length = None
    while True:
        line = await asyncio.wait_for(reader.readline(), 20)
        if not line:
            raise RuntimeError("MCP server closed the pipe")
        if line in {b"\r\n", b"\n"}:
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    if length is None:
        raise RuntimeError("MCP frame missing Content-Length")
    payload = await asyncio.wait_for(reader.readexactly(length), 20)
    return json.loads(payload)


def _text(result) -> str:
    if isinstance(result, str):
        return result[:500]
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text") or ""))
            return "\n".join(parts)[:500]
        if "text" in result:
            return str(result["text"])[:500]
    return ""
