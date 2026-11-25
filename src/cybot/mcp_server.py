from __future__ import annotations

import json
from typing import Any

PROTOCOL = "2024-11-05"

TOOLS = [
    {
        "name": "check_scope",
        "description": "Decide whether a target is inside the supplied bug bounty scope. Does not contact the host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "program": {"type": "string"},
                "include": {"type": "array", "items": {"type": "string"}},
                "exclude": {"type": "array", "items": {"type": "string"}},
                "authorization": {"type": "string"},
            },
            "required": ["target", "program", "include"],
        },
    },
    {
        "name": "start_recon",
        "description": "Start a scope-gated recon run. Choose passive, soft-active, or active-test. Out-of-scope hosts are refused.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "program": {"type": "string"},
                "include": {"type": "array", "items": {"type": "string"}},
                "exclude": {"type": "array", "items": {"type": "string"}},
                "authorization": {"type": "string"},
                "intensity": {"type": "string", "enum": ["passive", "light", "standard"]},
                "mode": {"type": "string", "enum": ["passive", "soft-active", "active-test"]},
                "attestation": {
                    "type": "string",
                    "description": "Optional. CYBOT fills a scope-limited statement when this is omitted.",
                },
                "active_approved": {"type": "boolean"},
                "publish_to_notion": {
                    "type": "boolean",
                    "description": "Optional. Omit it and Notion is not published; call publish_report_to_notion after the run.",
                },
            },
            "required": ["target", "program", "include"],
        },
    },
    {
        "name": "get_status",
        "description": "Status of a recon run.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "get_findings",
        "description": "Findings for a run, severe ones first.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "kb_ingest",
        "description": "Embed the vendored knowledge catalog into the cybot-kb Pinecone namespace. Idempotent: the same document id is overwritten.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "kb_search",
        "description": "Search the cybot-kb namespace. Returned URLs come from the vendored catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "k": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "run_command",
        "description": "Run one allowlisted command for a mission. Scope, rate, budget, and attestation rails apply. Active-test does not run until confirm is true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mission_id": {"type": "string"},
                "command": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["mission_id", "command"],
        },
    },
    {
        "name": "get_playbook",
        "description": "Research playbook for one finding: manual checks, evidence, and reference links. CYBOT does not run exploits.",
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "finding_assist",
        "description": "Guidance for one finding. Manual retest only. No exploit code. Actions: explain, impact, retest, fix, research, ask.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "action": {"type": "string"},
                "message": {"type": "string"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "explain_finding",
        "description": "Plain-English explanation of one finding. No exploit steps.",
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_report",
        "description": "Markdown report for a finished run.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "list_tools",
        "description": "Recon tools CYBOT can run at each intensity, and attached MCP tools that passed the policy.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "publish_report_to_notion",
        "description": "Publish a finished run to the Notion reports database and add tracker rows. No-op with a reason when Notion is not granted.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "list_tracked_findings",
        "description": "Read the Notion findings tracker. Status values are new, triaged, reported, duplicate, and fixed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "program": {"type": "string"},
            },
        },
    },
    {
        "name": "search_memory",
        "description": "Search Pinecone memory for this program. Returns nothing useful when the connector is not granted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "program": {"type": "string"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_notion_programs",
        "description": "Read optional program scope rows from the Notion Programs & Scope database.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServer:
    def __init__(self, service):
        self.service = service

    async def handle(self, message: dict) -> dict | None:
        if not isinstance(message, dict):
            return _error(None, -32600, "Request must be a JSON object.")
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(msg_id, -32600, "Invalid JSON-RPC.")
        if method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "cybot", "version": "0.1.0"},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = await self._call(params)
            else:
                return _error(msg_id, -32601, f"Unknown method {method}.")
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    async def _call(self, params: dict) -> dict:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ValueError("arguments must be an object.")
        if name == "check_scope":
            payload = await self.service.check_scope(arguments)
        elif name == "start_recon":
            payload = await self.service.start_run(arguments, source="mcp")
        elif name == "get_status":
            payload = self.service.status(str(arguments.get("run_id") or ""))
        elif name == "get_findings":
            payload = {"findings": self.service.findings(str(arguments.get("run_id") or ""))}
        elif name == "kb_ingest":
            from cybot.kb import ingest

            gateway = await self.service._gateway()
            payload = await ingest(gateway, self.service.store.settings())
            payload.pop("ids", None)
        elif name == "kb_search":
            from cybot.kb import search

            gateway = await self.service._gateway()
            k = arguments.get("k") or 5
            payload = {
                "matches": await search(
                    gateway,
                    self.service.store.settings(),
                    str(arguments.get("query") or ""),
                    int(k),
                )
            }
        elif name == "run_command":
            payload = self.service.run_terminal(
                str(arguments.get("mission_id") or ""),
                str(arguments.get("command") or ""),
                confirmed=bool(arguments.get("confirm")),
            )
        elif name == "get_playbook":
            payload = self.service.playbook(str(arguments.get("finding_id") or ""))
        elif name == "finding_assist":
            payload = await self.service.assist(
                str(arguments.get("finding_id") or ""),
                str(arguments.get("action") or "ask"),
                str(arguments.get("message") or ""),
            )
        elif name == "explain_finding":
            payload = await self.service.explain(str(arguments.get("finding_id") or ""))
        elif name == "get_report":
            payload = {"markdown": self.service.report_markdown(str(arguments.get("run_id") or ""))}
        elif name == "list_tools":
            payload = {"tools": self.service.tool_catalog()}
        elif name == "publish_report_to_notion":
            payload = await self.service.publish_to_notion(str(arguments.get("run_id") or ""))
        elif name == "list_tracked_findings":
            payload = await self.service.notion_findings(
                status=str(arguments.get("status") or ""),
                program=str(arguments.get("program") or ""),
            )
        elif name == "list_notion_programs":
            payload = await self.service.notion_programs()
        elif name == "search_memory":
            payload = await self.service.search_memory(
                str(arguments.get("query") or ""),
                str(arguments.get("program") or ""),
            )
        else:
            raise ValueError(f"Unknown tool {name}.")
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}], "isError": False}


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


async def stdio_main(service) -> None:
    import sys

    server = MCPServer(service)
    reader = sys.stdin.buffer
    writer = sys.stdout.buffer
    while True:
        header = b""
        while True:
            line = reader.readline()
            if not line:
                return
            if line in {b"\r\n", b"\n"}:
                break
            header += line
        length = 0
        for line in header.splitlines():
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        if length <= 0:
            continue
        raw = reader.read(length)
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        response = await server.handle(message)
        if response is None:
            continue
        body = json.dumps(response).encode()
        writer.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        writer.flush()
