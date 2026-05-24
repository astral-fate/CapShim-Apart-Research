"""Toy MCP server with the canonical exfiltration kit.

Implements four tools commonly chained in real prompt-injection attacks:

* ``fs_read``  — read a file by path
* ``fs_write`` — write content to a path
* ``net_http_post`` — POST a body to a URL
* ``env_get``  — read an environment variable

Each tool advertises its CapShim labels in the schema. The server itself
has no security boundary; CapShim provides the boundary externally.

Run standalone for debugging:
    python -m examples.servers.toy_mcp_server
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict

# Tools advertised as MCP schema dicts; CapShim consumes these via
# ToolSchema.from_json.
TOOLS: list[Dict[str, Any]] = [
    {
        "name": "fs_read",
        "description": "Read a file from disk.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "inputLabels": {"path": "PUBLIC"},
        "outputLabel": "$label_of_path(${path})+fs.read(${path})",
        "effects": ["fs.read"],
    },
    {
        "name": "fs_write",
        "description": "Write content to a file on disk.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
        # Literal `content` is PUBLIC; taint propagates only via $ret:N
        # references that the checker resolves to a prior tool's tag.
        "inputLabels": {"path": "PUBLIC", "content": "PUBLIC"},
        "outputLabel": "PUBLIC",
        "effects": ["fs.write"],
    },
    {
        "name": "net_http_post",
        "description": "POST a JSON body to a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
            "required": ["url", "body"],
        },
        "inputLabels": {"url": "PUBLIC", "body": "PUBLIC"},
        "outputLabel": "PUBLIC",
        "effects": ["net.http"],
    },
    {
        "name": "env_get",
        "description": "Read an environment variable.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        "inputLabels": {"name": "PUBLIC"},
        # Policy decides per-name whether to mark the result SECRET.
        "outputLabel": "$label_of_env(${name})+env(${name})",
        "effects": ["env.read"],
    },
]


def dispatch(call_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the tool. Used only for end-to-end demos, never in eval."""
    if call_name == "fs_read":
        path = str(arguments["path"])
        return {"content": Path(path).read_text(encoding="utf-8", errors="replace")}
    if call_name == "fs_write":
        path = str(arguments["path"])
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(str(arguments["content"]), encoding="utf-8")
        return {"bytes_written": len(str(arguments["content"]))}
    if call_name == "net_http_post":
        return {
            "ok": True,
            "stub": True,
            "url": str(arguments["url"]),
            "body_len": len(str(arguments["body"])),
        }
    if call_name == "env_get":
        return {"value": os.environ.get(str(arguments["name"]), "")}
    raise KeyError(f"unknown tool: {call_name}")


def tool_schemas() -> list[Dict[str, Any]]:
    return TOOLS


if __name__ == "__main__":  # pragma: no cover - standalone debug
    print(json.dumps({"tools": TOOLS}, indent=2))
