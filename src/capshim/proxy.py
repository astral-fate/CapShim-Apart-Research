"""CapShim proxy: a transparent MCP shim.

The proxy is intentionally minimal and *stateless across requests*. It
performs three things on every ``tools/call``:

1. Construct a one-call :class:`Plan` (or accept a multi-call plan via
   the ``capshim/plan`` non-standard method).
2. Hand the plan to :class:`Checker`.
3. If allowed, forward to the upstream MCP server. If denied, return a
   structured ``capability_denied`` error with the proof witness in
   ``data``.

The proxy ships an in-process variant (for tests and the eval harness)
and a stdio variant matching the official MCP transport so it can be
dropped into any existing client config.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from capshim.checker import Checker, Verdict
from capshim.policy import Policy
from capshim.schema import Plan, ToolCall, ToolSchema


@dataclass
class AuditRecord:
    timestamp: float
    plan_id: str
    tool: str
    decision: str  # "allow" | "deny" | "forward_error"
    reason: str
    latency_ms: float


@dataclass
class CapShimProxy:
    """Transparent MCP proxy enforcing CapShim policy.

    ``upstream_call`` is an async callable that forwards a ``ToolCall``
    to the real MCP server and returns its JSON result.
    """

    tools: Mapping[str, ToolSchema]
    policy: Policy
    upstream_call: Optional[Callable[[ToolCall], Awaitable[Any]]] = None
    audit_log: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.checker = Checker(self.tools, self.policy)

    # ----- synchronous API for tests and benchmarks ----------------------

    def check(self, plan: Plan) -> Verdict:
        return self.checker.check_plan(plan)

    def call_sync(self, call: ToolCall) -> Dict[str, Any]:
        """Synchronous in-process call path used by the eval harness."""

        start = time.perf_counter()
        verdict = self.checker.check_call(call)
        latency_ms = (time.perf_counter() - start) * 1000.0
        if not verdict.allow:
            self._record("deny", call.tool, "", verdict.reason(), latency_ms)
            return _deny_payload(verdict)
        self._record("allow", call.tool, "", "ok", latency_ms)
        return {"jsonrpc": "2.0", "result": {"forwarded": True, "tool": call.tool}}

    def check_plan_sync(self, plan: Plan) -> Dict[str, Any]:
        start = time.perf_counter()
        verdict = self.checker.check_plan(plan)
        latency_ms = (time.perf_counter() - start) * 1000.0
        first_tool = plan.calls[0].tool if plan.calls else ""
        if not verdict.allow:
            self._record("deny", first_tool, plan.plan_id, verdict.reason(), latency_ms)
            return _deny_payload(verdict)
        self._record("allow", first_tool, plan.plan_id, "ok", latency_ms)
        return {"jsonrpc": "2.0", "result": {"plan_id": plan.plan_id, "approved": True}}

    # ----- async forwarding API ------------------------------------------

    async def call_async(self, call: ToolCall) -> Dict[str, Any]:
        start = time.perf_counter()
        verdict = self.checker.check_call(call)
        latency_ms = (time.perf_counter() - start) * 1000.0
        if not verdict.allow:
            self._record("deny", call.tool, "", verdict.reason(), latency_ms)
            return _deny_payload(verdict)
        if self.upstream_call is None:
            self._record("allow", call.tool, "", "ok (no upstream)", latency_ms)
            return {"jsonrpc": "2.0", "result": {"forwarded": False}}
        try:
            result = await self.upstream_call(call)
        except Exception as exc:  # narrow on purpose: report upstream errors
            self._record("forward_error", call.tool, "", repr(exc), latency_ms)
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": f"upstream error: {exc!r}"},
            }
        self._record("allow", call.tool, "", "forwarded", latency_ms)
        return {"jsonrpc": "2.0", "result": result}

    # ----- audit ----------------------------------------------------------

    def _record(
        self,
        decision: str,
        tool: str,
        plan_id: str,
        reason: str,
        latency_ms: float,
    ) -> None:
        self.audit_log.append(
            AuditRecord(
                timestamp=time.time(),
                plan_id=plan_id,
                tool=tool,
                decision=decision,
                reason=reason,
                latency_ms=latency_ms,
            )
        )


def _deny_payload(verdict: Verdict) -> Dict[str, Any]:
    assert verdict.witness is not None
    w = verdict.witness
    return {
        "jsonrpc": "2.0",
        "error": {
            "code": -32010,
            "message": "capability_denied",
            "data": {
                "rule": w.rule,
                "tool": w.tool,
                "call_index": w.call_index,
                "source_label": w.source_label.name,
                "source_categories": [str(c) for c in w.source_categories],
                "sink": w.sink,
                "explanation": w.explain(),
            },
        },
    }
