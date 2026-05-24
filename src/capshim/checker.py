"""Static IFC checker for tool-call plans.

Given a tool registry (name -> :class:`ToolSchema`), a policy, and a
plan (sequence of tool calls), the checker simulates the data flow
symbolically and either returns :class:`Verdict(allow=True)` or
produces a :class:`Witness` describing exactly which call violated
which type rule.

Calls produce abstract return-values; subsequent calls may reference
prior returns via the literal ``"$ret:N"`` (where ``N`` is the index
into the plan). This models the LLM pattern of piping one tool's
output into another's input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

from capshim.labels import Category, Label, Tag, join, join_tags, leq
from capshim.policy import Policy
from capshim.schema import (
    Plan,
    ToolCall,
    ToolSchema,
    parse_tagged_template,
    render_label_template,
)


_REF_RE = re.compile(r"^\$ret:(\d+)(?::([a-zA-Z_][a-zA-Z_0-9.]*))?$")


@dataclass(frozen=True)
class Witness:
    """A structured description of a rejected flow."""

    rule: str
    call_index: int
    tool: str
    detail: str
    source_label: Label
    source_categories: tuple
    sink: str
    plan_id: str = ""

    def explain(self) -> str:
        cats = ", ".join(str(c) for c in self.source_categories) or "-"
        return (
            f"[{self.rule}] call #{self.call_index} {self.tool}: {self.detail} "
            f"(source label={self.source_label.name}, categories=[{cats}], sink={self.sink})"
        )


@dataclass(frozen=True)
class Verdict:
    """Result of typechecking a plan."""

    allow: bool
    witness: Optional[Witness] = None
    plan_id: str = ""

    def __bool__(self) -> bool:  # convenience
        return self.allow

    def reason(self) -> str:
        if self.allow:
            return "plan typechecks under the active policy"
        assert self.witness is not None
        return self.witness.explain()


class Checker:
    """Plan typechecker.

    Public surface:
      * :meth:`check_call`  — typecheck a single ``ToolCall`` in context.
      * :meth:`check_plan`  — typecheck a whole :class:`Plan`.
    """

    def __init__(self, tools: Mapping[str, ToolSchema], policy: Policy) -> None:
        self.tools = dict(tools)
        self.policy = policy

    # ----- public ---------------------------------------------------------

    def check_plan(self, plan: Plan) -> Verdict:
        """Symbolically execute a plan; return Allow or first violation."""

        returns: List[Tag] = []
        for idx, call in enumerate(plan.calls):
            verdict = self._check_one(idx, call, returns, plan.plan_id)
            if not verdict.allow:
                return verdict
            returns.append(self._infer_return_tag(call, returns))
        return Verdict(allow=True, plan_id=plan.plan_id)

    def check_call(self, call: ToolCall) -> Verdict:
        return self.check_plan(Plan.of(call))

    # ----- core type rules ------------------------------------------------

    def _check_one(
        self,
        idx: int,
        call: ToolCall,
        prior_returns: List[Tag],
        plan_id: str,
    ) -> Verdict:
        if call.tool not in self.tools:
            return Verdict(
                allow=False,
                witness=Witness(
                    rule="T-Unknown",
                    call_index=idx,
                    tool=call.tool,
                    detail="tool not in registry",
                    source_label=Label.PUBLIC,
                    source_categories=(),
                    sink=call.tool,
                    plan_id=plan_id,
                ),
                plan_id=plan_id,
            )

        schema = self.tools[call.tool]

        # Resolve and join all argument tags. We over-approximate by
        # joining: the caller's input taint becomes the lower bound for
        # the tool's output taint.
        arg_tag = Tag(Label.PUBLIC, frozenset())
        sink_host: str = ""
        for name, value in call.arguments.items():
            arg_label, arg_cats = self._tag_for_arg(name, value, schema, prior_returns)
            arg_tag = Tag(
                label=join(arg_tag.label, arg_label),
                categories=arg_tag.categories | set(arg_cats),
            )
            if name in {"host", "url", "endpoint"}:
                sink_host = _host_of(str(value))

        # ----- T-Net: egress checks ---------------------------------------
        if "net.http" in schema.effects:
            host = sink_host or _host_arg(call.arguments)
            if not self.policy.is_egress_allowed(host):
                return Verdict(
                    allow=False,
                    witness=Witness(
                        rule="T-Net-Egress",
                        call_index=idx,
                        tool=call.tool,
                        detail=f"host {host!r} not in allowed_egress",
                        source_label=arg_tag.label,
                        source_categories=tuple(arg_tag.categories),
                        sink=host,
                        plan_id=plan_id,
                    ),
                    plan_id=plan_id,
                )
            if not self.policy.allows_sink(host, arg_tag.label, arg_tag.categories):
                return Verdict(
                    allow=False,
                    witness=Witness(
                        rule="T-Net-Confidentiality",
                        call_index=idx,
                        tool=call.tool,
                        detail=(
                            f"confidential data (label={arg_tag.label.name}) "
                            f"would egress to untrusted host {host!r}"
                        ),
                        source_label=arg_tag.label,
                        source_categories=tuple(arg_tag.categories),
                        sink=host,
                        plan_id=plan_id,
                    ),
                    plan_id=plan_id,
                )

        # ----- T-Write: persisted-write checks ----------------------------
        if "fs.write" in schema.effects:
            path = str(call.arguments.get("path", ""))
            # Writing Secret-tagged data anywhere is currently forbidden
            # unless the target path is itself in sensitive_paths (i.e.
            # we're moving secrets among secret stores).
            if not leq(arg_tag.label, Label.PUBLIC) and not self.policy.is_sensitive_path(path):
                return Verdict(
                    allow=False,
                    witness=Witness(
                        rule="T-Write-Leak",
                        call_index=idx,
                        tool=call.tool,
                        detail=(
                            f"confidential data would be persisted to "
                            f"non-sensitive path {path!r}"
                        ),
                        source_label=arg_tag.label,
                        source_categories=tuple(arg_tag.categories),
                        sink=path,
                        plan_id=plan_id,
                    ),
                    plan_id=plan_id,
                )

        return Verdict(allow=True, plan_id=plan_id)

    # ----- helpers --------------------------------------------------------

    def _tag_for_arg(
        self,
        name: str,
        value: Any,
        schema: ToolSchema,
        prior_returns: List[Tag],
    ) -> tuple[Label, tuple[Category, ...]]:
        # 1) Reference to a prior return.
        if isinstance(value, str):
            m = _REF_RE.match(value)
            if m:
                ridx = int(m.group(1))
                if 0 <= ridx < len(prior_returns):
                    rt = prior_returns[ridx]
                    return rt.label, tuple(rt.categories)
                return Label.PUBLIC, ()
        # 2) Per-tool advertised input label, possibly templated.
        template = schema.input_labels.get(name)
        if template:
            rendered = render_label_template(template, dict(_args_view(name, value)))
            label, cats = parse_tagged_template(rendered)
            return label, cats
        # 3) Default: User-supplied.
        return Label.USER, ()

    def _infer_return_tag(
        self,
        call: ToolCall,
        prior_returns: List[Tag],
    ) -> Tag:
        schema = self.tools.get(call.tool)
        if schema is None:
            return Tag(Label.PUBLIC, frozenset())

        # Resolve output_label template against arguments AND a "label_of"
        # helper for fs paths so that fs_read can advertise:
        #     outputLabel: "SECRET+fs.read(${path})"  IF path is sensitive
        # We support a simple case: the schema author writes
        #     outputLabel: "$label_of_path(${path})+fs.read(${path})"
        # and we render label_of_path here.
        rendered = render_label_template(schema.output_label, dict(call.arguments))
        rendered = self._expand_label_helpers(rendered, call.arguments)

        # Join with arg labels so the tool can't "launder" inputs.
        arg_label = Label.PUBLIC
        arg_cats: set[Category] = set()
        for name, value in call.arguments.items():
            l, c = self._tag_for_arg(name, value, schema, prior_returns)
            arg_label = join(arg_label, l)
            arg_cats |= set(c)

        try:
            out_label, out_cats = parse_tagged_template(rendered)
        except ValueError:
            out_label, out_cats = Label.PUBLIC, ()

        return Tag(
            label=join(arg_label, out_label),
            categories=frozenset(arg_cats | set(out_cats)),
        )

    def _expand_label_helpers(self, rendered: str, arguments: Mapping[str, Any]) -> str:
        # $label_of_path(<rendered path>) -> SECRET if path is in
        # policy.sensitive_paths else PUBLIC.
        if "$label_of_path" in rendered:
            path = str(arguments.get("path", ""))
            label = "SECRET" if self.policy.is_sensitive_path(path) else "PUBLIC"
            rendered = re.sub(r"\$label_of_path\([^)]*\)", label, rendered)
        # $label_of_env(<rendered env name>) -> SECRET if env name is in
        # policy.sensitive_env else USER.
        if "$label_of_env" in rendered:
            name = str(arguments.get("name", ""))
            label = "SECRET" if self.policy.is_sensitive_env(name) else "USER"
            rendered = re.sub(r"\$label_of_env\([^)]*\)", label, rendered)
        return rendered

    # check_call kept for symmetry with single-call usage
    # (defined above already)


def _host_arg(arguments: Mapping[str, Any]) -> str:
    for key in ("host", "url", "endpoint"):
        if key in arguments:
            return _host_of(str(arguments[key]))
    return ""


def _host_of(url_or_host: str) -> str:
    """Extract a bare hostname from an argument that may be a URL."""

    if "://" in url_or_host:
        rest = url_or_host.split("://", 1)[1]
        return rest.split("/", 1)[0].split(":", 1)[0]
    return url_or_host


def _args_view(name: str, value: Any) -> Iterable[tuple[str, Any]]:
    """Tiny helper to render a single (name, value) pair into a templating dict."""

    yield name, value
