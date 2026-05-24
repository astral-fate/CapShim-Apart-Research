"""MCP tool-schema extensions for CapShim.

A vanilla MCP tool description is a JSON object with `name`, `description`,
and an `inputSchema`. CapShim adds three optional fields:

* ``inputLabels`` — for each named argument, the expected label or a label
  template (e.g. ``"fs.read(${path})"`` to derive the label at call time).
* ``outputLabel`` — the label/category attached to the tool's return value.
  May also be templated.
* ``effects`` — declarative side-effect categories the tool performs.
* ``declassifies`` — optional list of ``(from, to)`` label edges this tool
  is permitted to relabel (policy-gated).

These are *advertised* by the tool author and *checked* by the policy.
A misadvertised label is a policy bug, not a soundness bug — see the
Limitations & Dual-Use appendix in the paper.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from capshim.labels import Category, Label, Tag


@dataclass(frozen=True)
class LabeledArg:
    """An argument value paired with its inferred tag at call time."""

    value: Any
    tag: Tag


@dataclass(frozen=True)
class ToolSchema:
    """Extended MCP tool schema."""

    name: str
    description: str
    input_schema: Mapping[str, Any]
    input_labels: Mapping[str, str] = field(default_factory=dict)
    output_label: str = "PUBLIC"
    effects: tuple = ()
    declassifies: tuple = ()

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "ToolSchema":
        return cls(
            name=payload["name"],
            description=payload.get("description", ""),
            input_schema=payload.get("inputSchema", {}),
            input_labels=dict(payload.get("inputLabels", {})),
            output_label=payload.get("outputLabel", "PUBLIC"),
            effects=tuple(payload.get("effects", ())),
            declassifies=tuple(
                (str(a), str(b)) for a, b in payload.get("declassifies", ())
            ),
        )


@dataclass(frozen=True)
class ToolCall:
    """A single MCP ``tools/call``."""

    tool: str
    arguments: Mapping[str, Any]
    call_id: str = ""

    def __str__(self) -> str:
        args = json.dumps(self.arguments, default=str, sort_keys=True)
        return f"{self.tool}({args})"


@dataclass(frozen=True)
class Plan:
    """A linear sequence of tool calls the agent proposes to execute.

    CapShim checks plans, not individual calls in isolation, because the
    "weird machine" failure mode is a *composition* of benign calls.
    """

    calls: tuple
    plan_id: str = ""

    def __iter__(self):
        return iter(self.calls)

    def __len__(self) -> int:
        return len(self.calls)

    @classmethod
    def of(cls, *calls: ToolCall, plan_id: str = "") -> "Plan":
        return cls(calls=tuple(calls), plan_id=plan_id)


def render_label_template(template: str, arguments: Mapping[str, Any]) -> str:
    """Substitute ``${name}`` placeholders with stringified argument values."""

    out = template
    for key, value in arguments.items():
        out = out.replace("${" + key + "}", str(value))
    return out


def parse_tagged_template(template: str) -> tuple[Label, tuple[Category, ...]]:
    """Parse a label-template string into a (label, categories) tuple.

    Grammar (informal):
        TEMPLATE := LABEL [ "+" CAT ( "," CAT )* ]
        CAT      := KIND "(" ARG ")"
        LABEL    := PUBLIC | USER | SECRET
    """

    template = template.strip()
    if "+" not in template:
        return Label.parse(template), ()
    head, _, tail = template.partition("+")
    label = Label.parse(head)
    cats: list[Category] = []
    for piece in tail.split(","):
        piece = piece.strip()
        if not piece:
            continue
        kind, _, rest = piece.partition("(")
        arg = rest.rstrip(")").strip()
        cats.append(Category(kind.strip(), arg))
    return label, tuple(cats)
