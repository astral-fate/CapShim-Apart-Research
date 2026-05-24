"""CapShim: capability-typed shim for the Model Context Protocol.

A transparent proxy between an LLM agent and an MCP server that enforces
Information Flow Control labels on tool inputs and outputs, statically
rejecting any tool-call plan whose data flow would violate the
configured policy.
"""

from capshim.labels import Label, Category, Tag, join, leq
from capshim.schema import ToolSchema, LabeledArg, ToolCall, Plan
from capshim.policy import Policy, load_policy
from capshim.checker import Checker, Verdict, Witness
from capshim.proxy import CapShimProxy

__version__ = "0.1.0"

__all__ = [
    "Label",
    "Category",
    "Tag",
    "join",
    "leq",
    "ToolSchema",
    "LabeledArg",
    "ToolCall",
    "Plan",
    "Policy",
    "load_policy",
    "Checker",
    "Verdict",
    "Witness",
    "CapShimProxy",
]
