"""Policy DSL for CapShim.

A policy is a YAML document that names the IFC contract between the
agent and the MCP server. It declares:

* ``sensitive_paths`` — glob list whose contents are labelled ``Secret``.
* ``trusted_hosts`` — hosts to which ``Secret`` data may egress.
* ``allowed_egress`` — hosts to which *any* data may egress; everything
  else is implicitly forbidden.
* ``declassifications`` — explicit ``(from, to, when)`` edges that
  authorize a tool to relabel data.
* ``tool_labels`` — per-tool overrides of advertised labels.

If you set ``allowed_egress: []`` then no egress is permitted (a useful
default for closed environments).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional

from capshim.labels import Category, Label, category_matches, leq


@dataclass(frozen=True)
class Declassification:
    """An authorized relabeling edge."""

    from_label: Label
    to_label: Label
    by_tool: str = "*"
    when_category: Optional[Category] = None


@dataclass(frozen=True)
class Policy:
    sensitive_paths: tuple = ()
    sensitive_env: tuple = ()
    trusted_hosts: tuple = ()
    allowed_egress: tuple = ()
    declassifications: tuple = ()
    tool_labels: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    # ----- predicates ------------------------------------------------------

    def is_sensitive_path(self, path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, p) for p in self.sensitive_paths)

    def is_sensitive_env(self, name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, p) for p in self.sensitive_env)

    def is_egress_allowed(self, host: str) -> bool:
        if not self.allowed_egress:
            return False
        return any(fnmatch.fnmatchcase(host, h) for h in self.allowed_egress)

    def is_trusted_host(self, host: str) -> bool:
        return any(fnmatch.fnmatchcase(host, h) for h in self.trusted_hosts)

    def allows_sink(
        self,
        host: str,
        label: Label,
        categories: Iterable[Category] = (),
    ) -> bool:
        """Can data with this label and categories egress to this host?

        Lattice rules:
        * PUBLIC / USER  → any allowed_egress host.
        * SECRET         → trusted_hosts only, and only if no category
                           identifies the data as deeply sensitive
                           (sensitive_path / sensitive_env / secret / pii).
        """

        if not self.is_egress_allowed(host):
            return False
        # Independent of label: tagged sensitive material is gated even
        # for a host that happens to sit on the allowed_egress list.
        cats = list(categories)
        for cat in cats:
            if cat.kind == "fs.read" and self.is_sensitive_path(cat.arg):
                return self.is_trusted_host(host)
            if cat.kind == "env" and self.is_sensitive_env(cat.arg):
                return self.is_trusted_host(host)
            if cat.kind in {"secret", "pii"}:
                return self.is_trusted_host(host)
        if leq(label, Label.USER):
            return True
        # SECRET-labeled data without a sensitive category: trusted only.
        return self.is_trusted_host(host)

    def declassification_allowed(
        self,
        tool: str,
        from_label: Label,
        to_label: Label,
        categories: Iterable[Category] = (),
    ) -> bool:
        for d in self.declassifications:
            if d.by_tool not in {"*", tool}:
                continue
            if d.from_label != from_label or d.to_label != to_label:
                continue
            if d.when_category is None:
                return True
            for cat in categories:
                if category_matches(cat, d.when_category.kind, d.when_category.arg):
                    return True
        return False


def load_policy(path: str | Path) -> Policy:
    """Load and validate a YAML policy file."""

    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - friendly error
        raise RuntimeError(
            "PyYAML is required to load policies. `pip install pyyaml`."
        ) from exc

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return _from_dict(raw)


def policy_from_string(text: str) -> Policy:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML required") from exc
    raw = yaml.safe_load(text) or {}
    return _from_dict(raw)


def _from_dict(raw: Mapping[str, Any]) -> Policy:
    decls: list[Declassification] = []
    for d in raw.get("declassifications", []) or []:
        when = d.get("when")
        cat: Optional[Category] = None
        if isinstance(when, str) and "(" in when:
            kind, _, rest = when.partition("(")
            cat = Category(kind.strip(), rest.rstrip(")").strip())
        decls.append(
            Declassification(
                from_label=Label.parse(d["from"]),
                to_label=Label.parse(d["to"]),
                by_tool=d.get("by", "*"),
                when_category=cat,
            )
        )

    return Policy(
        sensitive_paths=tuple(raw.get("sensitive_paths", []) or []),
        sensitive_env=tuple(raw.get("sensitive_env", []) or []),
        trusted_hosts=tuple(raw.get("trusted_hosts", []) or []),
        allowed_egress=tuple(raw.get("allowed_egress", []) or []),
        declassifications=tuple(decls),
        tool_labels={k: dict(v) for k, v in (raw.get("tool_labels", {}) or {}).items()},
    )
