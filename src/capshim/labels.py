"""IFC lattice for CapShim.

The lattice has three confidentiality levels (Public ⊑ User ⊑ Secret).
Each labeled value also carries a set of tag categories that record
*provenance* — where the value came from. The checker uses categories
to enforce policy that depends not only on level but on origin
(e.g. "data tagged fs.read(~/.ssh/*) cannot reach net.http(*)").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import FrozenSet, Iterable


class Label(IntEnum):
    """Confidentiality lattice. Higher value is more confidential."""

    PUBLIC = 0
    USER = 1
    SECRET = 2

    @classmethod
    def parse(cls, name: str) -> "Label":
        upper = name.strip().upper()
        if upper not in cls.__members__:
            raise ValueError(f"unknown label: {name!r}")
        return cls[upper]


def leq(a: Label, b: Label) -> bool:
    """a ⊑ b ? (i.e. a is no more confidential than b)."""
    return int(a) <= int(b)


def join(a: Label, b: Label) -> Label:
    """Least upper bound on the confidentiality lattice."""
    return a if int(a) >= int(b) else b


def join_many(labels: Iterable[Label]) -> Label:
    out = Label.PUBLIC
    for label in labels:
        out = join(out, label)
    return out


@dataclass(frozen=True)
class Category:
    """A provenance category. `kind` is e.g. "fs.read"; `arg` is the
    concrete resource (path, hostname, env var). `arg` may be a glob.
    """

    kind: str
    arg: str = ""

    def __str__(self) -> str:
        return f"{self.kind}({self.arg})" if self.arg else self.kind


@dataclass(frozen=True)
class Tag:
    """A labeled value's full tag: confidentiality level + provenance categories.

    Tags are immutable; combine via :func:`join_tags`.
    """

    label: Label
    categories: FrozenSet[Category] = field(default_factory=frozenset)

    def with_label(self, new_label: Label) -> "Tag":
        return Tag(label=new_label, categories=self.categories)

    def add_category(self, cat: Category) -> "Tag":
        return Tag(label=self.label, categories=self.categories | {cat})

    def __str__(self) -> str:
        cats = ",".join(sorted(str(c) for c in self.categories)) or "-"
        return f"({self.label.name}, {{{cats}}})"


def join_tags(a: Tag, b: Tag) -> Tag:
    """Combine two tags. Confidentiality is the lattice join; categories union."""
    return Tag(label=join(a.label, b.label), categories=a.categories | b.categories)


PUBLIC = Tag(Label.PUBLIC, frozenset())
USER = Tag(Label.USER, frozenset())
SECRET = Tag(Label.SECRET, frozenset())


def category_matches(c: Category, kind: str, pattern: str = "*") -> bool:
    """True if category `c` is of kind `kind` and its arg matches `pattern`.

    Pattern matching uses fnmatch glob semantics; an empty arg is matched
    only by a literal empty pattern.
    """
    import fnmatch

    if c.kind != kind:
        return False
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(c.arg, pattern)
