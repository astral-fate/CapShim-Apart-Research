"""Tests for the IFC lattice."""

from __future__ import annotations

from hypothesis import given, strategies as st

from capshim.labels import (
    Category,
    Label,
    Tag,
    category_matches,
    join,
    join_many,
    join_tags,
    leq,
)


# ----- direct tests --------------------------------------------------------


def test_label_order():
    assert leq(Label.PUBLIC, Label.USER)
    assert leq(Label.USER, Label.SECRET)
    assert leq(Label.PUBLIC, Label.SECRET)
    assert not leq(Label.SECRET, Label.USER)
    assert not leq(Label.USER, Label.PUBLIC)


def test_join_is_lub():
    assert join(Label.PUBLIC, Label.SECRET) == Label.SECRET
    assert join(Label.USER, Label.USER) == Label.USER
    assert join(Label.SECRET, Label.PUBLIC) == Label.SECRET


def test_join_many_empty_is_public():
    assert join_many(()) == Label.PUBLIC


def test_category_matches_glob():
    assert category_matches(Category("fs.read", "/etc/passwd"), "fs.read", "*")
    assert category_matches(Category("fs.read", "/x/.ssh/id_rsa"), "fs.read", "*.ssh*")
    assert not category_matches(Category("fs.read", "/etc/passwd"), "fs.write")


def test_tag_addition_is_immutable():
    t = Tag(Label.PUBLIC, frozenset())
    t2 = t.add_category(Category("fs.read", "/x"))
    assert t.categories == frozenset()
    assert Category("fs.read", "/x") in t2.categories


def test_join_tags_unions_categories():
    a = Tag(Label.USER, frozenset({Category("fs.read", "a")}))
    b = Tag(Label.SECRET, frozenset({Category("net.http", "b")}))
    j = join_tags(a, b)
    assert j.label == Label.SECRET
    assert Category("fs.read", "a") in j.categories
    assert Category("net.http", "b") in j.categories


# ----- property-based tests -----------------------------------------------

labels = st.sampled_from([Label.PUBLIC, Label.USER, Label.SECRET])


@given(a=labels, b=labels)
def test_join_is_idempotent_when_equal(a, b):
    if a == b:
        assert join(a, b) == a


@given(a=labels, b=labels)
def test_join_is_commutative(a, b):
    assert join(a, b) == join(b, a)


@given(a=labels, b=labels, c=labels)
def test_join_is_associative(a, b, c):
    assert join(a, join(b, c)) == join(join(a, b), c)


@given(a=labels, b=labels)
def test_join_is_lub_property(a, b):
    j = join(a, b)
    assert leq(a, j)
    assert leq(b, j)


@given(a=labels, b=labels)
def test_leq_transitive_with_join(a, b):
    # x ⊑ y ⇔ join(x, y) = y
    if leq(a, b):
        assert join(a, b) == b
