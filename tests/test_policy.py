"""Tests for the policy DSL and predicates."""

from __future__ import annotations

from capshim.labels import Category, Label
from capshim.policy import policy_from_string


YAML = """
sensitive_paths:
  - "**/.ssh/*"
  - "**/.env"
sensitive_env:
  - "*TOKEN*"
  - "AWS_*"
trusted_hosts:
  - "audit-sink.company.local"
allowed_egress:
  - "api.github.com"
  - "audit-sink.company.local"
declassifications:
  - from: SECRET
    to: PUBLIC
    by: net_http_post
    when: "net.http(audit-sink.company.local)"
"""


def test_sensitive_path_glob():
    p = policy_from_string(YAML)
    assert p.is_sensitive_path("/home/u/.ssh/id_rsa")
    assert p.is_sensitive_path("/srv/app/.env")
    assert not p.is_sensitive_path("/srv/app/README.md")


def test_sensitive_env_glob():
    p = policy_from_string(YAML)
    assert p.is_sensitive_env("GITHUB_TOKEN")
    assert p.is_sensitive_env("AWS_SECRET_ACCESS_KEY")
    assert not p.is_sensitive_env("HOME")


def test_egress_allowlist():
    p = policy_from_string(YAML)
    assert p.is_egress_allowed("api.github.com")
    assert not p.is_egress_allowed("attacker.com")


def test_trusted_host_can_receive_secret():
    p = policy_from_string(YAML)
    assert p.allows_sink(
        "audit-sink.company.local",
        Label.SECRET,
        [Category("fs.read", "/srv/app/.env")],
    )


def test_secret_blocked_at_non_trusted_allowed_host():
    p = policy_from_string(YAML)
    assert not p.allows_sink(
        "api.github.com",
        Label.SECRET,
        [Category("fs.read", "/home/u/.ssh/id_rsa")],
    )


def test_public_data_allowed_at_any_egress():
    p = policy_from_string(YAML)
    assert p.allows_sink("api.github.com", Label.PUBLIC, [])


def test_unknown_host_always_blocked():
    p = policy_from_string(YAML)
    assert not p.allows_sink("attacker.com", Label.PUBLIC, [])


def test_declassification_lookup():
    p = policy_from_string(YAML)
    assert p.declassification_allowed(
        "net_http_post",
        Label.SECRET,
        Label.PUBLIC,
        [Category("net.http", "audit-sink.company.local")],
    )
    assert not p.declassification_allowed(
        "fs_write",
        Label.SECRET,
        Label.PUBLIC,
        [Category("net.http", "audit-sink.company.local")],
    )
