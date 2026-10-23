"""Condition 1: this public repo carries no team name, app tag, or email of a real person."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
SKIP_FILES = {"test_no_config_in_repo.py"}

# Allowed placeholders: example-team / <team> / your-team, and @example.com addresses.
TEAM_DOMAIN = re.compile(r"([a-z0-9-]+)\.cloudflareaccess\.com", re.IGNORECASE)
ALLOWED_TEAMS = {"example-team", "your-team", "evil"}
EMAIL = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")
ALLOWED_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com"}


def _files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS) and p.name not in SKIP_FILES:
            yield p


def test_no_real_team_domain_or_email_anywhere():
    leaks = []
    for p in _files():
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for m in TEAM_DOMAIN.finditer(text):
            if m.group(1).lower() not in ALLOWED_TEAMS:
                leaks.append(f"{p.relative_to(ROOT)}: {m.group(0)}")
        for m in EMAIL.finditer(text):
            domain = m.group(1).lower()
            if domain not in ALLOWED_EMAIL_DOMAINS and not domain.endswith(".noreply.github.com"):
                leaks.append(f"{p.relative_to(ROOT)}: {m.group(0)}")
    assert leaks == []


# Finding 4: Access AUD tags are 64 hex chars; lockfile hashes are the only allowed ones.
AUD_TAG = re.compile(r"\b[0-9a-f]{64}\b")


def test_no_aud_tag_outside_lockfile_hashes():
    leaks = []
    for p in _files():
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(lines, 1):
            if AUD_TAG.search(line) and not (p.name == "uv.lock" and "sha256:" in line):
                leaks.append(f"{p.relative_to(ROOT)}:{n}")
    assert leaks == []


def test_lockfile_only_uses_public_pypi():
    text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    registries = set(re.findall(r'registry = "([^"]+)"', text))
    assert registries == {"https://pypi.org/simple"}
    assert not re.search(r"https?://[^\s\"]*:[^\s\"]*@", text)  # no credentials in any URL


def test_repo_has_its_own_gitignore():
    # Finding 5: don't rely on the author's global excludes.
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert {".venv/", "__pycache__/", ".pytest_cache/", ".ruff_cache/"} <= set(ignored)
