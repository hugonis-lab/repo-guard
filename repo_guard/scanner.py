"""Deterministic line-by-line scanner for secrets, private infra, and 12-Factor hygiene."""

from __future__ import annotations

import fnmatch
from functools import lru_cache
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Sequence

from .config import HARD_CEILING_CATEGORIES, GuardConfig
from .emoji import _is_css_path, find_ui_emojis, is_ui_source_path

# Binary extensions skipped for content scanning (filenames are still checked via RG-FILE-001).
BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".ico",
        ".icns",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".pdf",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".zst",
        ".tar",
        ".7z",
        ".rar",
        ".wasm",
        ".o",
        ".a",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".pyc",
        ".pyo",
        ".class",
        ".jar",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".mp3",
        ".mp4",
        ".wav",
        ".ogg",
        ".mov",
        ".avi",
        ".mkv",
        ".flac",
    }
)

# Generic documentation placeholder usernames allowed in /home/<name>/ or /Users/<name>/
# UNLESS that exact username is also in the local machine's configured `usernames`.
GENERIC_PLACEHOLDER_USERS: frozenset[str] = frozenset(
    {
        "user",
        "username",
        "yourname",
        "example",
        "alice",
        "bob",
    }
)

# Allowed template suffixes for .env.* and secrets.* files.
ALLOWED_ENV_SUFFIXES: tuple[str, ...] = (
    ".example",
    ".sample",
    ".template",
    ".dist",
)

# Blocked sensitive filenames (RG-FILE-001).
BLOCKED_EXACT_FILENAMES: frozenset[str] = frozenset(
    {
        ".env",
        "credentials.json",
        "vault.key",
        "vault.enc",
        "queues.json",
    }
)

BLOCKED_EXTENSION_FILENAMES: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".enc",
    }
)

BLOCKED_PREFIX_FILENAMES: tuple[str, ...] = (
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
)

# RFC 5737 documentation IPv4 networks (explicitly allowed).
_DOC_IPV4_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_LOOPBACK_IPV4_NET = ipaddress.IPv4Network("127.0.0.0/8")
_UNSPECIFIED_IPV4_NET = ipaddress.IPv4Network("0.0.0.0/8")
_RFC1918_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network((10 << 24, 8)),
    ipaddress.IPv4Network(((172 << 24) | (16 << 16), 12)),
    ipaddress.IPv4Network(((192 << 24) | (168 << 16), 16)),
)
_CGNAT_NET = ipaddress.IPv4Network(((100 << 24) | (64 << 16), 10))

# Secret regexes (RG-SEC-001..009).
_RE_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_RE_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_RE_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,})\b"
)
_RE_STRIPE_KEY = re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")
_RE_AI_API_KEY = re.compile(
    r"\bsk-(?:ant-[A-Za-z0-9_-]{20,}|proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})\b"
)
_RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_RE_PAN_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z_-])(\d{4}(?:[ -]?\d{4}){2,3}|\d{4}[ -]?\d{6}[ -]?\d{5})(?![0-9A-Za-z_-])"
)

# Hardcoded secret assignment heuristic (RG-SEC-009).
_SECRET_KEY_NAMES = (
    r"(?:[A-Z0-9_]*?(?:API_?KEY|SECRET_?KEY|ACCESS_?SECRET|PRIVATE_?KEY|"
    r"AUTH_?TOKEN|ACCESS_?TOKEN|REFRESH_?TOKEN|BEARER_?TOKEN|CLIENT_?SECRET|"
    r"WEBHOOK_?SECRET|DB_?PASSWORD|PASSWORD|PASSWD|TOKEN|SECRET))"
)
_RE_SECRET_ASSIGN_QUOTED = re.compile(
    rf"""(?i)(?:^|[\s,{{("']){_SECRET_KEY_NAMES}["']?\s*[:=]\s*["']([^"'\n]{{8,}})["']"""
)
_RE_SECRET_ASSIGN_ENV = re.compile(
    rf"""(?i)^(?:\s*export\s+)?{_SECRET_KEY_NAMES}\s*=\s*([^\s"'#`$&;{{]{{8,}})"""
)

_PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "your_",
    "your-",
    "<your",
    "dummy",
    "fake",
    "redacted",
    "xxxx",
    "todo",
    "fixme",
    "unset",
    "not-set",
    "not_set",
    "insert_",
    "enter_",
    "empty",
)

_PLACEHOLDER_PREFIXES: tuple[str, ...] = (
    "$",
    "${",
    "%",
    "{{",
    "<",
    "env:",
    "process.env",
    "os.environ",
    "os.getenv",
    "http://",
    "https://",
    "file://",
    "/",
    "./",
    "../",
    "~/",
    "rg-",
    "re.compile(",
    "regexp(",
    "new regexp(",
)

_RE_ENV_VAR_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_RE_SIMPLE_LOWER_WORD = re.compile(r"^[a-z][a-z0-9_.-]{0,19}$")

# Hardcoded OS home paths (RG-PATH-001).
_RE_HOME_PATH = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:/home/|/Users/)([A-Za-z0-9._-]+)(?=/|\b)|"
    r"[A-Za-z]:[\\/]Users[\\/]([A-Za-z0-9._-]+)(?=[\\/]|\b))"
)

# Tailnet FQDN & IP rules (RG-NET-001..004).
_RE_TS_NET = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.ts\.net)\b", re.IGNORECASE)
_RE_IPV4 = re.compile(r"(?<![0-9A-Za-z._-])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z.])")
_RE_TS_IPV6 = re.compile(r"\b(fd7a:115c:a1e0:[0-9a-fA-F:]+)\b", re.IGNORECASE)
_RE_URL_WITH_PORT = re.compile(
    r"\b(?:https?|wss?)://([A-Za-z0-9._-]+):(\d{2,5})(?=[/\s\"'`):,;?]|$)",
    re.IGNORECASE,
)

_ALLOWED_URL_HOSTS: frozenset[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "example.org",
        "example.net",
        "host.docker.internal",
        "host",
        "hostname",
        "server",
        "target",
        "example",
        "app",
        "web",
        "api",
        "db",
        "redis",
        "postgres",
    }
)
_PRIVATE_TLDS: tuple[str, ...] = (
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".corp",
    ".home.arpa",
)

# Fast prefix-skip prefilter for _RE_PAN_CANDIDATE matching every valid IIN in _is_likely_pan.
_RE_PAN_PREFILTER = re.compile(r"[2-6]\d{3}[ -]?\d{4}")

# O(1) hostname/identity token prefiltering helpers.
_RE_ASCII_HOST_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")
_RE_HOST_TOKEN = re.compile(r"[A-Za-z0-9_-]+")
# Exhaustive set of non-ASCII Unicode codepoints that match ASCII letters under Python re.IGNORECASE
# (U+0130 'İ', U+0131 'ı', U+017F 'ſ', U+212A 'K').
_ASCII_HOST_TOKEN_TRANS: dict[int, str] = {
    c: (chr(c + 32) if 65 <= c <= 90 else " ")
    for c in range(128)
    if not (48 <= c <= 57 or 97 <= c <= 122 or c in (45, 95))
}
_BYTES_HOST_TOKEN_TRANS: bytes = bytes(
    c + 32 if 65 <= c <= 90 else (c if (48 <= c <= 57 or 97 <= c <= 122 or c in (45, 95)) else 32)
    for c in range(256)
)


def _has_unicode_ascii_fold(text: str) -> bool:
    """Return True if non-ASCII text contains any codepoint matching ASCII letters under re.IGNORECASE."""
    return (
        "\u0130" in text
        or "\u0131" in text
        or "\u017f" in text
        or "\u212a" in text
    )
_RE_CTX_CLI_CMD = re.compile(
    r"\b(?:ssh|scp|sftp|rsync|ping|nc|ncat|telnet|curl|wget)\b",
    re.IGNORECASE,
)
_RE_CTX_ASSIGN_KEY = re.compile(
    r"\b(?:host|hostname|server|server_host|endpoint|base_host|target_host|"
    r"remote_host|node|ssh_host|pg_host|db_host|redis_host|ollama_host|vllm_host)\b",
    re.IGNORECASE,
)
_RE_UNIFIED_DIFF_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class Finding:
    """Single deterministic scan violation."""

    rule_id: str
    category: str
    path: str
    line: int
    message: str
    snippet: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet,
            "remediation": self.remediation,
        }


@lru_cache(maxsize=4096)
def is_binary_path(path: str) -> bool:
    """Return True if filename has a known binary extension."""
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in BINARY_EXTENSIONS


def is_binary_bytes(sample: bytes) -> bool:
    """Return True if a byte chunk appears to be binary."""
    return b"\x00" in sample[:8192]


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        d = ord(ch) - 48
        if idx % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_likely_pan(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if len(digits) not in (15, 16) or not digits.isdigit():
        return False
    if len(set(digits)) <= 1:
        return False
    # Check major payment network IIN prefixes to avoid false positives on timestamps/IDs.
    valid_iin = (
        (len(digits) == 16 and digits.startswith("4"))
        or (len(digits) == 16 and 51 <= int(digits[:2]) <= 55)
        or (len(digits) == 16 and 2221 <= int(digits[:4]) <= 2720)
        or (len(digits) == 15 and digits[:2] in ("34", "37"))
        or (len(digits) == 16 and (digits.startswith("6011") or digits.startswith("65")))
    )
    if not valid_iin:
        return False
    return _luhn_valid(digits)


def _is_placeholder_secret(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return True
    # Multi-word English prose / error messages are not secret tokens.
    if " " in stripped:
        return True
    low = stripped.lower()
    if any(low.startswith(pref) for pref in _PLACEHOLDER_PREFIXES):
        return True
    if any(marker in low for marker in _PLACEHOLDER_SUBSTRINGS):
        return True
    # Environment variable names or constant references (e.g., OPENAI_API_KEY).
    if _RE_ENV_VAR_NAME.match(stripped):
        return True
    # Short simple lowercase identifiers without digits (e.g., "authorization", "client_secret").
    if _RE_SIMPLE_LOWER_WORD.match(stripped) and not any(ch.isdigit() for ch in stripped):
        return True
    # Require either >= 12 chars or at least two character classes (letters + digits/symbols).
    has_alpha = any(ch.isalpha() for ch in stripped)
    has_digit = any(ch.isdigit() for ch in stripped)
    has_sym = any(not ch.isalnum() for ch in stripped)
    classes = int(has_alpha) + int(has_digit) + int(has_sym)
    if len(stripped) < 12 and classes < 2:
        return True
    return False


def _redact_snippet(
    line: str,
    start: int,
    end: int,
    *,
    rule_id: str,
    category: str,
) -> str:
    """Build a concise redacted snippet that NEVER echoes full secrets."""
    token = line[start:end]
    if category == "secret":
        replacement = f"<{rule_id}:REDACTED>"
    elif category == "ui_emoji":
        replacement = f"<{rule_id}:{token}>"
    elif len(token) <= 6:
        replacement = f"<{rule_id}:REDACTED>"
    else:
        replacement = f"{token[:2]}***<{rule_id}>***{token[-2:]}"

    left = line[max(0, start - 30) : start]
    right = line[end : min(len(line), end + 30)]
    prefix = "..." if start > 30 else ""
    suffix = "..." if end + 30 < len(line) else ""
    combined = f"{prefix}{left}{replacement}{right}{suffix}"
    return " ".join(combined.strip().split())


def _is_allowed_by_repo_policy(
    config: GuardConfig,
    *,
    category: str,
    rel_path: str,
    matched_text: str,
) -> bool:
    """Check if `.repo-guard.json` may allow a non-ceiling finding."""
    if category in HARD_CEILING_CATEGORIES:
        return False
    policy = config.repo_policy
    if rel_path:
        norm_path = rel_path.replace("\\", "/")
        while norm_path.startswith("./"):
            norm_path = norm_path[2:]
        for pat in policy.allow_paths:
            if fnmatch.fnmatch(norm_path, pat) or fnmatch.fnmatch(PurePosixPath(norm_path).name, pat):
                return True
    if matched_text and policy.allow_terms:
        low_match = matched_text.strip().lower()
        for term in policy.allow_terms:
            if term == low_match or term in low_match:
                return True
    return False


def _compile_identity_pattern(identity: str) -> re.Pattern[str]:
    cleaned = identity.strip()
    if "@" in cleaned or "." in cleaned:
        return re.compile(
            rf"(?<![A-Za-z0-9_.-]){re.escape(cleaned)}(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        )
    if " " in cleaned:
        parts = [re.escape(p) for p in cleaned.split()]
        return re.compile(r"\b" + r"\s+".join(parts) + r"\b", re.IGNORECASE)
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(cleaned)}(?![A-Za-z0-9_-])", re.IGNORECASE)


def _compile_strict_host_pattern(host: str) -> re.Pattern[str]:
    cleaned = host.strip()
    if " " in cleaned:
        parts = [re.escape(p) for p in cleaned.split()]
        return re.compile(r"\b" + r"\s+".join(parts) + r"\b", re.IGNORECASE)
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(cleaned)}(?![A-Za-z0-9_-])", re.IGNORECASE)


def _compile_context_host_patterns(host: str) -> list[re.Pattern[str]]:
    esc = re.escape(host.strip())
    return [
        re.compile(
            rf"\b(?:https?|wss?|ssh|ftp|sftp|tcp|udp|postgres(?:ql)?|mysql|redis|amqp|mongodb(?:\+srv)?)://"
            rf"(?:[^/\s@]+@)?({esc})(?:[:/\s\"'`)]|$)",
            re.IGNORECASE,
        ),
        re.compile(rf"(?<![A-Za-z0-9_.-])({esc}):\d{{2,5}}\b", re.IGNORECASE),
        re.compile(
            rf"(?<![A-Za-z0-9_.-])({esc})\.(?:local|lan|home|internal|corp|ts\.net|home\.arpa)\b",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\b(?:ssh|scp|sftp|rsync|ping|nc|ncat|telnet|curl|wget)\b[^\n]*?"
            rf"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9._-]+@)?({esc})(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        ),
        re.compile(rf"(?<![A-Za-z0-9._-])[A-Za-z0-9._-]+@({esc})(?![A-Za-z0-9_.-])", re.IGNORECASE),
        re.compile(
            rf"\b(?:host|hostname|server|server_host|endpoint|base_host|target_host|"
            rf"remote_host|node|ssh_host|pg_host|db_host|redis_host|ollama_host|vllm_host)\b"
            rf"\s*[:=]\s*[\"']?({esc})[\"']?(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        ),
    ]


@dataclass(frozen=True)
class _ContextHostEntry:
    """Precomputed lookup and literal guards for a single context_hosts rule."""

    order: int
    host: str
    patterns: list[re.Pattern[str]]
    cli_host_re: re.Pattern[str]
    host_lower: str
    is_ascii: bool
    port_needle: str
    tld_needle: str
    at_needle: str


@dataclass(frozen=True)
class _IndexedRule:
    """Order-preserving rule entry for token-indexed or anchor-guarded scanning."""

    order: int
    label: str
    pattern: re.Pattern[str]
    first_anchor: str
    extra_anchors: tuple[str, ...]


def _build_indexed_rules(
    rules: Sequence[tuple[str, re.Pattern[str]]],
    *,
    allow_token_index: Callable[[str], bool],
) -> tuple[dict[str, list[_IndexedRule]], tuple[_IndexedRule, ...]]:
    """Split compiled rules into exact ASCII token-set lookups and anchor-guarded fallbacks."""
    token_map: dict[str, list[_IndexedRule]] = {}
    fallback: list[_IndexedRule] = []
    for order, (label, pat) in enumerate(rules):
        cleaned = label.strip()
        if allow_token_index(cleaned):
            key = cleaned.lower()
            token_map.setdefault(key, []).append(_IndexedRule(order, label, pat, key, ()))
        else:
            if cleaned.isascii():
                if " " in cleaned and "@" not in cleaned and "." not in cleaned:
                    parts = tuple(p.lower() for p in cleaned.split())
                    first_anchor, extra_anchors = parts[0], parts[1:]
                else:
                    first_anchor, extra_anchors = cleaned.lower(), ()
            else:
                first_anchor, extra_anchors = "", ()
            fallback.append(_IndexedRule(order, label, pat, first_anchor, extra_anchors))
    return token_map, tuple(fallback)


def _fallback_matches_text(entry: _IndexedRule, text_lower: str) -> bool:
    """Return True if a fallback rule's literal anchors all appear in lowercased text."""
    fa = entry.first_anchor
    if not fa:
        return True
    if fa not in text_lower:
        return False
    for extra in entry.extra_anchors:
        if extra not in text_lower:
            return False
    return True


def _select_indexed_rules(
    tokens: list[str] | None,
    token_map: dict[str, list[_IndexedRule]],
    fallback: Sequence[_IndexedRule],
    line_lower: str,
    can_anchor: bool,
) -> list[_IndexedRule]:
    """Return all potentially matching rules in original declaration order."""
    candidates: list[_IndexedRule] = []
    if tokens is not None and token_map:
        seen_tok: set[str] | None = None
        for tok in tokens:
            entries = token_map.get(tok)
            if entries is not None:
                if seen_tok is None:
                    seen_tok = {tok}
                elif tok in seen_tok:
                    continue
                else:
                    seen_tok.add(tok)
                candidates.extend(entries)
    if fallback:
        if can_anchor:
            for entry in fallback:
                if _fallback_matches_text(entry, line_lower):
                    candidates.append(entry)
        else:
            candidates.extend(fallback)
    if len(candidates) > 1:
        candidates.sort(key=lambda item: item.order)
    return candidates


@dataclass(slots=True)
class _ScanHints:
    """Sound file-level (or default all-on) prefilter hints for _scan_line_core."""

    check_secrets: bool
    check_pan: bool
    check_secret_assign: bool
    check_home_path: bool
    check_ts_net: bool
    tailnet_domains: tuple[tuple[str, bool, re.Pattern[str]], ...]
    check_ipv4: bool
    check_ts_ipv6: bool
    check_url_port: bool
    watch_tokens: frozenset[str]
    watch_token_tuple: tuple[str, ...] | None
    identity_fallback: tuple[_IndexedRule, ...]
    strict_host_fallback: tuple[_IndexedRule, ...]
    context_host_fallback: tuple[_ContextHostEntry, ...]
    strict_only_fallback: tuple[_IndexedRule, ...]
    extra_term_fallback: tuple[_IndexedRule, ...]
    check_ui: bool
    known_can_anchor: bool


class RepoScanner:
    """Compiled deterministic scanner bound to a GuardConfig."""

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        pats = config.patterns
        self._usernames_lower = {u.lower() for u in pats.usernames}
        self._home_paths = [p.rstrip("/") for p in pats.home_paths if p.strip()]
        self._tailnet_domains = [
            re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(d)}(?![A-Za-z0-9_.-])", re.IGNORECASE)
            for d in pats.tailnet_domains
        ]
        self._tailnet_domain_entries: tuple[tuple[str, bool, re.Pattern[str]], ...] = tuple(
            (d.lower(), d.isascii(), dom_re)
            for d, dom_re in zip(pats.tailnet_domains, self._tailnet_domains)
        )
        self._identity_rules: list[tuple[str, re.Pattern[str]]] = [
            (ident, _compile_identity_pattern(ident))
            for ident in pats.private_identities
            if len(ident.strip()) >= 3
        ]
        self._strict_host_rules: list[tuple[str, re.Pattern[str]]] = [
            (host, _compile_strict_host_pattern(host))
            for host in pats.strict_hosts
            if len(host.strip()) >= 3
        ]
        self._context_host_rules: list[tuple[str, list[re.Pattern[str]]]] = [
            (host, _compile_context_host_patterns(host))
            for host in pats.context_hosts
            if len(host.strip()) >= 3
        ]
        self._strict_only_host_rules: list[tuple[str, re.Pattern[str]]] = [
            (host, _compile_strict_host_pattern(host))
            for host in pats.strict_only_hosts
            if len(host.strip()) >= 3
        ]
        self._extra_terms: list[tuple[str, re.Pattern[str]]] = [
            (term, _compile_strict_host_pattern(term))
            for term in pats.extra_blocked_terms
            if len(term.strip()) >= 3
        ]
        self._all_configured_hosts: set[str] = {
            h.lower()
            for h in (pats.strict_hosts + pats.context_hosts + pats.strict_only_hosts)
        }

        # Precompute O(1) token indices and literal guards preserving exact declaration order.
        is_ascii_host = lambda s: bool(_RE_ASCII_HOST_TOKEN.match(s))
        is_ascii_ident_tok = lambda s: (
            "@" not in s and "." not in s and " " not in s and bool(_RE_ASCII_HOST_TOKEN.match(s))
        )
        self._identity_token_map, self._identity_fallback = _build_indexed_rules(
            self._identity_rules, allow_token_index=is_ascii_ident_tok
        )
        self._strict_host_token_map, self._strict_host_fallback = _build_indexed_rules(
            self._strict_host_rules, allow_token_index=is_ascii_host
        )
        self._strict_only_token_map, self._strict_only_fallback = _build_indexed_rules(
            self._strict_only_host_rules, allow_token_index=is_ascii_host
        )
        self._extra_term_token_map, self._extra_term_fallback = _build_indexed_rules(
            self._extra_terms, allow_token_index=is_ascii_host
        )

        self._context_host_entries: list[_ContextHostEntry] = []
        self._context_host_token_map: dict[str, list[_ContextHostEntry]] = {}
        ctx_fallback: list[_ContextHostEntry] = []
        for order, (host, patterns) in enumerate(self._context_host_rules):
            cleaned = host.strip()
            cleaned_low = cleaned.lower()
            esc = re.escape(cleaned)
            entry = _ContextHostEntry(
                order=order,
                host=host,
                patterns=patterns,
                cli_host_re=re.compile(rf"(?<![A-Za-z0-9_.-])(?:{esc})(?![A-Za-z0-9_.-])", re.IGNORECASE),
                host_lower=cleaned_low,
                is_ascii=cleaned.isascii(),
                port_needle=f"{cleaned_low}:",
                tld_needle=f"{cleaned_low}.",
                at_needle=f"@{cleaned_low}",
            )
            self._context_host_entries.append(entry)
            if is_ascii_host(cleaned):
                self._context_host_token_map.setdefault(cleaned_low, []).append(entry)
            else:
                ctx_fallback.append(entry)

        self._context_host_fallback: tuple[_ContextHostEntry, ...] = tuple(ctx_fallback)
        normal_watch: set[str] = set()
        normal_watch.update(self._identity_token_map)
        normal_watch.update(self._strict_host_token_map)
        normal_watch.update(self._context_host_token_map)
        normal_watch.update(self._extra_term_token_map)
        self._watch_tokens_normal: frozenset[str] = frozenset(normal_watch)
        self._watch_tokens_strict: frozenset[str] = frozenset(normal_watch | set(self._strict_only_token_map))
        self._watch_bytes_normal: frozenset[bytes] = frozenset(t.encode("ascii") for t in self._watch_tokens_normal)
        self._watch_bytes_strict: frozenset[bytes] = frozenset(t.encode("ascii") for t in self._watch_tokens_strict)
        self._has_repo_policy: bool = bool(
            config.repo_policy.allow_paths or config.repo_policy.allow_terms
        )

    def check_filename(self, rel_path: str) -> list[Finding]:
        """Check a repository-relative filename against RG-FILE-001."""
        norm = rel_path.replace("\\", "/")
        while norm.startswith("./"):
            norm = norm[2:]
        name = PurePosixPath(norm).name
        low = name.lower()

        blocked_reason: str | None = None
        if low in BLOCKED_EXACT_FILENAMES:
            blocked_reason = f"Blocked sensitive filename '{name}'"
        elif low.startswith(".env."):
            if not any(low.endswith(suf) for suf in ALLOWED_ENV_SUFFIXES):
                blocked_reason = f"Blocked environment file '{name}' (only .env.example/.sample/.template allowed)"
        elif low.startswith("secrets."):
            if not any(low.endswith(suf) for suf in ALLOWED_ENV_SUFFIXES):
                blocked_reason = f"Blocked secrets file '{name}'"
        elif any(low == pref or low.startswith(pref + ".") or low.startswith(pref + "_") for pref in BLOCKED_PREFIX_FILENAMES):
            if not low.endswith(".pub"):
                blocked_reason = f"Blocked SSH private key filename '{name}'"
        else:
            suffix = PurePosixPath(low).suffix
            if suffix in BLOCKED_EXTENSION_FILENAMES:
                blocked_reason = f"Blocked sensitive key/certificate extension '{suffix}'"

        if not blocked_reason:
            return []

        return [
            Finding(
                rule_id="RG-FILE-001",
                category="secret",
                path=norm,
                line=0,
                message=blocked_reason,
                snippet=f"<RG-FILE-001:{name}>",
                remediation=(
                    "Remove sensitive/runtime file from Git, add it to .gitignore, and "
                    "document placeholders in .env.example (12-Factor Factor III)."
                ),
            )
        ]

    def scan_author_metadata(
        self,
        *,
        commit_sha: str,
        author_name: str,
        author_email: str,
        committer_name: str,
        committer_email: str,
    ) -> list[Finding]:
        """Check commit author/committer identity against private_identities (respecting allow_author_emails)."""
        findings: list[Finding] = []
        allowed_emails = {e.lower() for e in self.config.repo_policy.allow_author_emails}
        entries = [
            ("author_name", author_name, False),
            ("author_email", author_email, True),
            ("committer_name", committer_name, False),
            ("committer_email", committer_email, True),
        ]
        seen: set[tuple[str, str]] = set()
        for label, value, is_email in entries:
            val = value.strip()
            if not val:
                continue
            if is_email and val.lower() in allowed_emails:
                continue
            for ident, pattern in self._identity_rules:
                m = pattern.search(val)
                if m:
                    key = (label, ident.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            rule_id="RG-ID-001",
                            category="personal_identity",
                            path=f"commit:{commit_sha[:12]}:{label}",
                            line=0,
                            message=f"Commit {label} contains private identity pattern",
                            snippet=_redact_snippet(
                                val,
                                m.start(),
                                m.end(),
                                rule_id="RG-ID-001",
                                category="personal_identity",
                            ),
                            remediation=(
                                "Set a public/noreply git user.name and user.email for open-source repos, "
                                "or explicitly allow the email in .repo-guard.json allow_author_emails."
                            ),
                        )
                    )
        return findings

    def _scan_context_host_entry(
        self,
        entry: _ContextHostEntry,
        line: str,
        line_lower: str,
        can_anchor: bool,
        has_url_sep: bool,
        has_assign_punct: bool,
        emit: Callable[..., None],
    ) -> None:
        """Evaluate the 6 context-host patterns for one host with O(N) literal pre-guards."""
        host = entry.host
        pats = entry.patterns
        entry_anchor = can_anchor and entry.is_ascii

        def emit_ctx(m: re.Match[str]) -> None:
            start = m.start(1) if m.lastindex else m.start()
            end = m.end(1) if m.lastindex else m.end()
            emit(
                "RG-HOST-002",
                "private_host_context",
                start,
                end,
                "Private hostname used in network/host configuration context",
                "Replace hardcoded host reference with an environment variable or 127.0.0.1/example.com placeholder (12-Factor III & IV).",
                matched_override=host,
            )

        # pat[0]: scheme://...@host...
        if has_url_sep:
            matched = False
            for m in pats[0].finditer(line):
                emit_ctx(m)
                matched = True
            if matched:
                return

        # pat[1]: host:port
        if (not entry_anchor) or (entry.port_needle in line_lower):
            matched = False
            for m in pats[1].finditer(line):
                emit_ctx(m)
                matched = True
            if matched:
                return

        # pat[2]: host.<private-tld>
        if (not entry_anchor) or (entry.tld_needle in line_lower):
            matched = False
            for m in pats[2].finditer(line):
                emit_ctx(m)
                matched = True
            if matched:
                return

        # pat[3]: ssh/scp/curl/... host (guarded so repeated CLI words without host stay O(N))
        m_cmd = _RE_CTX_CLI_CMD.search(line)
        if m_cmd is not None and entry.cli_host_re.search(line, m_cmd.end()) is not None:
            matched = False
            pos = m_cmd.start()
            while True:
                m = pats[3].search(line, pos)
                if m is None:
                    break
                emit_ctx(m)
                matched = True
                pos = m.end()
                next_cmd = _RE_CTX_CLI_CMD.search(line, pos)
                if next_cmd is None or entry.cli_host_re.search(line, next_cmd.end()) is None:
                    break
                pos = next_cmd.start()
            if matched:
                return

        # pat[4]: user@host
        if "@" in line and ((not entry_anchor) or (entry.at_needle in line_lower)):
            matched = False
            for m in pats[4].finditer(line):
                emit_ctx(m)
                matched = True
            if matched:
                return

        # pat[5]: host_key = host
        if has_assign_punct and _RE_CTX_ASSIGN_KEY.search(line) is not None:
            for m in pats[5].finditer(line):
                emit_ctx(m)

    def _scan_indexed_bucket(
        self,
        *,
        line: str,
        line_lower: str,
        can_anchor: bool,
        active_tokens: list[str] | None,
        all_rules: Sequence[tuple[str, re.Pattern[str]]],
        token_map: dict[str, list[_IndexedRule]],
        fallback: Sequence[_IndexedRule],
        rule_id: str,
        category: str,
        message: str,
        remediation: str,
        emit: Callable[..., None],
    ) -> None:
        """Scan a token-indexed + anchor-guarded rule bucket preserving exact declaration order."""
        if not can_anchor:
            for label, pat in all_rules:
                for m in pat.finditer(line):
                    emit(rule_id, category, m.start(), m.end(), message, remediation, matched_override=label)
            return
        if active_tokens is None:
            for rule in fallback:
                if _fallback_matches_text(rule, line_lower):
                    for m in rule.pattern.finditer(line):
                        emit(rule_id, category, m.start(), m.end(), message, remediation, matched_override=rule.label)
            return
        for rule in _select_indexed_rules(active_tokens, token_map, fallback, line_lower, True):
            for m in rule.pattern.finditer(line):
                emit(rule_id, category, m.start(), m.end(), message, remediation, matched_override=rule.label)

    def _emit_finding(
        self,
        findings: list[Finding],
        seen_keys: set[tuple[str, int]],
        rel_path: str,
        line_no: int,
        line: str,
        rule_id: str,
        category: str,
        start: int,
        end: int,
        message: str,
        remediation: str,
        matched_override: str | None = None,
    ) -> None:
        if self._has_repo_policy and category not in HARD_CEILING_CATEGORIES:
            matched_text = matched_override if matched_override is not None else line[start:end]
            if _is_allowed_by_repo_policy(
                self.config,
                category=category,
                rel_path=rel_path,
                matched_text=matched_text,
            ):
                return
        dedup_key = (rule_id, start)
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)
        findings.append(
            Finding(
                rule_id=rule_id,
                category=category,
                path=rel_path,
                line=line_no,
                message=message,
                snippet=_redact_snippet(
                    line,
                    start,
                    end,
                    rule_id=rule_id,
                    category=category,
                ),
                remediation=remediation,
            )
        )

    def _scan_line_core(
        self,
        rel_path: str,
        line_no: int,
        line: str,
        hints: _ScanHints,
    ) -> list[Finding]:
        """Core single-line scanner parameterized by sound file-level or default hints."""
        if not line or line.isspace():
            return []

        findings: list[Finding] | None = None
        seen_keys: set[tuple[str, int]] | None = None
        emit_fn = self._emit_finding

        def emit(
            rule_id: str,
            category: str,
            start: int,
            end: int,
            message: str,
            remediation: str,
            matched_override: str | None = None,
        ) -> None:
            nonlocal findings, seen_keys
            if findings is None:
                findings = []
                seen_keys = set()
            assert seen_keys is not None
            emit_fn(
                findings,
                seen_keys,
                rel_path,
                line_no,
                line,
                rule_id,
                category,
                start,
                end,
                message,
                remediation,
                matched_override,
            )

        is_ascii = line.isascii()
        can_anchor = hints.known_can_anchor or is_ascii or (not _has_unicode_ascii_fold(line))
        line_lower = ""

        has_colon = ":" in line
        has_eq = "=" in line
        has_assign_punct = has_eq or has_colon
        has_url_sep = has_colon and ("://" in line)
        has_dot = "." in line

        # 1. Secrets & Credentials (RG-SEC-001..009) — HARD CEILING
        if hints.check_secrets:
            if "PRIVATE KEY-----" in line:
                for m in _RE_PRIVATE_KEY.finditer(line):
                    emit(
                        "RG-SEC-001",
                        "secret",
                        m.start(),
                        m.end(),
                        "Private key block header detected",
                        "Remove private key material from source; load via env var or secret manager (12-Factor III).",
                    )
            if "AKIA" in line or "ASIA" in line:
                for m in _RE_AWS_KEY.finditer(line):
                    emit(
                        "RG-SEC-002",
                        "secret",
                        m.start(),
                        m.end(),
                        "AWS access key ID detected",
                        "Remove AWS key; authenticate via IAM role or environment variables (12-Factor III).",
                    )
            if "_" in line and (
                "ghp_" in line
                or "gho_" in line
                or "ghu_" in line
                or "ghs_" in line
                or "ghr_" in line
                or "github_pat_" in line
            ):
                for m in _RE_GITHUB_TOKEN.finditer(line):
                    emit(
                        "RG-SEC-003",
                        "secret",
                        m.start(),
                        m.end(),
                        "GitHub personal/app token detected",
                        "Remove GitHub token; read from GITHUB_TOKEN environment variable (12-Factor III).",
                    )
            if "k_live_" in line or "k_test_" in line:
                for m in _RE_STRIPE_KEY.finditer(line):
                    emit(
                        "RG-SEC-004",
                        "secret",
                        m.start(),
                        m.end(),
                        "Stripe API key detected",
                        "Remove Stripe key; inject via STRIPE_SECRET_KEY environment variable (12-Factor III).",
                    )
            if "sk-" in line:
                for m in _RE_AI_API_KEY.finditer(line):
                    emit(
                        "RG-SEC-005",
                        "secret",
                        m.start(),
                        m.end(),
                        "OpenAI/Anthropic API key detected",
                        "Remove LLM API key; load from environment variable (12-Factor III).",
                    )
            if "xox" in line:
                for m in _RE_SLACK_TOKEN.finditer(line):
                    emit(
                        "RG-SEC-006",
                        "secret",
                        m.start(),
                        m.end(),
                        "Slack token detected",
                        "Remove Slack token; inject via environment variable (12-Factor III).",
                    )
            if "eyJ" in line:
                for m in _RE_JWT.finditer(line):
                    emit(
                        "RG-SEC-007",
                        "secret",
                        m.start(),
                        m.end(),
                        "JSON Web Token (JWT) detected",
                        "Remove hardcoded JWT; issue or fetch tokens dynamically at runtime.",
                    )

        if hints.check_pan and len(line) >= 15 and _RE_PAN_PREFILTER.search(line) is not None:
            for m in _RE_PAN_CANDIDATE.finditer(line):
                raw_pan = m.group(1)
                if _is_likely_pan(raw_pan):
                    emit(
                        "RG-SEC-008",
                        "secret",
                        m.start(1),
                        m.end(1),
                        "Luhn-valid payment card number (PAN) detected",
                        "Remove payment card numbers immediately; never commit PANs to source or tests.",
                    )

        # RG-SEC-009: Hardcoded non-placeholder secret assignment
        if hints.check_secret_assign and has_assign_punct:
            if not line_lower:
                line_lower = line.lower()
            if (
                (not can_anchor)
                or "key" in line_lower
                or "secret" in line_lower
                or "token" in line_lower
                or "passw" in line_lower
            ):
                if '"' in line or "'" in line:
                    for m in _RE_SECRET_ASSIGN_QUOTED.finditer(line):
                        val = m.group(1)
                        if not _is_placeholder_secret(val):
                            emit(
                                "RG-SEC-009",
                                "secret",
                                m.start(1),
                                m.end(1),
                                "Hardcoded non-placeholder secret assignment detected",
                                "Load secrets from environment variables and commit only placeholder templates in .env.example (12-Factor III).",
                            )
                if has_eq:
                    for m in _RE_SECRET_ASSIGN_ENV.finditer(line):
                        val = m.group(1)
                        if not _is_placeholder_secret(val):
                            emit(
                                "RG-SEC-009",
                                "secret",
                                m.start(1),
                                m.end(1),
                                "Hardcoded non-placeholder secret assignment detected",
                                "Load secrets from environment variables and commit only placeholder templates in .env.example (12-Factor III).",
                            )

        # 2. Hardcoded Home / OS Paths (RG-PATH-001) — HARD CEILING
        if hints.check_home_path:
            path_matched_spans: set[tuple[int, int]] | None = None
            if "/home/" in line or "Users" in line:
                for m in _RE_HOME_PATH.finditer(line):
                    user_part = (m.group(1) or m.group(2) or "").strip()
                    low_user = user_part.lower()
                    is_local_user = low_user in self._usernames_lower
                    is_generic_placeholder = low_user in GENERIC_PLACEHOLDER_USERS and not is_local_user
                    if not is_generic_placeholder:
                        if path_matched_spans is None:
                            path_matched_spans = set()
                        path_matched_spans.add((m.start(), m.end()))
                        emit(
                            "RG-PATH-001",
                            "home_path",
                            m.start(),
                            m.end(),
                            "Hardcoded user home directory path detected (violates 12-Factor III)",
                            "Use Path.home(), os.homedir(), $HOME, or $XDG_CONFIG_HOME instead of hardcoded user paths.",
                        )

            for hp in self._home_paths:
                idx = line.find(hp)
                while idx != -1:
                    span = (idx, idx + len(hp))
                    if path_matched_spans is None or not any(s <= span[0] and e >= span[1] for s, e in path_matched_spans):
                        emit(
                            "RG-PATH-001",
                            "home_path",
                            span[0],
                            span[1],
                            "Hardcoded local $HOME path detected (violates 12-Factor III)",
                            "Use Path.home(), os.homedir(), $HOME, or $XDG_CONFIG_HOME instead of hardcoded user paths.",
                        )
                    idx = line.find(hp, idx + len(hp))

        # 3. Tailnet FQDNs (RG-NET-001) — HARD CEILING
        if hints.check_ts_net and has_dot:
            if not line_lower:
                line_lower = line.lower()
            if (not can_anchor) or (".ts.net" in line_lower):
                for m in _RE_TS_NET.finditer(line):
                    emit(
                        "RG-NET-001",
                        "tailnet_fqdn",
                        m.start(1),
                        m.end(1),
                        "Tailnet *.ts.net FQDN detected",
                        "Replace hardcoded tailnet FQDN with a configurable service URL env var (12-Factor III & IV).",
                    )
        if hints.tailnet_domains:
            if not line_lower:
                line_lower = line.lower()
            for dom_low, dom_is_ascii, dom_re in hints.tailnet_domains:
                if can_anchor and dom_is_ascii and dom_low not in line_lower:
                    continue
                for m in dom_re.finditer(line):
                    emit(
                        "RG-NET-001",
                        "tailnet_fqdn",
                        m.start(),
                        m.end(),
                        "Configured private tailnet domain detected",
                        "Replace hardcoded tailnet domain with a configurable service URL env var (12-Factor III & IV).",
                    )

        # 4. Private LAN & CGNAT IPs (RG-NET-002, RG-NET-003) — HARD CEILING
        if hints.check_ipv4 and has_dot and (
            "10." in line or "172." in line or "192.168." in line or "100." in line
        ) and line.count(".") >= 3:
            for m in _RE_IPV4.finditer(line):
                raw_ip = m.group(1)
                try:
                    addr = ipaddress.IPv4Address(raw_ip)
                except ipaddress.AddressValueError:
                    continue
                if addr in _LOOPBACK_IPV4_NET or addr in _UNSPECIFIED_IPV4_NET:
                    continue
                if any(addr in net for net in _DOC_IPV4_NETS):
                    continue
                if any(addr in net for net in _RFC1918_NETS):
                    emit(
                        "RG-NET-002",
                        "private_ip",
                        m.start(1),
                        m.end(1),
                        "RFC 1918 private LAN IPv4 address detected",
                        "Replace hardcoded LAN IP with 127.0.0.1, an RFC 5737 doc IP (192.0.2.1), or an env var (12-Factor III & IV).",
                    )
                elif addr in _CGNAT_NET:
                    emit(
                        "RG-NET-003",
                        "private_ip",
                        m.start(1),
                        m.end(1),
                        "Tailscale/CGNAT IPv4 address (100.64/10) detected",
                        "Replace hardcoded tailnet IP with a configurable env var (12-Factor III & IV).",
                    )

        if hints.check_ts_ipv6 and has_colon:
            if not line_lower:
                line_lower = line.lower()
            if (not can_anchor) or ("fd7a:115c:a1e0:" in line_lower):
                for m in _RE_TS_IPV6.finditer(line):
                    emit(
                        "RG-NET-003",
                        "private_ip",
                        m.start(1),
                        m.end(1),
                        "Tailscale ULA IPv6 address detected",
                        "Replace hardcoded tailnet IPv6 address with a configurable env var (12-Factor III & IV).",
                    )

        # 5. Hardcoded non-loopback private http(s)/ws(s)://<host>:<port> URLs (RG-NET-004)
        if hints.check_url_port and has_url_sep:
            for m in _RE_URL_WITH_PORT.finditer(line):
                host = m.group(1).lower()
                if host in _ALLOWED_URL_HOSTS or host.endswith(".example") or host.endswith(".example.com"):
                    continue
                if host.endswith(".ts.net"):
                    continue  # Already caught by RG-NET-001.
                # Skip raw IPs (already handled by RG-NET-002/003 or allowed loopback/doc IP).
                try:
                    ipaddress.IPv4Address(host)
                    continue
                except ipaddress.AddressValueError:
                    pass
                is_private_url_host = (
                    host in self._all_configured_hosts
                    or any(host.endswith(tld) for tld in _PRIVATE_TLDS)
                    or "." not in host
                )
                if is_private_url_host:
                    emit(
                        "RG-NET-004",
                        "private_url",
                        m.start(),
                        m.end(),
                        "Hardcoded non-loopback internal service URL with port detected",
                        "Inject backing-service URLs via env vars (e.g., API_BASE_URL), defaulting only to http://127.0.0.1:<port> (12-Factor IV).",
                        matched_override=host,
                    )

        # Tokenize once for O(1) lookup across identities, strict/context/strict-only hosts, and extra terms.
        active_tokens: list[str] | None = None
        if can_anchor and hints.watch_tokens:
            may_have_token = True
            tok_tuple = hints.watch_token_tuple
            if tok_tuple is not None:
                if not line_lower:
                    line_lower = line.lower()
                may_have_token = False
                for tok_needle in tok_tuple:
                    if tok_needle in line_lower:
                        may_have_token = True
                        break
            if may_have_token:
                if is_ascii:
                    raw_tokens = line.translate(_ASCII_HOST_TOKEN_TRANS).split()
                else:
                    if not line_lower:
                        line_lower = line.lower()
                    raw_tokens = _RE_HOST_TOKEN.findall(line_lower)
                if not hints.watch_tokens.isdisjoint(raw_tokens):
                    active_tokens = raw_tokens

        # 6. Personal Identity Patterns (RG-ID-001) — HARD CEILING
        if (not can_anchor) or active_tokens is not None or hints.identity_fallback:
            if not line_lower:
                line_lower = line.lower()
            self._scan_indexed_bucket(
                line=line,
                line_lower=line_lower,
                can_anchor=can_anchor,
                active_tokens=active_tokens,
                all_rules=self._identity_rules,
                token_map=self._identity_token_map,
                fallback=hints.identity_fallback,
                rule_id="RG-ID-001",
                category="personal_identity",
                message="Private personal identity/handle/domain detected",
                remediation="Remove personal names, handles, emails, and private domains from open-source files.",
                emit=emit,
            )

        # 7. Private Hostnames (RG-HOST-001, RG-HOST-002, RG-HOST-003)
        if (not can_anchor) or active_tokens is not None or hints.strict_host_fallback:
            if not line_lower:
                line_lower = line.lower()
            self._scan_indexed_bucket(
                line=line,
                line_lower=line_lower,
                can_anchor=can_anchor,
                active_tokens=active_tokens,
                all_rules=self._strict_host_rules,
                token_map=self._strict_host_token_map,
                fallback=hints.strict_host_fallback,
                rule_id="RG-HOST-001",
                category="private_host",
                message="Private infrastructure hostname detected",
                remediation="Remove machine-specific hostname; configure host via environment variable (12-Factor III & IV).",
                emit=emit,
            )

        if not can_anchor:
            if not line_lower:
                line_lower = line.lower()
            for entry in self._context_host_entries:
                self._scan_context_host_entry(
                    entry, line, line_lower, False, has_url_sep, has_assign_punct, emit
                )
        elif active_tokens is not None or hints.context_host_fallback:
            if not line_lower:
                line_lower = line.lower()
            ctx_candidates: list[_ContextHostEntry] = []
            if active_tokens is not None and self._context_host_token_map:
                seen_ctx_tok: set[str] | None = None
                for tok in active_tokens:
                    entries = self._context_host_token_map.get(tok)
                    if entries is not None:
                        if seen_ctx_tok is None:
                            seen_ctx_tok = {tok}
                        elif tok in seen_ctx_tok:
                            continue
                        else:
                            seen_ctx_tok.add(tok)
                        ctx_candidates.extend(entries)
            if hints.context_host_fallback:
                for entry in hints.context_host_fallback:
                    if (not entry.is_ascii) or (entry.host_lower in line_lower):
                        ctx_candidates.append(entry)
            if len(ctx_candidates) > 1:
                ctx_candidates.sort(key=lambda item: item.order)
            for entry in ctx_candidates:
                self._scan_context_host_entry(
                    entry, line, line_lower, True, has_url_sep, has_assign_punct, emit
                )

        if self.config.strict and ((not can_anchor) or active_tokens is not None or hints.strict_only_fallback):
            if not line_lower:
                line_lower = line.lower()
            self._scan_indexed_bucket(
                line=line,
                line_lower=line_lower,
                can_anchor=can_anchor,
                active_tokens=active_tokens,
                all_rules=self._strict_only_host_rules,
                token_map=self._strict_only_token_map,
                fallback=hints.strict_only_fallback,
                rule_id="RG-HOST-003",
                category="private_host_strict",
                message="Local infrastructure hostname detected in --strict OSS mode",
                remediation="Remove environment-specific node references before open-sourcing (12-Factor III).",
                emit=emit,
            )

        if (not can_anchor) or active_tokens is not None or hints.extra_term_fallback:
            if not line_lower:
                line_lower = line.lower()
            self._scan_indexed_bucket(
                line=line,
                line_lower=line_lower,
                can_anchor=can_anchor,
                active_tokens=active_tokens,
                all_rules=self._extra_terms,
                token_map=self._extra_term_token_map,
                fallback=hints.extra_term_fallback,
                rule_id="RG-HOST-001",
                category="private_host",
                message="Blocked private term detected",
                remediation="Remove environment-specific identifier from repository.",
                emit=emit,
            )

        # 8. User-Facing UI Emoji Guard (RG-UI-001)
        if hints.check_ui:
            for em in find_ui_emojis(line, rel_path):
                emit(
                    "RG-UI-001",
                    "ui_emoji",
                    em.start,
                    em.end,
                    f"Emoji detected in user-facing UI source ({em.codepoints}, {em.kind})",
                    "Remove emoji from user-facing UI; use crisp monochrome inline SVG icons or plain typography instead.",
                    matched_override=em.codepoints,
                )

        return findings if findings is not None else []

    def scan_line(self, rel_path: str, line_no: int, line: str) -> list[Finding]:
        """Scan a single line and return all deterministic findings."""
        watch_tokens = self._watch_tokens_strict if self.config.strict else self._watch_tokens_normal
        hints = _ScanHints(
            check_secrets=True,
            check_pan=True,
            check_secret_assign=True,
            check_home_path=True,
            check_ts_net=True,
            tailnet_domains=self._tailnet_domain_entries,
            check_ipv4=True,
            check_ts_ipv6=True,
            check_url_port=True,
            watch_tokens=watch_tokens,
            watch_token_tuple=None,
            identity_fallback=self._identity_fallback,
            strict_host_fallback=self._strict_host_fallback,
            context_host_fallback=self._context_host_fallback,
            strict_only_fallback=self._strict_only_fallback,
            extra_term_fallback=self._extra_term_fallback,
            check_ui=is_ui_source_path(rel_path),
            known_can_anchor=False,
        )
        return self._scan_line_core(rel_path, line_no, line, hints)

    def scan_text(self, rel_path: str, text: str) -> list[Finding]:
        """Scan multi-line text content line by line with sound file-level prefiltering."""
        if not text:
            return []

        is_ascii = text.isascii()
        if not is_ascii and _has_unicode_ascii_fold(text):
            findings: list[Finding] = []
            for idx, line in enumerate(text.splitlines(), start=1):
                findings.extend(self.scan_line(rel_path, idx, line))
            return findings

        text_lower = text.lower()
        check_secrets = (
            "PRIVATE KEY-----" in text
            or "AKIA" in text
            or "ASIA" in text
            or (
                "_" in text
                and (
                    "ghp_" in text
                    or "gho_" in text
                    or "ghu_" in text
                    or "ghs_" in text
                    or "ghr_" in text
                    or "github_pat_" in text
                )
            )
            or "k_live_" in text
            or "k_test_" in text
            or "sk-" in text
            or "xox" in text
            or "eyJ" in text
        )
        check_pan = len(text) >= 15 and (_RE_PAN_PREFILTER.search(text) is not None)
        check_secret_assign = ("=" in text or ":" in text) and (
            "key" in text_lower
            or "secret" in text_lower
            or "token" in text_lower
            or "passw" in text_lower
        )
        check_home_path = (
            "/home/" in text
            or "Users" in text
            or any(hp in text for hp in self._home_paths)
        )
        check_ts_net = ".ts.net" in text_lower
        tailnet_domains = tuple(
            entry
            for entry in self._tailnet_domain_entries
            if (not entry[1]) or (entry[0] in text_lower)
        )
        check_ipv4 = "." in text and (
            "10." in text or "172." in text or "192.168." in text or "100." in text
        )
        check_ts_ipv6 = "fd7a:115c:a1e0:" in text_lower
        check_url_port = "://" in text

        watch_bytes = self._watch_bytes_strict if self.config.strict else self._watch_bytes_normal
        if watch_bytes:
            # Non-ASCII chars are replaced with b'?' (outside [A-Za-z0-9_-]) and split identically to ASCII tokens.
            raw_bytes = text.encode("ascii", "replace")
            matched_bytes = watch_bytes.intersection(raw_bytes.translate(_BYTES_HOST_TOKEN_TRANS).split())
            file_watch_tokens = frozenset(b.decode("ascii") for b in matched_bytes)
        else:
            file_watch_tokens = frozenset()
        watch_token_tuple = tuple(file_watch_tokens) if 0 < len(file_watch_tokens) <= 8 else None

        identity_fallback = tuple(
            r for r in self._identity_fallback if _fallback_matches_text(r, text_lower)
        )
        strict_host_fallback = tuple(
            r for r in self._strict_host_fallback if _fallback_matches_text(r, text_lower)
        )
        context_host_fallback = tuple(
            e for e in self._context_host_fallback if (not e.is_ascii) or (e.host_lower in text_lower)
        )
        strict_only_fallback = (
            tuple(r for r in self._strict_only_fallback if _fallback_matches_text(r, text_lower))
            if self.config.strict
            else ()
        )
        extra_term_fallback = tuple(
            r for r in self._extra_term_fallback if _fallback_matches_text(r, text_lower)
        )
        check_ui = is_ui_source_path(rel_path) and (
            (not is_ascii)
            or "&#" in text
            or "\\u" in text
            or ("\\" in text and _is_css_path(rel_path))
        )

        if not (
            check_secrets
            or check_pan
            or check_secret_assign
            or check_home_path
            or check_ts_net
            or tailnet_domains
            or check_ipv4
            or check_ts_ipv6
            or check_url_port
            or file_watch_tokens
            or identity_fallback
            or strict_host_fallback
            or context_host_fallback
            or strict_only_fallback
            or extra_term_fallback
            or check_ui
        ):
            return []

        hints = _ScanHints(
            check_secrets=check_secrets,
            check_pan=check_pan,
            check_secret_assign=check_secret_assign,
            check_home_path=check_home_path,
            check_ts_net=check_ts_net,
            tailnet_domains=tailnet_domains,
            check_ipv4=check_ipv4,
            check_ts_ipv6=check_ts_ipv6,
            check_url_port=check_url_port,
            watch_tokens=file_watch_tokens,
            watch_token_tuple=watch_token_tuple,
            identity_fallback=identity_fallback,
            strict_host_fallback=strict_host_fallback,
            context_host_fallback=context_host_fallback,
            strict_only_fallback=strict_only_fallback,
            extra_term_fallback=extra_term_fallback,
            check_ui=check_ui,
            known_can_anchor=True,
        )

        findings = []
        scan_core = self._scan_line_core
        for idx, line in enumerate(text.splitlines(), start=1):
            line_hits = scan_core(rel_path, idx, line, hints)
            if line_hits:
                findings.extend(line_hits)
        return findings

    def scan_file(self, root: Path, rel_path: str) -> list[Finding]:
        """Scan a single repository file (filename + text content if non-binary)."""
        findings = self.check_filename(rel_path)
        if is_binary_path(rel_path):
            return findings
        full_path = root / rel_path
        if not full_path.is_file():
            return findings
        try:
            raw = full_path.read_bytes()
        except OSError:
            return findings
        if is_binary_bytes(raw):
            return findings
        text = raw.decode("utf-8", errors="replace")
        findings.extend(self.scan_text(rel_path, text))
        return findings

    def scan_unified_diff(self, diff_text: str) -> list[Finding]:
        """Scan added lines (`+...`) from a `git diff -U0` output."""
        findings: list[Finding] = []
        current_path = ""
        current_line = 0
        hunk_re = _RE_UNIFIED_DIFF_HUNK

        for raw_line in diff_text.splitlines():
            if raw_line.startswith("+++ "):
                target = raw_line[4:].strip()
                if target == "/dev/null":
                    current_path = ""
                elif target.startswith("b/"):
                    current_path = target[2:]
                else:
                    current_path = target
                # Unquote C-escaped git paths if wrapped in quotes.
                if len(current_path) >= 2 and current_path[0] == '"' and current_path[-1] == '"':
                    current_path = current_path[1:-1]
                current_line = 0
                continue

            if raw_line.startswith("@@ "):
                m = hunk_re.match(raw_line)
                if m:
                    current_line = int(m.group(1))
                continue

            if not current_path or is_binary_path(current_path):
                continue

            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                added_content = raw_line[1:]
                findings.extend(self.scan_line(current_path, current_line, added_content))
                current_line += 1
            elif raw_line.startswith(" "):
                current_line += 1

        return findings


def scan_commit_message(scanner: RepoScanner, message_text: str, source_label: str = "COMMIT_EDITMSG") -> list[Finding]:
    """Scan commit message text while skipping Git comment lines starting with '#'."""
    findings: list[Finding] = []
    for idx, line in enumerate(message_text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        findings.extend(scanner.scan_line(source_label, idx, line))
    return findings


def summarize_findings(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings grouped by rule_id."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    return dict(sorted(counts.items()))
