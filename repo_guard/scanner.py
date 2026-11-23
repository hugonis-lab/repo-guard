"""Deterministic line-by-line scanner for secrets, private infra, and 12-Factor hygiene."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

from .config import HARD_CEILING_CATEGORIES, GuardConfig
from .emoji import find_ui_emojis, is_ui_source_path

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
        re.compile(rf"[A-Za-z0-9._-]+@({esc})(?![A-Za-z0-9_.-])", re.IGNORECASE),
        re.compile(
            rf"\b(?:host|hostname|server|server_host|endpoint|base_host|target_host|"
            rf"remote_host|node|ssh_host|pg_host|db_host|redis_host|ollama_host|vllm_host)\b"
            rf"\s*[:=]\s*[\"']?({esc})[\"']?(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        ),
    ]


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

    def scan_line(self, rel_path: str, line_no: int, line: str) -> list[Finding]:
        """Scan a single line and return all deterministic findings."""
        if not line or not line.strip():
            return []

        findings: list[Finding] = []
        seen_keys: set[tuple[str, int]] = set()

        def emit(
            rule_id: str,
            category: str,
            start: int,
            end: int,
            message: str,
            remediation: str,
            matched_override: str | None = None,
        ) -> None:
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

        # 1. Secrets & Credentials (RG-SEC-001..009) — HARD CEILING
        secret_specs: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
            (
                "RG-SEC-001",
                _RE_PRIVATE_KEY,
                "Private key block header detected",
                "Remove private key material from source; load via env var or secret manager (12-Factor III).",
            ),
            (
                "RG-SEC-002",
                _RE_AWS_KEY,
                "AWS access key ID detected",
                "Remove AWS key; authenticate via IAM role or environment variables (12-Factor III).",
            ),
            (
                "RG-SEC-003",
                _RE_GITHUB_TOKEN,
                "GitHub personal/app token detected",
                "Remove GitHub token; read from GITHUB_TOKEN environment variable (12-Factor III).",
            ),
            (
                "RG-SEC-004",
                _RE_STRIPE_KEY,
                "Stripe API key detected",
                "Remove Stripe key; inject via STRIPE_SECRET_KEY environment variable (12-Factor III).",
            ),
            (
                "RG-SEC-005",
                _RE_AI_API_KEY,
                "OpenAI/Anthropic API key detected",
                "Remove LLM API key; load from environment variable (12-Factor III).",
            ),
            (
                "RG-SEC-006",
                _RE_SLACK_TOKEN,
                "Slack token detected",
                "Remove Slack token; inject via environment variable (12-Factor III).",
            ),
            (
                "RG-SEC-007",
                _RE_JWT,
                "JSON Web Token (JWT) detected",
                "Remove hardcoded JWT; issue or fetch tokens dynamically at runtime.",
            ),
        )
        for rule_id, pat, msg, hint in secret_specs:
            for m in pat.finditer(line):
                emit(rule_id, "secret", m.start(), m.end(), msg, hint)

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
        for assign_re in (_RE_SECRET_ASSIGN_QUOTED, _RE_SECRET_ASSIGN_ENV):
            for m in assign_re.finditer(line):
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
        path_matched_spans: set[tuple[int, int]] = set()
        for m in _RE_HOME_PATH.finditer(line):
            user_part = (m.group(1) or m.group(2) or "").strip()
            low_user = user_part.lower()
            is_local_user = low_user in self._usernames_lower
            is_generic_placeholder = low_user in GENERIC_PLACEHOLDER_USERS and not is_local_user
            if not is_generic_placeholder:
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
                if not any(s <= span[0] and e >= span[1] for s, e in path_matched_spans):
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
        for m in _RE_TS_NET.finditer(line):
            emit(
                "RG-NET-001",
                "tailnet_fqdn",
                m.start(1),
                m.end(1),
                "Tailnet *.ts.net FQDN detected",
                "Replace hardcoded tailnet FQDN with a configurable service URL env var (12-Factor III & IV).",
            )
        for dom_re in self._tailnet_domains:
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

        # 6. Personal Identity Patterns (RG-ID-001) — HARD CEILING
        for ident, pat in self._identity_rules:
            for m in pat.finditer(line):
                emit(
                    "RG-ID-001",
                    "personal_identity",
                    m.start(),
                    m.end(),
                    "Private personal identity/handle/domain detected",
                    "Remove personal names, handles, emails, and private domains from open-source files.",
                    matched_override=ident,
                )

        # 7. Private Hostnames (RG-HOST-001, RG-HOST-002, RG-HOST-003)
        for host, pat in self._strict_host_rules:
            for m in pat.finditer(line):
                emit(
                    "RG-HOST-001",
                    "private_host",
                    m.start(),
                    m.end(),
                    "Private infrastructure hostname detected",
                    "Remove machine-specific hostname; configure host via environment variable (12-Factor III & IV).",
                    matched_override=host,
                )

        for host, patterns in self._context_host_rules:
            matched_ctx = False
            for pat in patterns:
                for m in pat.finditer(line):
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
                    matched_ctx = True
                if matched_ctx:
                    break

        if self.config.strict:
            for host, pat in self._strict_only_host_rules:
                for m in pat.finditer(line):
                    emit(
                        "RG-HOST-003",
                        "private_host_strict",
                        m.start(),
                        m.end(),
                        "Local infrastructure hostname detected in --strict OSS mode",
                        "Remove environment-specific node references before open-sourcing (12-Factor III).",
                        matched_override=host,
                    )

        for term, pat in self._extra_terms:
            for m in pat.finditer(line):
                emit(
                    "RG-HOST-001",
                    "private_host",
                    m.start(),
                    m.end(),
                    "Blocked private term detected",
                    "Remove environment-specific identifier from repository.",
                    matched_override=term,
                )

        # 8. User-Facing UI Emoji Guard (RG-UI-001)
        if is_ui_source_path(rel_path):
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

        return findings

    def scan_text(self, rel_path: str, text: str) -> list[Finding]:
        """Scan multi-line text content line by line."""
        findings: list[Finding] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            findings.extend(self.scan_line(rel_path, idx, line))
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
        hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

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
