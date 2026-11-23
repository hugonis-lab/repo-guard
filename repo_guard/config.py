"""Configuration loader and local private-pattern initializer for repo-guard.

12-Factor Factor III compliance:
- Zero machine-specific usernames, hostnames, domains, or identities exist in code.
- Local private patterns are stored outside any repository at:
    $REPO_GUARD_CONFIG or $XDG_CONFIG_HOME/repo-guard/private-patterns.json (0600).
- Optional per-repository `.repo-guard.json` can narrow allowlists ONLY for
  non-ceiling rules and can NEVER disable hard-ceiling safety categories.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Hard-ceiling categories that `.repo-guard.json` can NEVER bypass or disable.
HARD_CEILING_CATEGORIES: frozenset[str] = frozenset(
    {
        "secret",
        "tailnet_fqdn",
        "private_ip",
        "home_path",
        "personal_identity",
    }
)

# Generic user names that should not be auto-added as personal usernames.
GENERIC_SYSTEM_USERS: frozenset[str] = frozenset(
    {
        "root",
        "user",
        "username",
        "yourname",
        "nobody",
        "daemon",
        "example",
        "alice",
        "bob",
    }
)

# Generic hostnames never treated as private infrastructure hosts.
IGNORED_HOSTS: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "example",
        "example.com",
        "example.org",
        "example.net",
    }
)

_PURE_ALPHA_WORD_RE = re.compile(r"^[a-z]{2,15}$")


@dataclass
class PrivatePatterns:
    """Machine-local private patterns loaded at runtime."""

    usernames: list[str] = field(default_factory=list)
    home_paths: list[str] = field(default_factory=list)
    tailnet_domains: list[str] = field(default_factory=list)
    strict_hosts: list[str] = field(default_factory=list)
    context_hosts: list[str] = field(default_factory=list)
    strict_only_hosts: list[str] = field(default_factory=list)
    private_identities: list[str] = field(default_factory=list)
    extra_blocked_terms: list[str] = field(default_factory=list)

    def normalized(self) -> "PrivatePatterns":
        """Return a deduplicated, cleaned copy."""
        return PrivatePatterns(
            usernames=_dedup_clean(self.usernames, lower=True),
            home_paths=_dedup_clean(self.home_paths, lower=False),
            tailnet_domains=_dedup_clean(self.tailnet_domains, lower=True),
            strict_hosts=_dedup_clean(self.strict_hosts, lower=True),
            context_hosts=_dedup_clean(self.context_hosts, lower=True),
            strict_only_hosts=_dedup_clean(self.strict_only_hosts, lower=True),
            private_identities=_dedup_clean(self.private_identities, lower=False),
            extra_blocked_terms=_dedup_clean(self.extra_blocked_terms, lower=True),
        )

    def to_dict(self) -> dict[str, Any]:
        norm = self.normalized()
        return {
            "version": 1,
            "usernames": norm.usernames,
            "home_paths": norm.home_paths,
            "tailnet_domains": norm.tailnet_domains,
            "strict_hosts": norm.strict_hosts,
            "context_hosts": norm.context_hosts,
            "strict_only_hosts": norm.strict_only_hosts,
            "private_identities": norm.private_identities,
            "extra_blocked_terms": norm.extra_blocked_terms,
        }


@dataclass
class RepoPolicy:
    """Per-repository `.repo-guard.json` narrow allowlist (subject to hard ceiling)."""

    allow_terms: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_author_emails: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class GuardConfig:
    """Combined runtime configuration for scanning."""

    patterns: PrivatePatterns
    repo_policy: RepoPolicy = field(default_factory=RepoPolicy)
    strict: bool = False
    config_path: Path | None = None


def _dedup_clean(items: list[str], *, lower: bool) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        if not isinstance(raw, str):
            continue
        val = raw.strip()
        if not val:
            continue
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(key if lower else val)
    return sorted(out, key=str.lower)


def default_private_config_path() -> Path:
    """Resolve private pattern config path from env / XDG_CONFIG_HOME."""
    env_override = os.environ.get("REPO_GUARD_CONFIG", "").strip()
    if env_override:
        return Path(env_override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else (Path.home() / ".config")
    return base / "repo-guard" / "private-patterns.json"


def _classify_hostname(host: str) -> str | None:
    """Generically classify a discovered hostname into strict_hosts or context_hosts.

    - Multi-word, hyphenated, underscored, or digit-bearing names -> `strict_hosts`
      (unlikely to collide with everyday English/code words).
    - Short pure-alphabetic single words -> `context_hosts`
      (blocked whenever used in host/URL/network syntax to avoid prose false positives).
    """
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned or len(cleaned) < 3 or cleaned in IGNORED_HOSTS:
        return None
    if _PURE_ALPHA_WORD_RE.match(cleaned):
        return "context_hosts"
    return "strict_hosts"


def _detect_runtime_defaults() -> PrivatePatterns:
    """Auto-detect current OS user, home directory, and local hostname at runtime."""
    usernames: list[str] = []
    home_paths: list[str] = []
    strict_hosts: list[str] = []
    context_hosts: list[str] = []

    try:
        user = getpass.getuser().strip()
        if user and user.lower() not in GENERIC_SYSTEM_USERS:
            usernames.append(user.lower())
    except Exception:
        pass

    try:
        home = str(Path.home().resolve())
        if home and home not in ("/", "/root"):
            home_paths.append(home)
    except Exception:
        pass

    try:
        raw_host = socket.gethostname().strip()
        short_host = raw_host.split(".")[0]
        for candidate in {raw_host, short_host}:
            bucket = _classify_hostname(candidate)
            if bucket == "strict_hosts":
                strict_hosts.append(candidate.lower())
            elif bucket == "context_hosts":
                context_hosts.append(candidate.lower())
    except Exception:
        pass

    return PrivatePatterns(
        usernames=usernames,
        home_paths=home_paths,
        strict_hosts=strict_hosts,
        context_hosts=context_hosts,
    )


def _discover_tailscale_patterns() -> PrivatePatterns:
    """Read-only local inspection of `tailscale status --json` if installed."""
    tailnet_domains: list[str] = []
    strict_hosts: list[str] = []
    context_hosts: list[str] = []

    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return PrivatePatterns()

    if proc.returncode != 0 or not proc.stdout.strip():
        return PrivatePatterns()

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return PrivatePatterns()

    suffix = (data.get("MagicDNSSuffix") or "").strip().rstrip(".").lower()
    if suffix:
        tailnet_domains.append(suffix)
        first_label = suffix.split(".")[0]
        if first_label and len(first_label) >= 4:
            strict_hosts.append(first_label)

    nodes: list[dict[str, Any]] = []
    self_node = data.get("Self")
    if isinstance(self_node, dict):
        nodes.append(self_node)
    peers = data.get("Peer")
    if isinstance(peers, dict):
        for peer in peers.values():
            if isinstance(peer, dict):
                nodes.append(peer)

    for node in nodes:
        candidates: list[str] = []
        hostname = (node.get("HostName") or "").strip()
        if hostname:
            candidates.append(hostname)
        dns_name = (node.get("DNSName") or "").strip().rstrip(".")
        if dns_name:
            short_dns = dns_name.split(".")[0]
            if short_dns:
                candidates.append(short_dns)

        for cand in candidates:
            bucket = _classify_hostname(cand)
            if bucket == "strict_hosts":
                strict_hosts.append(cand.lower())
            elif bucket == "context_hosts":
                context_hosts.append(cand.lower())

    return PrivatePatterns(
        tailnet_domains=tailnet_domains,
        strict_hosts=strict_hosts,
        context_hosts=context_hosts,
    )


def _merge_patterns(*items: PrivatePatterns) -> PrivatePatterns:
    merged = PrivatePatterns()
    for p in items:
        merged.usernames.extend(p.usernames)
        merged.home_paths.extend(p.home_paths)
        merged.tailnet_domains.extend(p.tailnet_domains)
        merged.strict_hosts.extend(p.strict_hosts)
        merged.context_hosts.extend(p.context_hosts)
        merged.strict_only_hosts.extend(p.strict_only_hosts)
        merged.private_identities.extend(p.private_identities)
        merged.extra_blocked_terms.extend(p.extra_blocked_terms)

    norm = merged.normalized()
    # If a host is explicitly in strict_hosts, keep it out of context_hosts to avoid duplicate hits.
    strict_set = set(norm.strict_hosts)
    norm.context_hosts = [h for h in norm.context_hosts if h not in strict_set]
    norm.strict_only_hosts = [h for h in norm.strict_only_hosts if h not in strict_set]
    return norm


def load_private_patterns(
    config_path: Path | None = None,
    *,
    include_runtime_defaults: bool = True,
) -> PrivatePatterns:
    """Load private patterns from JSON file and merge runtime defaults."""
    path = config_path or default_private_config_path()
    from_file = PrivatePatterns()

    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                from_file = PrivatePatterns(
                    usernames=list(raw.get("usernames") or []),
                    home_paths=list(raw.get("home_paths") or []),
                    tailnet_domains=list(raw.get("tailnet_domains") or []),
                    strict_hosts=list(raw.get("strict_hosts") or []),
                    context_hosts=list(raw.get("context_hosts") or []),
                    strict_only_hosts=list(raw.get("strict_only_hosts") or []),
                    private_identities=list(raw.get("private_identities") or []),
                    extra_blocked_terms=list(raw.get("extra_blocked_terms") or []),
                )
        except (OSError, json.JSONDecodeError) as exc:
            print(f"repo-guard warning: failed to read {path}: {exc}", file=sys.stderr)

    if include_runtime_defaults:
        return _merge_patterns(from_file, _detect_runtime_defaults())
    return from_file.normalized()


def load_repo_policy(repo_root: Path | None) -> RepoPolicy:
    """Load optional per-repo `.repo-guard.json` while enforcing hard ceilings."""
    if repo_root is None:
        return RepoPolicy()
    policy_file = repo_root / ".repo-guard.json"
    if not policy_file.is_file():
        return RepoPolicy()

    warnings: list[str] = []
    try:
        raw = json.loads(policy_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return RepoPolicy(warnings=[f"Invalid .repo-guard.json: {exc}"])

    if not isinstance(raw, dict):
        return RepoPolicy(warnings=["Invalid .repo-guard.json: root must be an object"])

    allowed_keys = {"allow_terms", "allow_paths", "allow_author_emails"}
    for key in raw:
        if key not in allowed_keys:
            warnings.append(
                f"Ignoring unsupported/forbidden .repo-guard.json key '{key}' "
                f"(hard-ceiling rules cannot be disabled)"
            )

    allow_terms = _dedup_clean(list(raw.get("allow_terms") or []), lower=True)
    allow_paths = _dedup_clean(list(raw.get("allow_paths") or []), lower=False)
    allow_author_emails = _dedup_clean(list(raw.get("allow_author_emails") or []), lower=True)

    return RepoPolicy(
        allow_terms=allow_terms,
        allow_paths=allow_paths,
        allow_author_emails=allow_author_emails,
        warnings=warnings,
    )


def init_local_config(
    *,
    config_path: Path | None = None,
    add_identities: list[str] | None = None,
    add_strict_hosts: list[str] | None = None,
    add_context_hosts: list[str] | None = None,
    add_strict_only_hosts: list[str] | None = None,
    add_tailnet_domains: list[str] | None = None,
    include_tailscale: bool = True,
) -> tuple[Path, PrivatePatterns]:
    """Create or refresh local private-patterns.json with strict 0600 permissions."""
    path = config_path or default_private_config_path()
    existing = load_private_patterns(path, include_runtime_defaults=False)
    runtime = _detect_runtime_defaults()
    ts = _discover_tailscale_patterns() if include_tailscale else PrivatePatterns()

    explicit = PrivatePatterns(
        tailnet_domains=list(add_tailnet_domains or []),
        strict_hosts=list(add_strict_hosts or []),
        context_hosts=list(add_context_hosts or []),
        strict_only_hosts=list(add_strict_only_hosts or []),
        private_identities=list(add_identities or []),
    )

    merged = _merge_patterns(existing, runtime, ts, explicit)

    # If user explicitly passed --add-context-host, remove from strict_hosts if auto-added.
    if add_context_hosts:
        explicit_ctx = {h.strip().lower() for h in add_context_hosts if h.strip()}
        merged.strict_hosts = [h for h in merged.strict_hosts if h not in explicit_ctx]
        merged.context_hosts = _dedup_clean(merged.context_hosts + list(explicit_ctx), lower=True)

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass

    payload = json.dumps(merged.to_dict(), indent=2, sort_keys=False) + "\n"
    # Atomic write with 0600 permissions so secrets/identities are never world-readable.
    tmp_path = path.with_suffix(".json.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise

    return path, merged


def build_guard_config(
    *,
    repo_root: Path | None = None,
    config_path: Path | None = None,
    strict: bool = False,
) -> GuardConfig:
    """Build complete GuardConfig for a scan invocation."""
    resolved_path = config_path or default_private_config_path()
    patterns = load_private_patterns(resolved_path, include_runtime_defaults=True)
    policy = load_repo_policy(repo_root)
    return GuardConfig(
        patterns=patterns,
        repo_policy=policy,
        strict=strict,
        config_path=resolved_path,
    )
