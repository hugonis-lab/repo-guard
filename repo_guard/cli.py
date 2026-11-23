"""Command-line interface for repo-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import (
    GuardConfig,
    build_guard_config,
    default_private_config_path,
    init_local_config,
)
from .git_ops import (
    audit_repository,
    check_push_refs,
    check_staged,
    find_repo_root,
)
from .scanner import Finding, RepoScanner, scan_commit_message, summarize_findings


def _print_findings(
    findings: Sequence[Finding],
    *,
    context_label: str,
    as_json: bool = False,
    files_scanned: int | None = None,
    warnings: Sequence[str] = (),
) -> None:
    if as_json:
        payload = {
            "status": "fail" if findings else "pass",
            "context": context_label,
            "files_scanned": files_scanned,
            "finding_count": len(findings),
            "counts_by_rule": summarize_findings(findings),
            "warnings": list(warnings),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
        return

    for warn in warnings:
        print(f"repo-guard warning: {warn}", file=sys.stderr)

    if not findings:
        extra = f" ({files_scanned} files scanned)" if files_scanned is not None else ""
        print(f"repo-guard PASS [{context_label}]: 0 findings{extra}")
        return

    counts = summarize_findings(findings)
    summary = ", ".join(f"{rule}={cnt}" for rule, cnt in counts.items())
    print(
        f"repo-guard BLOCKED [{context_label}]: {len(findings)} finding(s) ({summary})",
        file=sys.stderr,
    )
    print("-" * 72, file=sys.stderr)
    for f in findings:
        loc = f"{f.path}:{f.line}" if f.line > 0 else f.path
        print(f"[{f.rule_id}] {loc} — {f.message}", file=sys.stderr)
        print(f"  preview: {f.snippet}", file=sys.stderr)
        print(f"  fix:     {f.remediation}", file=sys.stderr)
    print("-" * 72, file=sys.stderr)
    print(
        "Fix the findings above before committing/pushing. Do NOT bypass with --no-verify.",
        file=sys.stderr,
    )


def _cmd_init_local(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser() if args.config else default_private_config_path()
    path, patterns = init_local_config(
        config_path=config_path,
        add_identities=args.add_identity,
        add_strict_hosts=args.add_strict_host,
        add_context_hosts=args.add_context_host,
        add_strict_only_hosts=args.add_strict_only_host,
        add_tailnet_domains=args.add_tailnet_domain,
        include_tailscale=not args.no_tailscale,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "config_path": str(path),
                    "mode": "0600",
                    "counts": {
                        "usernames": len(patterns.usernames),
                        "home_paths": len(patterns.home_paths),
                        "tailnet_domains": len(patterns.tailnet_domains),
                        "strict_hosts": len(patterns.strict_hosts),
                        "context_hosts": len(patterns.context_hosts),
                        "strict_only_hosts": len(patterns.strict_only_hosts),
                        "private_identities": len(patterns.private_identities),
                    },
                },
                indent=2,
            )
        )
    else:
        print(f"repo-guard initialized local private config at {path} (mode 0600)")
        print(
            f"  usernames={len(patterns.usernames)} home_paths={len(patterns.home_paths)} "
            f"tailnet_domains={len(patterns.tailnet_domains)} strict_hosts={len(patterns.strict_hosts)} "
            f"context_hosts={len(patterns.context_hosts)} strict_only_hosts={len(patterns.strict_only_hosts)} "
            f"private_identities={len(patterns.private_identities)}"
        )
    return 0


def _cmd_check_staged(args: argparse.Namespace) -> int:
    start = Path(args.repo).resolve() if args.repo else Path.cwd()
    repo_root = find_repo_root(start)
    if repo_root is None:
        print("repo-guard error: not inside a git repository", file=sys.stderr)
        return 2

    cfg = build_guard_config(
        repo_root=repo_root,
        config_path=Path(args.config).expanduser() if args.config else None,
        strict=args.strict,
    )
    scanner = RepoScanner(cfg)
    findings = check_staged(scanner, repo_root)
    _print_findings(
        findings,
        context_label="pre-commit",
        as_json=args.json,
        warnings=cfg.repo_policy.warnings,
    )
    return 1 if findings else 0


def _cmd_check_commit_msg(args: argparse.Namespace) -> int:
    msg_path = Path(args.msg_file)
    if not msg_path.is_file():
        print(f"repo-guard error: commit message file not found: {msg_path}", file=sys.stderr)
        return 2

    repo_root = find_repo_root(Path.cwd())
    cfg = build_guard_config(
        repo_root=repo_root,
        config_path=Path(args.config).expanduser() if args.config else None,
        strict=args.strict,
    )
    scanner = RepoScanner(cfg)
    text = msg_path.read_text(encoding="utf-8", errors="replace")
    findings = scan_commit_message(scanner, text, source_label=msg_path.name)
    _print_findings(
        findings,
        context_label="commit-msg",
        as_json=args.json,
        warnings=cfg.repo_policy.warnings,
    )
    return 1 if findings else 0


def _cmd_check_push(args: argparse.Namespace) -> int:
    start = Path(args.repo).resolve() if args.repo else Path.cwd()
    repo_root = find_repo_root(start)
    if repo_root is None:
        print("repo-guard error: not inside a git repository", file=sys.stderr)
        return 2

    cfg = build_guard_config(
        repo_root=repo_root,
        config_path=Path(args.config).expanduser() if args.config else None,
        strict=args.strict,
    )
    scanner = RepoScanner(cfg)
    ref_lines = sys.stdin.read().splitlines()
    findings = check_push_refs(
        scanner,
        repo_root,
        ref_lines,
        remote_name=args.remote_name,
    )
    _print_findings(
        findings,
        context_label="pre-push",
        as_json=args.json,
        warnings=cfg.repo_policy.warnings,
    )
    return 1 if findings else 0


def _cmd_audit_repo(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve() if args.path else Path.cwd()
    if not target.exists():
        print(f"repo-guard error: path does not exist: {target}", file=sys.stderr)
        return 2

    repo_root = find_repo_root(target) or target
    cfg = build_guard_config(
        repo_root=repo_root,
        config_path=Path(args.config).expanduser() if args.config else None,
        strict=args.strict,
    )
    scanner = RepoScanner(cfg)
    findings, files_scanned = audit_repository(
        scanner,
        target,
        include_history=args.history,
    )
    mode = "audit-repo --strict" if args.strict else "audit-repo"
    if args.history:
        mode += " --history"
    _print_findings(
        findings,
        context_label=mode,
        as_json=args.json,
        files_scanned=files_scanned,
        warnings=cfg.repo_policy.warnings,
    )
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-guard",
        description="Deterministic Git hooks & 12-Factor open-source hygiene guardrail.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        help="Override private patterns JSON path (defaults to $REPO_GUARD_CONFIG or $XDG_CONFIG_HOME/repo-guard/private-patterns.json).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init-local",
        help="Create or refresh local private-patterns.json (0600, outside any repo).",
    )
    p_init.add_argument("--add-identity", action="append", default=[], help="Add a personal name, handle, email, or domain to private_identities.")
    p_init.add_argument("--add-strict-host", action="append", default=[], help="Add a hostname always blocked as a standalone token.")
    p_init.add_argument("--add-context-host", action="append", default=[], help="Add a hostname blocked in URL/host/network syntax.")
    p_init.add_argument("--add-strict-only-host", action="append", default=[], help="Add a hostname also blocked standalone in --strict mode.")
    p_init.add_argument("--add-tailnet-domain", action="append", default=[], help="Add a private tailnet DNS domain suffix.")
    p_init.add_argument("--no-tailscale", action="store_true", help="Skip read-only local tailscale status inspection.")
    p_init.set_defaults(func=_cmd_init_local)

    p_staged = sub.add_parser("check-staged", help="Scan staged filenames and staged diff lines (pre-commit hook).")
    p_staged.add_argument("--repo", help="Path inside target git repository.")
    p_staged.add_argument("--strict", action="store_true", help="Enable --strict OSS rules.")
    p_staged.set_defaults(func=_cmd_check_staged)

    p_msg = sub.add_parser("check-commit-msg", help="Scan a git commit message file (commit-msg hook).")
    p_msg.add_argument("msg_file", help="Path to commit message file.")
    p_msg.add_argument("--strict", action="store_true", help="Enable --strict OSS rules.")
    p_msg.set_defaults(func=_cmd_check_commit_msg)

    p_push = sub.add_parser("check-push", help="Scan commit range from git pre-push stdin.")
    p_push.add_argument("remote_name", nargs="?", help="Optional remote name passed by git pre-push.")
    p_push.add_argument("remote_url", nargs="?", help="Optional remote URL passed by git pre-push.")
    p_push.add_argument("--repo", help="Path inside target git repository.")
    p_push.add_argument("--strict", action="store_true", help="Enable --strict OSS rules.")
    p_push.set_defaults(func=_cmd_check_push)

    p_audit = sub.add_parser("audit-repo", help="Audit all git-tracked files (and optionally history) in a repository.")
    p_audit.add_argument("path", nargs="?", default=".", help="Path to repository or directory to audit.")
    p_audit.add_argument("--strict", action="store_true", help="Enable --strict OSS readiness checks.")
    p_audit.add_argument("--history", action="store_true", help="Also scan all commit messages, metadata, and diffs in git history.")
    p_audit.set_defaults(func=_cmd_audit_repo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
