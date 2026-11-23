"""Git inspection helpers for pre-commit, commit-msg, pre-push, and repo audits."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable

from .scanner import Finding, RepoScanner, scan_commit_message

ZERO_SHA = "0" * 40


def _run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def find_repo_root(start: Path | None = None) -> Path | None:
    """Return top-level git worktree path or None if not in a git repo."""
    proc = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return Path(out) if out else None


def check_staged(scanner: RepoScanner, repo_root: Path) -> list[Finding]:
    """Scan staged filenames and staged added diff lines (`pre-commit`)."""
    findings: list[Finding] = []

    names_proc = _run_git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
        cwd=repo_root,
    )
    if names_proc.returncode == 0 and names_proc.stdout:
        for rel_path in names_proc.stdout.split("\x00"):
            if rel_path:
                findings.extend(scanner.check_filename(rel_path))

    diff_proc = _run_git(
        ["diff", "--cached", "-U0", "--no-prefix", "--no-color", "--no-ext-diff", "--diff-filter=ACM"],
        cwd=repo_root,
    )
    if diff_proc.returncode == 0 and diff_proc.stdout:
        findings.extend(scanner.scan_unified_diff(diff_proc.stdout))

    return findings


def _scan_commit_object(scanner: RepoScanner, repo_root: Path, sha: str) -> list[Finding]:
    """Scan one commit's message, author metadata, filenames, and added lines."""
    findings: list[Finding] = []

    meta_proc = _run_git(
        ["log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha],
        cwd=repo_root,
    )
    if meta_proc.returncode == 0 and meta_proc.stdout:
        parts = meta_proc.stdout.split("\x00", 4)
        if len(parts) == 5:
            an, ae, cn, ce, msg = parts
            findings.extend(
                scanner.scan_author_metadata(
                    commit_sha=sha,
                    author_name=an,
                    author_email=ae,
                    committer_name=cn,
                    committer_email=ce,
                )
            )
            findings.extend(scan_commit_message(scanner, msg, source_label=f"commit:{sha[:12]}:message"))

    names_proc = _run_git(
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "--diff-filter=ACM", "-z", sha],
        cwd=repo_root,
    )
    if names_proc.returncode == 0 and names_proc.stdout:
        for rel_path in names_proc.stdout.split("\x00"):
            if rel_path:
                for f in scanner.check_filename(rel_path):
                    findings.append(
                        Finding(
                            rule_id=f.rule_id,
                            category=f.category,
                            path=f"{sha[:12]}:{f.path}",
                            line=f.line,
                            message=f.message,
                            snippet=f.snippet,
                            remediation=f.remediation,
                        )
                    )

    diff_proc = _run_git(
        ["diff-tree", "--no-commit-id", "-p", "-U0", "--no-prefix", "--no-color", "--no-ext-diff", "--root", "--diff-filter=ACM", sha],
        cwd=repo_root,
    )
    if diff_proc.returncode == 0 and diff_proc.stdout:
        for f in scanner.scan_unified_diff(diff_proc.stdout):
            findings.append(
                Finding(
                    rule_id=f.rule_id,
                    category=f.category,
                    path=f"{sha[:12]}:{f.path}",
                    line=f.line,
                    message=f.message,
                    snippet=f.snippet,
                    remediation=f.remediation,
                )
            )

    return findings


def check_push_refs(
    scanner: RepoScanner,
    repo_root: Path,
    ref_lines: Iterable[str],
    *,
    remote_name: str | None = None,
) -> list[Finding]:
    """Scan every commit being pushed based on git pre-push stdin lines."""
    commits_to_scan: list[str] = []
    seen_commits: set[str] = set()

    for raw in ref_lines:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
        if local_sha == ZERO_SHA:
            # Deleting a remote branch does not upload new content.
            continue

        if remote_sha == ZERO_SHA:
            args = ["rev-list", local_sha, "--not"]
            if remote_name:
                args.append(f"--remotes={remote_name}")
            else:
                args.append("--remotes")
            rev_proc = _run_git(args, cwd=repo_root)
        else:
            rev_proc = _run_git(["rev-list", f"{remote_sha}..{local_sha}"], cwd=repo_root)

        if rev_proc.returncode != 0:
            continue
        for sha in rev_proc.stdout.splitlines():
            sha = sha.strip()
            if sha and sha not in seen_commits:
                seen_commits.add(sha)
                commits_to_scan.append(sha)

    findings: list[Finding] = []
    for sha in commits_to_scan:
        findings.extend(_scan_commit_object(scanner, repo_root, sha))
    return findings


def _list_repo_files(target: Path, is_git: bool) -> list[str]:
    if is_git:
        proc = _run_git(["ls-files", "-z"], cwd=target)
        if proc.returncode == 0:
            return [p for p in proc.stdout.split("\x00") if p]

    files: list[str] = []
    skip_dirs = {".git", "node_modules", ".venv", "__pycache__", "dist", "build", "target"}
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in filenames:
            full = Path(root) / fname
            files.append(full.relative_to(target).as_posix())
    return sorted(files)


def audit_repository(
    scanner: RepoScanner,
    target: Path,
    *,
    include_history: bool = False,
) -> tuple[list[Finding], int]:
    """Audit all tracked files (and optionally full git history) in a directory/repo."""
    target = target.resolve()
    git_root = find_repo_root(target)
    is_git = git_root is not None and git_root.resolve() == target
    rel_files = _list_repo_files(target, is_git=is_git)

    findings: list[Finding] = []
    for rel_path in rel_files:
        findings.extend(scanner.scan_file(target, rel_path))

    if include_history and is_git:
        rev_proc = _run_git(["rev-list", "--all"], cwd=target)
        if rev_proc.returncode == 0:
            for sha in rev_proc.stdout.splitlines():
                sha = sha.strip()
                if sha:
                    findings.extend(_scan_commit_object(scanner, target, sha))

    return findings, len(rel_files)
