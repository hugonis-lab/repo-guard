"""Unit tests for repo_guard/git_ops.py and the check-commit-msg CLI integration.

All synthetic secret/IP/path/identity fixtures are constructed dynamically at
runtime so this test file itself passes `repo-guard audit-repo --strict`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repo_guard.cli import main as cli_main  # noqa: E402
from repo_guard.config import GuardConfig, PrivatePatterns, RepoPolicy  # noqa: E402
from repo_guard.git_ops import (  # noqa: E402
    ZERO_SHA,
    audit_repository,
    check_push_refs,
    check_staged,
    find_repo_root,
)
from repo_guard.scanner import RepoScanner  # noqa: E402


# --- Synthetic fixture builders (zero hardcoded secrets/IPs/paths/identities) ---

def _secret_aws() -> str:
    return "AKIA" + "0123456789ABCDEF"


def _lan_ip() -> str:
    return ".".join(["192", "168", "1", "36"])


def _home_path() -> str:
    return "/" + "home" + "/devuser99"


def _identity() -> str:
    return "Taylor" + " Exampleperson"


def _private_email() -> str:
    return "taylor@" + "private-domain.test"


def _git_config_user() -> str:
    return "OSS" + " Maintainer"


def _git_config_email() -> str:
    return "maintainer@" + "example.com"


def _make_config(*, strict: bool = False) -> GuardConfig:
    patterns = PrivatePatterns(
        usernames=["dev" + "user99"],
        home_paths=[_home_path()],
        tailnet_domains=["alpha-beta." + "ts" + ".net"],
        strict_hosts=["lab-node-7", "alpha-beta"],
        context_hosts=["pointer", "helios", "reefnode"],
        strict_only_hosts=["reefnode"],
        private_identities=[_identity(), "text" + "examplehandle", _private_email()],
    )
    return GuardConfig(
        patterns=patterns.normalized(),
        repo_policy=RepoPolicy(),
        strict=strict,
    )


class _GitRepoCase(unittest.TestCase):
    """Isolated temp git repo fixture. Empty hooksPath keeps commits hook-free."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.hooks_dir = self.base / "hooks"
        self.hooks_dir.mkdir(parents=True)
        self.repo_dir = self.base / "work"
        self.repo_dir.mkdir()
        self._git(["init", "-b", "main"], cwd=self.repo_dir)
        self._git(["config", "core.hooksPath", str(self.hooks_dir)], cwd=self.repo_dir)
        self._git(["config", "user.name", _git_config_user()], cwd=self.repo_dir)
        self._git(["config", "user.email", _git_config_email()], cwd=self.repo_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _git(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.repo_dir),
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            check=check,
        )

    def _write(self, rel_path: str, content: str) -> Path:
        full = self.repo_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        return full

    def _add_remote(self) -> Path:
        remote_dir = self.base / "remote.git"
        self._git(["init", "--bare", str(remote_dir)], cwd=self.base)
        self._git(["remote", "add", "origin", str(remote_dir)])
        return remote_dir

    def _clean_initial_commit(self) -> str:
        self._write("clean.txt", "hello world\n")
        self._git(["add", "clean.txt"])
        self._git(["commit", "-m", "feat: add clean"])
        self._git(["push", "origin", "main"])
        return self._git(["rev-parse", "HEAD"]).stdout.strip()


class TestFindRepoRoot(unittest.TestCase):
    def test_repo_root_itself_returns_resolved_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            self.assertEqual(find_repo_root(repo), repo.resolve())

    def test_nested_subdirectory_returns_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            nested = repo / "a" / "b" / "c"
            nested.mkdir(parents=True)
            self.assertEqual(find_repo_root(nested), repo.resolve())

    def test_non_repo_directory_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(find_repo_root(Path(td)))

    def test_start_none_uses_cwd_inside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            prev_cwd = Path.cwd()
            try:
                os.chdir(repo)
                self.assertEqual(find_repo_root(None), repo.resolve())
            finally:
                os.chdir(prev_cwd)

    def test_start_none_uses_cwd_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            prev_cwd = Path.cwd()
            try:
                os.chdir(td)
                self.assertIsNone(find_repo_root(None))
            finally:
                os.chdir(prev_cwd)


class TestCheckStaged(_GitRepoCase):
    def test_empty_staging_area_returns_empty(self) -> None:
        scanner = RepoScanner(_make_config())
        self.assertEqual(check_staged(scanner, self.repo_dir), [])

    def test_clean_staged_file_returns_empty(self) -> None:
        self._write("app.py", 'BASE_URL = "http://127.0.0.1:8080"\n')
        self._git(["add", "app.py"])
        self.assertEqual(check_staged(RepoScanner(_make_config()), self.repo_dir), [])

    def test_staged_blocked_filename(self) -> None:
        self._write(".env", "PORT=8080\n")
        self._write("credentials.json", '{"status": "ready"}\n')
        self._git(["add", "-f", ".env", "credentials.json"])
        findings = check_staged(RepoScanner(_make_config()), self.repo_dir)
        file_hits = [f for f in findings if f.rule_id == "RG-FILE-001"]
        self.assertEqual({f.path for f in file_hits}, {".env", "credentials.json"})

    def test_staged_added_diff_lines_with_synthetic_leaks(self) -> None:
        notes = "\n".join(
            [
                f'aws = "{_secret_aws()}"',
                f'host = "{_lan_ip()}"',
                f'data = "{_home_path()}/data"',
                f'owner = "{_identity()}"',
            ]
        )
        self._write("notes.txt", notes + "\n")
        self._git(["add", "notes.txt"])
        findings = check_staged(RepoScanner(_make_config()), self.repo_dir)
        self.assertTrue(
            any(f.rule_id == "RG-SEC-002" and f.path == "notes.txt" and f.line == 1 for f in findings),
            "Expected RG-SEC-002 for staged aws key at notes.txt:1",
        )
        self.assertTrue(
            any(f.rule_id == "RG-NET-002" and f.path == "notes.txt" and f.line == 2 for f in findings),
            "Expected RG-NET-002 for staged private IP at notes.txt:2",
        )
        self.assertTrue(
            any(f.rule_id == "RG-PATH-001" and f.path == "notes.txt" and f.line == 3 for f in findings),
            "Expected RG-PATH-001 for staged home path at notes.txt:3",
        )
        self.assertTrue(
            any(f.rule_id == "RG-ID-001" and f.path == "notes.txt" and f.line == 4 for f in findings),
            "Expected RG-ID-001 for staged identity at notes.txt:4",
        )

    def test_filename_with_spaces_and_nested_path(self) -> None:
        self._write("brand new dir/.env", "PORT=8080\n")
        self._write("sub/nested file.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "brand new dir/.env", "sub/nested file.py"])
        findings = check_staged(RepoScanner(_make_config()), self.repo_dir)
        file_hits = [f for f in findings if f.rule_id == "RG-FILE-001"]
        self.assertEqual([f.path for f in file_hits], ["brand new dir/.env"])
        diff_hits = [f for f in findings if f.rule_id == "RG-NET-002"]
        self.assertEqual([f.path for f in diff_hits], ["sub/nested file.py"])

    def test_unstaged_working_tree_leak_ignored(self) -> None:
        self._write("leak.py", f'ip = "{_lan_ip()}"\n')
        self._write("clean.txt", "hello world\n")
        self._git(["add", "clean.txt"])
        self.assertEqual(check_staged(RepoScanner(_make_config()), self.repo_dir), [])

    def test_unborn_head_and_subsequent_commit(self) -> None:
        scanner = RepoScanner(_make_config())
        # Before any commit (unborn HEAD), staged files still work.
        self._write("a.txt", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "a.txt"])
        findings = check_staged(scanner, self.repo_dir)
        self.assertTrue(any(f.rule_id == "RG-NET-002" for f in findings))

        self._git(["commit", "-m", "feat: add a"])
        # After a commit, staging new files still works.
        self._write("b.txt", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "b.txt"])
        findings2 = check_staged(scanner, self.repo_dir)
        self.assertTrue(any(f.rule_id == "RG-NET-002" for f in findings2))

    def test_line_deletion_of_committed_leak_not_triggering(self) -> None:
        self._write("leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "leak.py"])
        self._git(["commit", "-m", "feat: add leak"])
        # Later commit removes the leaked line; staged added lines are clean.
        self._write("leak.py", 'clean = "yes"\n')
        self._git(["add", "leak.py"])
        findings = check_staged(RepoScanner(_make_config()), self.repo_dir)
        self.assertEqual(findings, [])

    def test_git_rm_of_committed_blocked_file_not_triggering(self) -> None:
        self._write(".env", "PORT=8080\n")
        self._git(["add", "-f", ".env"])
        self._git(["commit", "-m", "chore: add env"])
        self._git(["rm", ".env"])
        findings = check_staged(RepoScanner(_make_config()), self.repo_dir)
        self.assertEqual(findings, [])


class TestCheckPushRefs(_GitRepoCase):
    def test_empty_lines_and_malformed_lines(self) -> None:
        scanner = RepoScanner(_make_config())
        findings = check_push_refs(scanner, self.repo_dir, ["", "   ", "refs/heads/main", "a b c"])
        self.assertEqual(findings, [])

    def test_branch_deletion_skipped(self) -> None:
        scanner = RepoScanner(_make_config())
        line = f"refs/heads/old {ZERO_SHA} refs/heads/old {'f' * 40}"
        self.assertEqual(check_push_refs(scanner, self.repo_dir, [line]), [])

    def test_invalid_sha_gracefully_skipped(self) -> None:
        scanner = RepoScanner(_make_config())
        line = f"refs/heads/main {'f' * 40} refs/heads/main {'a' * 40}"
        self.assertEqual(check_push_refs(scanner, self.repo_dir, [line]), [])

    def test_clean_existing_branch_update(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        self._write("more.txt", "more words\n")
        self._git(["add", "more.txt"])
        self._git(["commit", "-m", "feat: add more"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        sha_a = self._git(["rev-parse", "origin/main"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        self.assertEqual(findings, [])

    def test_leaked_added_diff_line_prefixed_with_sha(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        self._write("leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "leak.py"])
        self._git(["commit", "-m", "feat: add leak"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        sha_a = self._git(["rev-parse", "origin/main"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        self.assertTrue(
            any(f.rule_id == "RG-NET-002" and f.path == f"{sha_b[:12]}:leak.py" for f in findings),
            "Expected RG-NET-002 with sha-prefixed path",
        )

    def test_blocked_filename_prefixed_with_sha(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        self._write(".env", "PORT=8080\n")
        self._git(["add", "-f", ".env"])
        self._git(["commit", "-m", "chore: add env"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        sha_a = self._git(["rev-parse", "origin/main"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        self.assertTrue(
            any(f.rule_id == "RG-FILE-001" and f.path == f"{sha_b[:12]}:.env" for f in findings),
            "Expected RG-FILE-001 with sha-prefixed path",
        )

    def test_leaked_commit_message_path_label(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        self._write("note.txt", "a new note\n")
        self._git(["add", "note.txt"])
        self._git(["commit", "-m", f"docs: note about {_identity()}"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        sha_a = self._git(["rev-parse", "origin/main"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        self.assertTrue(
            any(
                f.rule_id == "RG-ID-001"
                and f.path == f"commit:{sha_b[:12]}:message"
                for f in findings
            ),
            "Expected RG-ID-001 with commit:<sha12>:message path",
        )

    def test_leaked_author_committer_metadata(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = _identity()
        env["GIT_AUTHOR_EMAIL"] = _private_email()
        env["GIT_COMMITTER_NAME"] = _identity()
        env["GIT_COMMITTER_EMAIL"] = _private_email()
        self._write("note.txt", "a new note\n")
        self._git(["add", "note.txt"])
        self._git(["commit", "-m", "feat: add note"], env=env)
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        sha_a = self._git(["rev-parse", "origin/main"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        for field in ("author_name", "author_email", "committer_name", "committer_email"):
            self.assertTrue(
                any(f.rule_id == "RG-ID-001" and f.path == f"commit:{sha_b[:12]}:{field}" for f in findings),
                f"Expected RG-ID-001 for {field}",
            )

    def test_already_pushed_ancestor_not_rescanned(self) -> None:
        self._add_remote()
        # Push an ancestor commit containing a leak so we genuinely verify it is skipped.
        self._write("ancestor_leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "ancestor_leak.py"])
        self._git(["commit", "-m", f"docs: legacy commit by {_identity()}"])
        self._git(["push", "origin", "main"])
        sha_a = self._git(["rev-parse", "HEAD"]).stdout.strip()

        self._write("new_clean.py", 'msg = "clean follow-up"\n')
        self._git(["add", "new_clean.py"])
        self._git(["commit", "-m", "feat: clean follow-up"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"
        findings = check_push_refs(RepoScanner(_make_config()), self.repo_dir, [line])
        self.assertEqual(findings, [], f"Already-pushed ancestor commit must not be re-scanned: {findings}")

    def test_new_branch_push_zero_sha_with_remote_name(self) -> None:
        self._add_remote()
        # Push a leaky ancestor on origin/main to verify --not --remotes=origin excludes it.
        self._write("ancestor_leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "ancestor_leak.py"])
        self._git(["commit", "-m", "chore: existing remote commit"])
        self._git(["push", "origin", "main"])
        sha_a = self._git(["rev-parse", "HEAD"]).stdout.strip()

        self._git(["checkout", "-b", "feature"])
        self._write("feature_leak.py", f'aws = "{_secret_aws()}"\n')
        self._git(["add", "feature_leak.py"])
        self._git(["commit", "-m", "feat: add feature"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        line = f"refs/heads/feature {sha_b} refs/heads/feature {ZERO_SHA}"
        findings = check_push_refs(
            RepoScanner(_make_config()), self.repo_dir, [line], remote_name="origin"
        )
        self.assertTrue(
            any(f.rule_id == "RG-SEC-002" and f.path == f"{sha_b[:12]}:feature_leak.py" for f in findings),
            "Expected finding for new-branch local commit",
        )
        self.assertFalse(
            any(f.path.startswith(f"{sha_a[:12]}:") for f in findings),
            "Commits reachable from origin must not be re-scanned",
        )

    def test_new_branch_push_zero_sha_without_remote_name(self) -> None:
        self._add_remote()
        # Push a leaky ancestor on origin/main to verify --not --remotes excludes it.
        self._write("ancestor_leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "ancestor_leak.py"])
        self._git(["commit", "-m", "chore: existing remote commit"])
        self._git(["push", "origin", "main"])
        sha_a = self._git(["rev-parse", "HEAD"]).stdout.strip()

        self._git(["checkout", "-b", "feature"])
        self._write("feature_leak.py", f'aws = "{_secret_aws()}"\n')
        self._git(["add", "feature_leak.py"])
        self._git(["commit", "-m", "feat: add feature"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        line = f"refs/heads/feature {sha_b} refs/heads/feature {ZERO_SHA}"
        findings = check_push_refs(
            RepoScanner(_make_config()), self.repo_dir, [line], remote_name=None
        )
        self.assertTrue(
            any(f.rule_id == "RG-SEC-002" and f.path == f"{sha_b[:12]}:feature_leak.py" for f in findings),
            "Expected finding for new-branch local commit",
        )
        self.assertFalse(
            any(f.path.startswith(f"{sha_a[:12]}:") for f in findings),
            "Commits reachable from remotes must not be re-scanned",
        )

    def test_new_branch_push_deduplicates_commits_across_ref_lines(self) -> None:
        self._add_remote()
        self._clean_initial_commit()
        self._git(["checkout", "-b", "feature"])
        self._write("leak.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "leak.py"])
        self._git(["commit", "-m", "feat: add leak"])
        sha_b = self._git(["rev-parse", "HEAD"]).stdout.strip()
        ref_lines = [
            f"refs/heads/feature {sha_b} refs/heads/feature {ZERO_SHA}",
            f"refs/heads/hotfix {sha_b} refs/heads/hotfix {ZERO_SHA}",
        ]
        findings = check_push_refs(
            RepoScanner(_make_config()), self.repo_dir, ref_lines, remote_name="origin"
        )
        net_findings = [f for f in findings if f.path.startswith(f"{sha_b[:12]}:")]
        self.assertEqual(
            len(net_findings),
            1,
            "Each commit must be scanned once even with multiple ref lines",
        )


class TestAuditRepository(_GitRepoCase):
    def test_git_repo_mode_scans_tracked_files_only(self) -> None:
        self._write("tracked.py", f'ip = "{_lan_ip()}"\n')
        self._write("untracked.py", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "tracked.py"])
        findings, files_scanned = audit_repository(RepoScanner(_make_config()), self.repo_dir)
        self.assertEqual(files_scanned, 1)
        self.assertTrue(any(f.path == "tracked.py" and f.rule_id == "RG-NET-002" for f in findings))
        self.assertFalse(any(f.path == "untracked.py" for f in findings))

    def test_history_disabled_skips_historical_leaks(self) -> None:
        self._write("hist.txt", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "hist.txt"])
        self._git(["commit", "-m", f"docs: add hist for {_identity()}"])
        self._write("hist.txt", "clean = true\n")
        self._git(["add", "hist.txt"])
        self._git(["commit", "-m", "docs: clean hist"])
        findings, files_scanned = audit_repository(
            RepoScanner(_make_config()), self.repo_dir, include_history=False
        )
        self.assertEqual(files_scanned, 1)
        self.assertEqual(findings, [])

    def test_history_enabled_reports_historical_leaks(self) -> None:
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = _identity()
        env["GIT_AUTHOR_EMAIL"] = _private_email()
        self._write("hist.txt", f'ip = "{_lan_ip()}"\n')
        self._git(["add", "hist.txt"])
        self._git(["commit", "-m", f"docs: add hist for {_identity()}"], env=env)
        self._write("hist.txt", "clean = true\n")
        self._git(["add", "hist.txt"])
        self._git(["commit", "-m", "docs: clean hist"])
        sha1 = self._git(["rev-parse", "HEAD~1"]).stdout.strip()

        findings, files_scanned = audit_repository(
            RepoScanner(_make_config()), self.repo_dir, include_history=True
        )
        self.assertEqual(files_scanned, 1)
        self.assertTrue(
            any(f.rule_id == "RG-NET-002" and f.path == f"{sha1[:12]}:hist.txt" for f in findings),
            "Expected historical diff leak",
        )
        self.assertTrue(
            any(f.rule_id == "RG-ID-001" and f.path == f"commit:{sha1[:12]}:message" for f in findings),
            "Expected historical commit-message leak",
        )
        self.assertTrue(
            any(f.rule_id == "RG-ID-001" and f.path == f"commit:{sha1[:12]}:author_name" for f in findings),
            "Expected historical author-name identity leak",
        )
        self.assertTrue(
            any(f.rule_id == "RG-ID-001" and f.path == f"commit:{sha1[:12]}:author_email" for f in findings),
            "Expected historical author-email identity leak",
        )

    def test_non_git_directory_mode_walks_files_and_skips_ignored_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text(f'ip = "{_lan_ip()}"\n', encoding="utf-8")
            for ignored in ("node_modules", "__pycache__", ".venv", "dist", "build", "target"):
                d = root / ignored / "pkg"
                d.mkdir(parents=True)
                (d / "index.py").write_text(f'ip = "{_lan_ip()}"\n', encoding="utf-8")
            findings, files_scanned = audit_repository(RepoScanner(_make_config()), root)
            self.assertEqual(files_scanned, 1)
            self.assertTrue(any(f.path == "app.py" and f.rule_id == "RG-NET-002" for f in findings))
            self.assertFalse(
                any(f.path.startswith(("node_modules/", "__pycache__/", ".venv/", "dist/", "build/", "target/")) for f in findings)
            )

    def test_subdirectory_inside_git_repo_uses_filesystem_walk(self) -> None:
        self._write("sub/nested.py", f'ip = "{_lan_ip()}"\n')
        self._write("sub/untracked.py", f'aws = "{_secret_aws()}"\n')
        self._write("root.py", "hello world\n")
        self._git(["add", "sub/nested.py", "root.py"])
        self._git(["commit", "-m", "feat: add files"])
        sub = self.repo_dir / "sub"
        findings, files_scanned = audit_repository(RepoScanner(_make_config()), sub)
        self.assertEqual(files_scanned, 2)
        self.assertTrue(any(f.path == "nested.py" and f.rule_id == "RG-NET-002" for f in findings))
        self.assertTrue(any(f.path == "untracked.py" and f.rule_id == "RG-SEC-002" for f in findings))
        self.assertFalse(any(f.path == "root.py" for f in findings))


class TestCheckCommitMsgCli(unittest.TestCase):
    """End-to-end CLI tests for `check-commit-msg` (isolated config, quiet output)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.cfg_path = self.base / "private-patterns.json"
        self.cfg_path.write_text(
            json.dumps(
                {
                    "private_identities": [_identity()],
                    "usernames": ["dev" + "user99"],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        previous = os.environ.get("REPO_GUARD_CONFIG")
        prev_cwd = Path.cwd()
        os.environ["REPO_GUARD_CONFIG"] = str(self.cfg_path)
        out = StringIO()
        err = StringIO()
        try:
            os.chdir(self.base)
            with redirect_stdout(out), redirect_stderr(err):
                code = cli_main(argv)
        finally:
            os.chdir(prev_cwd)
            if previous is None:
                os.environ.pop("REPO_GUARD_CONFIG", None)
            else:
                os.environ["REPO_GUARD_CONFIG"] = previous
        return code, out.getvalue(), err.getvalue()

    def test_clean_commit_message_exits_zero(self) -> None:
        msg = self.base / "MSG"
        msg.write_text("feat: add portable config\n", encoding="utf-8")
        code, _, _ = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 0)

    def test_comment_only_leak_exits_zero(self) -> None:
        msg = self.base / "MSG"
        msg.write_text(f"feat: clean commit\n# On branch main\n# modified: {_lan_ip()}\n", encoding="utf-8")
        code, _, _ = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 0)

    def test_identity_and_ip_leaks_exit_one(self) -> None:
        for text, expected_rule in (
            (f"feat: add config for {_identity()}\n", "RG-ID-001"),
            (f"docs: endpoint is {_lan_ip()}\n", "RG-NET-002"),
        ):
            msg = self.base / "MSG"
            msg.write_text(text, encoding="utf-8")
            code, _, err = self._run_cli(["check-commit-msg", str(msg)])
            self.assertEqual(code, 1, f"Expected exit 1 for: {text!r}")
            self.assertIn("repo-guard BLOCKED", err)
            self.assertIn(expected_rule, err)

    def test_missing_commit_message_file_exits_two(self) -> None:
        msg = self.base / "does-not-exist.txt"
        code, _, err = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
