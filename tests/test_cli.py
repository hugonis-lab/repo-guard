"""Unit and CLI integration tests for repo_guard/cli.py.

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
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repo_guard import __version__  # noqa: E402
from repo_guard.cli import (  # noqa: E402
    _cmd_audit_repo,
    _cmd_check_commit_msg,
    _cmd_check_push,
    _cmd_check_staged,
    _cmd_init_local,
    _print_findings,
    build_parser,
    main,
)
from repo_guard.scanner import Finding  # noqa: E402


# --- Synthetic fixture builders (zero hardcoded secrets/IPs/paths/identities) ---

def _secret_aws() -> str:
    return "AKIA" + "0123456789ABCDEF"


def _lan_ip() -> str:
    return ".".join(["192", "168", "1", "36"])


def _home_path() -> str:
    return "/" + "home" + "/devuser99"


def _identity() -> str:
    return "Taylor" + " Exampleperson"


def _handle() -> str:
    return "text" + "examplehandle"


def _git_config_user() -> str:
    return "OSS" + " Maintainer"


def _git_config_email() -> str:
    return "maintainer@" + "example.com"


def _strict_only_host() -> str:
    return "reefnode"


def _context_host() -> str:
    return "pointer"


def _strict_host() -> str:
    return "lab-node-7"


def _write_fixture_config(path: Path, **overrides: object) -> Path:
    """Write a deterministic private-patterns.json fixture to path."""
    data: dict[str, object] = {
        "private_identities": [_identity(), _handle()],
        "usernames": ["dev" + "user99"],
        "home_paths": [_home_path()],
        "tailnet_domains": ["alpha-beta." + "ts" + ".net"],
        "strict_hosts": [_strict_host()],
        "context_hosts": [_context_host()],
        "strict_only_hosts": [_strict_only_host()],
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _sample_finding(path: str = "a.py", line: int = 3) -> Finding:
    return Finding(
        rule_id="RG-SEC-002",
        category="secret",
        path=path,
        line=line,
        message="Synthetic finding",
        snippet="snippet",
        remediation="fix",
    )


# --- Isolated CLI & Git test harnesses ---

class _CliCase(unittest.TestCase):
    """Isolated temp directory, cwd, and env per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.cfg_path = _write_fixture_config(self.base / "private-patterns.json")
        self._saved_cwd = Path.cwd()
        self._saved_config = os.environ.get("REPO_GUARD_CONFIG")
        self._saved_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["REPO_GUARD_CONFIG"] = str(self.cfg_path)
        os.environ.pop("XDG_CONFIG_HOME", None)

    def tearDown(self) -> None:
        os.chdir(self._saved_cwd)
        if self._saved_config is None:
            os.environ.pop("REPO_GUARD_CONFIG", None)
        else:
            os.environ["REPO_GUARD_CONFIG"] = self._saved_config
        if self._saved_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._saved_xdg
        self._tmp.cleanup()

    def _run_cli(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        stdin_text: str | None = None,
    ) -> tuple[int, str, str]:
        out = StringIO()
        err = StringIO()
        stdin = StringIO(stdin_text if stdin_text is not None else "")
        try:
            if cwd is not None:
                os.chdir(cwd)
            with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", stdin):
                try:
                    code = main(argv)
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else 2
        finally:
            os.chdir(self._saved_cwd)
        return code, out.getvalue(), err.getvalue()


class _GitCliCase(_CliCase):
    """Isolated CLI harness with a hook-free temporary git repository."""

    def setUp(self) -> None:
        super().setUp()
        self.hooks_dir = self.base / "hooks"
        self.hooks_dir.mkdir(parents=True)
        self.repo_dir = self.base / "work"
        self.repo_dir.mkdir()
        self._git(["init", "-b", "main"], cwd=self.repo_dir)
        self._git(["config", "core.hooksPath", str(self.hooks_dir)], cwd=self.repo_dir)
        self._git(["config", "user.name", _git_config_user()], cwd=self.repo_dir)
        self._git(["config", "user.email", _git_config_email()], cwd=self.repo_dir)

    def _git(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.repo_dir),
            capture_output=True,
            text=True,
            check=check,
        )

    def _write(self, rel_path: str, content: str) -> Path:
        full = self.repo_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        return full

    def _add_and_commit(self, rel_path: str, content: str, message: str) -> str:
        self._write(rel_path, content)
        self._git(["add", rel_path])
        self._git(["commit", "-m", message])
        return self._git(["rev-parse", "HEAD"]).stdout.strip()

    def _add_remote(self) -> Path:
        remote_dir = self.base / "remote.git"
        self._git(["init", "--bare", str(remote_dir)], cwd=self.base)
        self._git(["remote", "add", "origin", str(remote_dir)])
        return remote_dir

    def _push_clean_initial_commit(self) -> str:
        self._add_remote()
        self._add_and_commit("clean.txt", "hello world\n", "feat: add clean")
        self._git(["push", "origin", "main"])
        return self._git(["rev-parse", "origin/main"]).stdout.strip()


# --- _print_findings unit tests ---

class TestPrintFindings(unittest.TestCase):
    def _capture(self, findings: list[Finding], **kwargs: object) -> tuple[str, str]:
        out = StringIO()
        err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _print_findings(findings, **kwargs)  # type: ignore[arg-type]
        return out.getvalue(), err.getvalue()

    def test_json_empty_findings_pass_with_none_scanned(self) -> None:
        out, err = self._capture([], context_label="ctx", as_json=True, files_scanned=None)
        payload = json.loads(out)
        self.assertEqual(err, "")
        self.assertEqual(
            payload,
            {
                "status": "pass",
                "context": "ctx",
                "files_scanned": None,
                "finding_count": 0,
                "counts_by_rule": {},
                "warnings": [],
                "findings": [],
            },
        )

    def test_json_empty_findings_pass_with_zero_scanned(self) -> None:
        out, err = self._capture([], context_label="ctx", as_json=True, files_scanned=0)
        payload = json.loads(out)
        self.assertEqual(err, "")
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["files_scanned"], 0)

    def test_json_empty_findings_pass_with_n_scanned_and_warnings(self) -> None:
        out, err = self._capture(
            [], context_label="ctx", as_json=True, files_scanned=4, warnings=("w1", "w2")
        )
        payload = json.loads(out)
        self.assertEqual(err, "")
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["files_scanned"], 4)
        self.assertEqual(payload["warnings"], ["w1", "w2"])

    def test_json_non_empty_findings_fail_with_counts_and_to_dict(self) -> None:
        findings = [
            _sample_finding("a.py", 3),
            Finding("RG-NET-002", "private_ip", "a.py", 5, "m1", "snip1", "fix1"),
            Finding("RG-NET-002", "private_ip", "b.py", 1, "m2", "snip2", "fix2"),
        ]
        out, err = self._capture(
            findings, context_label="ctx", as_json=True, files_scanned=3, warnings=("w1",)
        )
        payload = json.loads(out)
        self.assertEqual(err, "")
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["context"], "ctx")
        self.assertEqual(payload["finding_count"], 3)
        self.assertEqual(payload["counts_by_rule"], {"RG-NET-002": 2, "RG-SEC-002": 1})
        self.assertEqual(payload["files_scanned"], 3)
        self.assertEqual(payload["warnings"], ["w1"])
        self.assertEqual(payload["findings"], [f.to_dict() for f in findings])

    def test_text_pass_without_files_scanned_suffix(self) -> None:
        out, err = self._capture([], context_label="pre-commit")
        self.assertEqual(out, "repo-guard PASS [pre-commit]: 0 findings\n")
        self.assertEqual(err, "")

    def test_text_pass_with_zero_files_scanned_suffix(self) -> None:
        out, err = self._capture([], context_label="audit-repo", files_scanned=0)
        self.assertEqual(out, "repo-guard PASS [audit-repo]: 0 findings (0 files scanned)\n")
        self.assertEqual(err, "")

    def test_text_pass_with_nonzero_files_scanned_suffix(self) -> None:
        out, err = self._capture([], context_label="audit-repo", files_scanned=7)
        self.assertEqual(out, "repo-guard PASS [audit-repo]: 0 findings (7 files scanned)\n")
        self.assertEqual(err, "")

    def test_text_pass_emits_warnings_on_stderr_only(self) -> None:
        out, err = self._capture([], context_label="ctx", warnings=("warn one", "warn two"))
        self.assertEqual(out, "repo-guard PASS [ctx]: 0 findings\n")
        self.assertEqual(
            err.splitlines(),
            ["repo-guard warning: warn one", "repo-guard warning: warn two"],
        )

    def test_text_blocked_formats_warnings_summary_locations_and_footer(self) -> None:
        findings = [
            _sample_finding("a.py", 3),
            Finding("RG-NET-002", "private_ip", "b.py", 0, "bare file hit", "snip2", "fix2"),
            Finding("RG-NET-002", "private_ip", "c.py", 9, "line hit", "snip3", "fix3"),
        ]
        out, err = self._capture(findings, context_label="ctx", warnings=("warn one",))
        self.assertEqual(out, "")
        lines = err.splitlines()
        self.assertEqual(lines[0], "repo-guard warning: warn one")
        self.assertEqual(
            lines[1],
            "repo-guard BLOCKED [ctx]: 3 finding(s) (RG-NET-002=2, RG-SEC-002=1)",
        )
        self.assertEqual(lines[2], "-" * 72)
        self.assertIn("[RG-SEC-002] a.py:3 — Synthetic finding", lines)
        self.assertIn("  preview: snippet", lines)
        self.assertIn("  fix:     fix", lines)
        # line == 0 omits the :0 suffix
        self.assertIn("[RG-NET-002] b.py — bare file hit", lines)
        self.assertNotIn("b.py:0", err)
        self.assertIn("  preview: snip2", lines)
        self.assertIn("  fix:     fix2", lines)
        self.assertIn("[RG-NET-002] c.py:9 — line hit", lines)
        self.assertEqual(lines[-2], "-" * 72)
        self.assertEqual(
            lines[-1],
            "Fix the findings above before committing/pushing. Do NOT bypass with --no-verify.",
        )

    def test_text_blocked_without_warnings_starts_with_status_line(self) -> None:
        out, err = self._capture([_sample_finding("a.py", 1)], context_label="ctx")
        self.assertEqual(out, "")
        first_line = err.splitlines()[0]
        self.assertEqual(first_line, "repo-guard BLOCKED [ctx]: 1 finding(s) (RG-SEC-002=1)")


# --- build_parser & argparse tests ---

class TestBuildParser(unittest.TestCase):
    def test_version_prints_and_exits_zero(self) -> None:
        out = StringIO()
        with redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f"repo-guard {__version__}")

    def test_missing_subcommand_exits_two(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args([])
        self.assertEqual(ctx.exception.code, 2)

    def test_invalid_subcommand_exits_two(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["bogus-command"])
        self.assertEqual(ctx.exception.code, 2)

    def test_unknown_flag_exits_two(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["audit-repo", "--no-such-flag"])
        self.assertEqual(ctx.exception.code, 2)

    def test_check_commit_msg_missing_positional_exits_two(self) -> None:
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["check-commit-msg"])
        self.assertEqual(ctx.exception.code, 2)

    def test_init_local_parses_all_flags(self) -> None:
        args = build_parser().parse_args(
            [
                "--config", "/tmp/xyz.json",
                "--json",
                "init-local",
                "--no-tailscale",
                "--add-identity", "id-one",
                "--add-identity", "id-two",
                "--add-strict-host", "host-one",
                "--add-context-host", "ctx-one",
                "--add-strict-only-host", "so-one",
                "--add-tailnet-domain", "d-one.example.net",
                "--add-tailnet-domain", "d-two.example.net",
            ]
        )
        self.assertIs(args.func, _cmd_init_local)
        self.assertEqual(args.config, "/tmp/xyz.json")
        self.assertTrue(args.json)
        self.assertTrue(args.no_tailscale)
        self.assertEqual(args.add_identity, ["id-one", "id-two"])
        self.assertEqual(args.add_strict_host, ["host-one"])
        self.assertEqual(args.add_context_host, ["ctx-one"])
        self.assertEqual(args.add_strict_only_host, ["so-one"])
        self.assertEqual(args.add_tailnet_domain, ["d-one.example.net", "d-two.example.net"])

    def test_check_staged_parses_flags_and_defaults(self) -> None:
        defaults = build_parser().parse_args(["check-staged"])
        self.assertIs(defaults.func, _cmd_check_staged)
        self.assertIsNone(defaults.config)
        self.assertFalse(defaults.json)
        self.assertIsNone(defaults.repo)
        self.assertFalse(defaults.strict)

        args = build_parser().parse_args(
            ["--json", "check-staged", "--repo", "/tmp/r", "--strict"]
        )
        self.assertIs(args.func, _cmd_check_staged)
        self.assertTrue(args.json)
        self.assertTrue(args.strict)
        self.assertEqual(args.repo, "/tmp/r")

    def test_check_commit_msg_parses_flags(self) -> None:
        args = build_parser().parse_args(
            ["--config", "/tmp/xyz.json", "check-commit-msg", "/tmp/MSG", "--strict"]
        )
        self.assertIs(args.func, _cmd_check_commit_msg)
        self.assertEqual(args.msg_file, "/tmp/MSG")
        self.assertTrue(args.strict)
        self.assertEqual(args.config, "/tmp/xyz.json")

    def test_check_push_parses_optional_positionals_and_flags(self) -> None:
        args = build_parser().parse_args(
            ["check-push", "origin", "git@example.com:repo.git", "--repo", "/tmp/r", "--strict"]
        )
        self.assertIs(args.func, _cmd_check_push)
        self.assertEqual(args.remote_name, "origin")
        self.assertEqual(args.remote_url, "git@example.com:repo.git")
        self.assertEqual(args.repo, "/tmp/r")
        self.assertTrue(args.strict)

        minimal = build_parser().parse_args(["check-push"])
        self.assertIs(minimal.func, _cmd_check_push)
        self.assertIsNone(minimal.remote_name)
        self.assertIsNone(minimal.remote_url)
        self.assertIsNone(minimal.repo)
        self.assertFalse(minimal.strict)

    def test_audit_repo_parses_all_flags_and_defaults(self) -> None:
        args = build_parser().parse_args(
            ["audit-repo", "/tmp/target", "--strict", "--history"]
        )
        self.assertIs(args.func, _cmd_audit_repo)
        self.assertEqual(args.path, "/tmp/target")
        self.assertTrue(args.strict)
        self.assertTrue(args.history)

        defaults = build_parser().parse_args(["audit-repo"])
        self.assertIs(defaults.func, _cmd_audit_repo)
        self.assertEqual(defaults.path, ".")
        self.assertFalse(defaults.strict)
        self.assertFalse(defaults.history)


# --- Subcommand CLI integration tests ---

class TestInitLocal(_CliCase):
    def test_text_output_with_explicit_config(self) -> None:
        target = self.base / "explicit.json"
        code, out, err = self._run_cli(
            ["--config", str(target), "init-local", "--no-tailscale"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn(f"repo-guard initialized local private config at {target} (mode 0600)", out)
        for label in (
            "usernames=",
            "home_paths=",
            "tailnet_domains=",
            "strict_hosts=",
            "context_hosts=",
            "strict_only_hosts=",
            "private_identities=",
        ):
            self.assertIn(label, out)
        self.assertTrue(target.is_file())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_json_output_with_explicit_config(self) -> None:
        target = self.base / "explicit.json"
        code, out, err = self._run_cli(
            ["--json", "--config", str(target), "init-local", "--no-tailscale"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual(payload["config_path"], str(target))
        self.assertEqual(payload["mode"], "0600")
        self.assertEqual(
            set(payload["counts"].keys()),
            {
                "usernames",
                "home_paths",
                "tailnet_domains",
                "strict_hosts",
                "context_hosts",
                "strict_only_hosts",
                "private_identities",
            },
        )
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_default_path_uses_repo_guard_config_env_text_and_json(self) -> None:
        code, out, err = self._run_cli(["init-local", "--no-tailscale"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn(str(self.cfg_path), out)
        self.assertEqual(self.cfg_path.stat().st_mode & 0o777, 0o600)

        code_json, out_json, err_json = self._run_cli(["--json", "init-local", "--no-tailscale"])
        self.assertEqual(code_json, 0)
        self.assertEqual(err_json, "")
        payload = json.loads(out_json)
        self.assertEqual(payload["config_path"], str(self.cfg_path))
        self.assertEqual(payload["mode"], "0600")

    def test_repeated_add_flags_persisted_and_counted_accurately(self) -> None:
        target = self.base / "explicit-cli.json"
        extra_id_1 = "Extra" + "-Identity-One"
        extra_id_2 = "Extra" + "-Identity-Two"
        extra_strict = "strict-" + "node-1"
        extra_context = "contextnode"
        extra_strict_only = "strictonlynode"
        extra_tailnet = "extra-tailnet." + "ts" + ".net"

        code, out, err = self._run_cli(
            [
                "--json",
                "--config", str(target),
                "init-local",
                "--no-tailscale",
                "--add-identity", extra_id_1,
                "--add-identity", extra_id_2,
                "--add-strict-host", extra_strict,
                "--add-context-host", extra_context,
                "--add-strict-only-host", extra_strict_only,
                "--add-tailnet-domain", extra_tailnet,
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        written = json.loads(target.read_text(encoding="utf-8"))

        self.assertIn(extra_id_1, written["private_identities"])
        self.assertIn(extra_id_2, written["private_identities"])
        self.assertIn(extra_strict, written["strict_hosts"])
        self.assertIn(extra_context, written["context_hosts"])
        self.assertIn(extra_strict_only, written["strict_only_hosts"])
        self.assertIn(extra_tailnet, written["tailnet_domains"])
        for key, reported_count in payload["counts"].items():
            self.assertEqual(reported_count, len(written[key]), f"Count mismatch for {key}")


class TestCheckStaged(_GitCliCase):
    def test_outside_git_repo_with_repo_flag_exits_two(self) -> None:
        non_git = self.base / "not-a-repo"
        non_git.mkdir()
        code, out, err = self._run_cli(["check-staged", "--repo", str(non_git)])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("not inside a git repository", err)

    def test_outside_git_repo_via_cwd_exits_two(self) -> None:
        non_git = self.base / "not-a-repo"
        non_git.mkdir()
        code, out, err = self._run_cli(["check-staged"], cwd=non_git)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("not inside a git repository", err)

    def test_clean_staged_repo_exits_zero_text_and_json(self) -> None:
        self._write("clean.txt", "hello world\n")
        self._git(["add", "clean.txt"])

        code, out, err = self._run_cli(["check-staged", "--repo", str(self.repo_dir)])
        self.assertEqual(code, 0)
        self.assertEqual(out, "repo-guard PASS [pre-commit]: 0 findings\n")
        self.assertEqual(err, "")

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-staged", "--repo", str(self.repo_dir)]
        )
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["context"], "pre-commit")
        self.assertEqual(payload["finding_count"], 0)

    def test_leaky_staged_file_exits_one_text_and_json(self) -> None:
        self._write("leak.txt", f'ip = "{_lan_ip()}"\naws = "{_secret_aws()}"\n')
        self._git(["add", "leak.txt"])

        code, out, err = self._run_cli(["check-staged", "--repo", str(self.repo_dir)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("repo-guard BLOCKED [pre-commit]", err)
        self.assertIn("RG-NET-002", err)
        self.assertIn("RG-SEC-002", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-staged", "--repo", str(self.repo_dir)]
        )
        self.assertEqual(code_j, 1)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["context"], "pre-commit")
        self.assertGreaterEqual(payload["finding_count"], 2)

    def test_explicit_config_flag_overrides_env_config(self) -> None:
        custom_token = "Custom" + " Overrideperson"
        override_cfg = _write_fixture_config(
            self.base / "override.json",
            private_identities=[custom_token],
        )
        self._write("note.txt", f"owner = {custom_token}\n")
        self._git(["add", "note.txt"])

        code_default, _, _ = self._run_cli(["check-staged", "--repo", str(self.repo_dir)])
        self.assertEqual(code_default, 0)

        code_override, _, err = self._run_cli(
            ["--config", str(override_cfg), "check-staged", "--repo", str(self.repo_dir)]
        )
        self.assertEqual(code_override, 1)
        self.assertIn("RG-ID-001", err)

    def test_strict_flag_toggles_strict_only_host_detection(self) -> None:
        self._write("node.txt", f"{_strict_only_host()}\n")
        self._git(["add", "node.txt"])

        code_normal, out_normal, _ = self._run_cli(["check-staged", "--repo", str(self.repo_dir)])
        self.assertEqual(code_normal, 0)
        self.assertIn("PASS", out_normal)

        code_strict, out_strict, err_strict = self._run_cli(
            ["check-staged", "--repo", str(self.repo_dir), "--strict"]
        )
        self.assertEqual(code_strict, 1)
        self.assertEqual(out_strict, "")
        self.assertIn("RG-HOST-003", err_strict)

    def test_repo_guard_json_warning_surfaced_text_and_json(self) -> None:
        (self.repo_dir / ".repo-guard.json").write_text(
            json.dumps({"allow_terms": ["alpha"], "unsupported_key": 1}),
            encoding="utf-8",
        )
        self._write("clean.txt", "hello world\n")
        self._git(["add", "clean.txt"])

        code, out, err = self._run_cli(["check-staged", "--repo", str(self.repo_dir)])
        self.assertEqual(code, 0)
        self.assertIn("PASS [pre-commit]", out)
        self.assertIn("repo-guard warning:", err)
        self.assertIn("unsupported_key", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-staged", "--repo", str(self.repo_dir)]
        )
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertTrue(any("unsupported_key" in w for w in payload["warnings"]))


class TestCheckCommitMsg(_GitCliCase):
    def test_missing_file_exits_two(self) -> None:
        msg = self.base / "does-not-exist.txt"
        code, out, err = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("commit message file not found", err)

    def test_clean_message_exits_zero_text_and_json(self) -> None:
        msg = self.base / "MSG"
        msg.write_text("feat: add portable config\n", encoding="utf-8")

        code, out, err = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 0)
        self.assertEqual(out, "repo-guard PASS [commit-msg]: 0 findings\n")
        self.assertEqual(err, "")

        code_j, out_j, err_j = self._run_cli(["--json", "check-commit-msg", str(msg)])
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["context"], "commit-msg")

    def test_leaky_message_exits_one_text_and_json(self) -> None:
        msg = self.base / "MSG"
        msg.write_text(f"feat: add config for {_identity()}\n", encoding="utf-8")
        code, out, err = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("repo-guard BLOCKED [commit-msg]", err)
        self.assertIn("RG-ID-001", err)

        msg.write_text(f"docs: endpoint {_lan_ip()}\n", encoding="utf-8")
        code_j, out_j, err_j = self._run_cli(["--json", "check-commit-msg", str(msg)])
        self.assertEqual(code_j, 1)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["context"], "commit-msg")
        self.assertGreaterEqual(payload["finding_count"], 1)

    def test_strict_flag_toggles_strict_only_host_detection(self) -> None:
        msg = self.base / "MSG"
        msg.write_text(f"feat: node {_strict_only_host()}\n", encoding="utf-8")

        code_normal, _, _ = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code_normal, 0)

        code_strict, _, err = self._run_cli(["check-commit-msg", str(msg), "--strict"])
        self.assertEqual(code_strict, 1)
        self.assertIn("RG-HOST-003", err)

    def test_repo_guard_json_warning_surfaced_when_cwd_inside_repo(self) -> None:
        (self.repo_dir / ".repo-guard.json").write_text(
            json.dumps({"bogus_key": 1}), encoding="utf-8"
        )
        msg = self.base / "MSG"
        msg.write_text("feat: clean message\n", encoding="utf-8")

        code, out, err = self._run_cli(["check-commit-msg", str(msg)], cwd=self.repo_dir)
        self.assertEqual(code, 0)
        self.assertIn("PASS [commit-msg]", out)
        self.assertIn("repo-guard warning:", err)
        self.assertIn("bogus_key", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-commit-msg", str(msg)], cwd=self.repo_dir
        )
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertTrue(any("bogus_key" in w for w in payload["warnings"]))

    def test_invalid_utf8_handled_cleanly(self) -> None:
        msg = self.base / "MSG"
        msg.write_bytes(b"\xff\xfe feat: bad bytes\n")
        code, out, err = self._run_cli(["check-commit-msg", str(msg)])
        self.assertEqual(code, 0)
        self.assertIn("PASS [commit-msg]", out)
        self.assertEqual(err, "")


class TestCheckPush(_GitCliCase):
    def test_outside_git_repo_exits_two_via_repo_flag_and_cwd(self) -> None:
        non_git = self.base / "not-a-repo"
        non_git.mkdir()

        code_flag, out_flag, err_flag = self._run_cli(
            ["check-push", "--repo", str(non_git)], stdin_text=""
        )
        self.assertEqual(code_flag, 2)
        self.assertEqual(out_flag, "")
        self.assertIn("not inside a git repository", err_flag)

        code_cwd, out_cwd, err_cwd = self._run_cli(
            ["check-push"], cwd=non_git, stdin_text=""
        )
        self.assertEqual(code_cwd, 2)
        self.assertEqual(out_cwd, "")
        self.assertIn("not inside a git repository", err_cwd)

    def test_clean_push_ref_exits_zero_text_and_json(self) -> None:
        sha_a = self._push_clean_initial_commit()
        sha_b = self._add_and_commit("more.txt", "more words\n", "feat: add more")
        stdin_text = f"refs/heads/main {sha_b} refs/heads/main {sha_a}\n"

        code, out, err = self._run_cli(
            ["check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "repo-guard PASS [pre-push]: 0 findings\n")
        self.assertEqual(err, "")

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["context"], "pre-push")

    def test_leaky_push_ref_exits_one_text_and_json(self) -> None:
        sha_a = self._push_clean_initial_commit()
        sha_b = self._add_and_commit("leak.txt", f'ip = "{_lan_ip()}"\n', "feat: add leak")
        stdin_text = f"refs/heads/main {sha_b} refs/heads/main {sha_a}\n"

        code, out, err = self._run_cli(
            ["check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("repo-guard BLOCKED [pre-push]", err)
        self.assertIn("RG-NET-002", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code_j, 1)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["context"], "pre-push")
        self.assertGreaterEqual(payload["finding_count"], 1)

    def test_remote_name_and_url_positionals_forwarded_to_check_push_refs(self) -> None:
        sha_a = self._push_clean_initial_commit()
        sha_b = self._add_and_commit("more.txt", "more words\n", "feat: add more")
        ref_line = f"refs/heads/main {sha_b} refs/heads/main {sha_a}"

        with mock.patch("repo_guard.cli.check_push_refs", return_value=[]) as spy:
            code, out, err = self._run_cli(
                [
                    "check-push",
                    "origin",
                    "git@example.com:repo.git",
                    "--repo",
                    str(self.repo_dir),
                ],
                stdin_text=ref_line + "\n",
            )
        self.assertEqual(code, 0)
        self.assertIn("PASS [pre-push]", out)
        self.assertEqual(err, "")
        spy.assert_called_once()
        _, call_kwargs = spy.call_args
        self.assertEqual(call_kwargs["remote_name"], "origin")
        self.assertEqual(spy.call_args.args[2], [ref_line])

    def test_strict_flag_toggles_strict_only_host_detection(self) -> None:
        sha_a = self._push_clean_initial_commit()
        sha_b = self._add_and_commit("node.txt", f"{_strict_only_host()}\n", "feat: add node")
        stdin_text = f"refs/heads/main {sha_b} refs/heads/main {sha_a}\n"

        code_normal, _, _ = self._run_cli(
            ["check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code_normal, 0)

        code_strict, _, err = self._run_cli(
            ["check-push", "--repo", str(self.repo_dir), "--strict"], stdin_text=stdin_text
        )
        self.assertEqual(code_strict, 1)
        self.assertIn("RG-HOST-003", err)

    def test_repo_guard_json_warning_surfaced_text_and_json(self) -> None:
        sha_a = self._push_clean_initial_commit()
        (self.repo_dir / ".repo-guard.json").write_text(
            json.dumps({"allow_terms": ["alpha"], "unsupported_key": 1}),
            encoding="utf-8",
        )
        sha_b = self._add_and_commit("more.txt", "more words\n", "feat: add more")
        stdin_text = f"refs/heads/main {sha_b} refs/heads/main {sha_a}\n"

        code, out, err = self._run_cli(
            ["check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code, 0)
        self.assertIn("PASS [pre-push]", out)
        self.assertIn("repo-guard warning:", err)
        self.assertIn("unsupported_key", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "check-push", "--repo", str(self.repo_dir)], stdin_text=stdin_text
        )
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertTrue(any("unsupported_key" in w for w in payload["warnings"]))


class TestAuditRepo(_GitCliCase):
    def test_nonexistent_target_exits_two(self) -> None:
        code, out, err = self._run_cli(["audit-repo", str(self.base / "no-such-dir")])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("path does not exist", err)

    def test_clean_repo_default_path_exits_zero_text_and_json(self) -> None:
        self._add_and_commit("clean.txt", "hello world\n", "feat: add clean")

        code, out, err = self._run_cli(["audit-repo"], cwd=self.repo_dir)
        self.assertEqual(code, 0)
        self.assertEqual(out, "repo-guard PASS [audit-repo]: 0 findings (1 files scanned)\n")
        self.assertEqual(err, "")

        code_j, out_j, err_j = self._run_cli(["--json", "audit-repo"], cwd=self.repo_dir)
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["context"], "audit-repo")
        self.assertEqual(payload["files_scanned"], 1)
        self.assertEqual(payload["finding_count"], 0)

    def test_leaky_repo_exits_one_text_and_json(self) -> None:
        self._add_and_commit("leak.txt", f'ip = "{_lan_ip()}"\n', "feat: add leak")

        code, out, err = self._run_cli(["audit-repo", str(self.repo_dir)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("repo-guard BLOCKED [audit-repo]", err)
        self.assertIn("RG-NET-002", err)

        code_j, out_j, err_j = self._run_cli(["--json", "audit-repo", str(self.repo_dir)])
        self.assertEqual(code_j, 1)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["context"], "audit-repo")
        self.assertEqual(payload["files_scanned"], 1)
        self.assertGreaterEqual(payload["finding_count"], 1)

    def test_strict_context_label_and_strict_only_toggle(self) -> None:
        self._add_and_commit("node.txt", f"{_strict_only_host()}\n", "feat: add node")

        code_normal, out_normal, _ = self._run_cli(["audit-repo", str(self.repo_dir)])
        self.assertEqual(code_normal, 0)
        self.assertIn("PASS [audit-repo]", out_normal)

        code_strict, out_strict, err_strict = self._run_cli(
            ["audit-repo", "--strict", str(self.repo_dir)]
        )
        self.assertEqual(code_strict, 1)
        self.assertEqual(out_strict, "")
        self.assertIn("repo-guard BLOCKED [audit-repo --strict]", err_strict)
        self.assertIn("RG-HOST-003", err_strict)

    def test_history_context_label_and_historical_leak_toggle(self) -> None:
        self._add_and_commit("hist.txt", f'ip = "{_lan_ip()}"\n', "feat: add hist")
        self._add_and_commit("hist.txt", "clean = true\n", "chore: clean hist")

        code_head, out_head, _ = self._run_cli(["audit-repo", str(self.repo_dir)])
        self.assertEqual(code_head, 0)
        self.assertIn("PASS [audit-repo]", out_head)

        code_hist, _, err_hist = self._run_cli(["audit-repo", "--history", str(self.repo_dir)])
        self.assertEqual(code_hist, 1)
        self.assertIn("repo-guard BLOCKED [audit-repo --history]", err_hist)
        self.assertIn("RG-NET-002", err_hist)

    def test_strict_and_history_combined_context_label_text_and_json(self) -> None:
        self._add_and_commit("hist.txt", f'ip = "{_lan_ip()}"\n', "feat: add hist")
        self._add_and_commit("hist.txt", "clean = true\n", "chore: clean hist")

        code, _, err = self._run_cli(
            ["audit-repo", "--strict", "--history", str(self.repo_dir)]
        )
        self.assertEqual(code, 1)
        self.assertIn("repo-guard BLOCKED [audit-repo --strict --history]", err)

        code_j, out_j, err_j = self._run_cli(
            ["--json", "audit-repo", "--strict", "--history", str(self.repo_dir)]
        )
        self.assertEqual(code_j, 1)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["context"], "audit-repo --strict --history")

    def test_non_git_directory_fallback_loads_repo_guard_json_warnings(self) -> None:
        target = self.base / "plain-dir"
        target.mkdir()
        (target / ".repo-guard.json").write_text(
            json.dumps({"unsupported_key": 1}), encoding="utf-8"
        )
        (target / "file.txt").write_text("hello world\n", encoding="utf-8")

        code, out, err = self._run_cli(["audit-repo", str(target)])
        self.assertEqual(code, 0)
        self.assertIn("PASS [audit-repo]: 0 findings (2 files scanned)", out)
        self.assertIn("repo-guard warning:", err)
        self.assertIn("unsupported_key", err)

        code_j, out_j, err_j = self._run_cli(["--json", "audit-repo", str(target)])
        self.assertEqual(code_j, 0)
        self.assertEqual(err_j, "")
        payload = json.loads(out_j)
        self.assertEqual(payload["files_scanned"], 2)
        self.assertTrue(any("unsupported_key" in w for w in payload["warnings"]))


class TestModuleEntrypoint(unittest.TestCase):
    def test_python_m_repo_guard_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "repo_guard", "--version"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"repo-guard {__version__}")

    def test_python_m_repo_guard_cli_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "repo_guard.cli", "--version"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"repo-guard {__version__}")


if __name__ == "__main__":
    unittest.main()
