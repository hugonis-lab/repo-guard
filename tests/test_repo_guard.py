"""Unit and real Git hook integration tests for repo-guard.

All synthetic secret/IP/path fixtures are constructed dynamically at runtime so
this test file itself passes `repo-guard audit-repo --strict` with zero findings.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN_PATH = ROOT / "bin" / "repo-guard"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repo_guard.config import (  # noqa: E402
    GuardConfig,
    PrivatePatterns,
    RepoPolicy,
    init_local_config,
    load_repo_policy,
)
from repo_guard.scanner import RepoScanner, scan_commit_message  # noqa: E402


def _make_config(
    *,
    strict: bool = False,
    repo_policy: RepoPolicy | None = None,
) -> GuardConfig:
    patterns = PrivatePatterns(
        usernames=["devuser99"],
        home_paths=["/" + "home" + "/devuser99"],
        tailnet_domains=["alpha-beta." + "ts" + ".net"],
        strict_hosts=["lab-node-7", "alpha-beta"],
        context_hosts=["pointer", "helios", "reefnode"],
        strict_only_hosts=["reefnode"],
        private_identities=["Taylor Exampleperson", "texamplehandle", "taylor@" + "private-domain.test"],
    )
    return GuardConfig(
        patterns=patterns.normalized(),
        repo_policy=repo_policy or RepoPolicy(),
        strict=strict,
    )


class TestScannerUnit(unittest.TestCase):
    def test_blocked_and_allowed_filenames(self) -> None:
        scanner = RepoScanner(_make_config())
        blocked = [
            ".env",
            ".env.local",
            ".env.production",
            "certs/server.key",
            "certs/ca.pem",
            "certs/bundle.p12",
            "certs/app.pfx",
            "state/vault.enc",
            "state/vault.key",
            "ssh/id_rsa",
            "ssh/id_ed25519",
            "credentials.json",
            "secrets.yaml",
            "runtime/queues.json",
        ]
        for path in blocked:
            hits = scanner.check_filename(path)
            self.assertTrue(
                any(h.rule_id == "RG-FILE-001" for h in hits),
                f"Expected RG-FILE-001 for {path}",
            )

        allowed = [
            ".env.example",
            ".env.sample",
            ".env.template",
            "ssh/id_ed25519.pub",
            "secrets.yaml.example",
            "src/config.py",
        ]
        for path in allowed:
            self.assertEqual(scanner.check_filename(path), [], f"Unexpected hit for {path}")

    def test_secret_rules_and_redaction(self) -> None:
        scanner = RepoScanner(_make_config())

        # Dynamically constructed synthetic secrets (zero literals in source).
        pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
        aws = "AKIA" + "0123456789ABCDEF"
        gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1L2"
        stripe = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQr"
        ai_key = "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz"
        slack = "xoxb-" + "1234567890-abcdef123456"
        jwt = (
            "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        # Synthetic Visa-prefix Luhn-valid 16-digit PAN (4242...4242).
        pan_valid = "-".join(["4242", "4242", "4242", "4242"])
        pan_invalid = "-".join(["4242", "4242", "4242", "4243"])
        hardcoded_assign = 'API_KEY = "' + "prod_9f8e7d6c5b4a3210" + '"'

        cases = [
            (pem, "RG-SEC-001"),
            (f'aws_id = "{aws}"', "RG-SEC-002"),
            (f'token = "{gh}"', "RG-SEC-003"),
            (f'stripe = "{stripe}"', "RG-SEC-004"),
            (f'llm = "{ai_key}"', "RG-SEC-005"),
            (f'slack = "{slack}"', "RG-SEC-006"),
            (f'auth = "Bearer {jwt}"', "RG-SEC-007"),
            (f'card = "{pan_valid}"', "RG-SEC-008"),
            (hardcoded_assign, "RG-SEC-009"),
        ]
        for line, expected_rule in cases:
            hits = scanner.scan_line("app.py", 1, line)
            matched = [h for h in hits if h.rule_id == expected_rule]
            self.assertTrue(matched, f"Expected {expected_rule} for line")
            # Ensure snippet NEVER echoes the full secret back.
            for h in matched:
                self.assertIn("REDACTED", h.snippet)
                self.assertNotIn(aws, h.snippet)
                self.assertNotIn(gh, h.snippet)
                self.assertNotIn(stripe, h.snippet)
                self.assertNotIn(pan_valid, h.snippet)

        # Non-Luhn 16-digit number should NOT trigger RG-SEC-008.
        hits_invalid_pan = scanner.scan_line("app.py", 2, f'id = "{pan_invalid}"')
        self.assertFalse(any(h.rule_id == "RG-SEC-008" for h in hits_invalid_pan))

        # Placeholders and env refs should NOT trigger RG-SEC-009.
        clean_lines = [
            'API_KEY = "your_api_key_here"',
            'API_KEY = "OPENAI_API_KEY"',
            'SECRET_KEY="${MY_SECRET_KEY}"',
            'TOKEN = "Missing auth token in header"',
            "PASSWORD=changeme_in_prod",
        ]
        for line in clean_lines:
            hits = scanner.scan_line(".env.example", 1, line)
            self.assertEqual(hits, [], f"Unexpected hit on placeholder line: {line} -> {hits}")

    def test_home_paths_and_generic_placeholders(self) -> None:
        scanner = RepoScanner(_make_config())

        bad_paths = [
            "/" + "home" + "/jdoe/projects/app",
            "/" + "home" + "/devuser99/.config/app",
            "/" + "Users" + "/mscott/src/app",
            "C:\\" + "Users" + "\\jdoe\\AppData",
        ]
        for p in bad_paths:
            hits = scanner.scan_line("cfg.py", 1, f'p = "{p}"')
            self.assertTrue(any(h.rule_id == "RG-PATH-001" for h in hits), f"Expected RG-PATH-001 for {p}")

        # Generic doc placeholders are allowed when not matching local username.
        allowed_paths = [
            "/" + "home" + "/user/projects/app",
            "/" + "Users" + "/example/src/app",
            "/" + "home" + "/<user>/.config/app",
        ]
        for p in allowed_paths:
            hits = scanner.scan_line("README.md", 1, f"Path: `{p}`")
            self.assertEqual(hits, [], f"Unexpected hit on generic placeholder {p}: {hits}")

        # If local username happens to be "alice", /home/alice/ MUST still be blocked.
        cfg_alice = GuardConfig(patterns=PrivatePatterns(usernames=["alice"]).normalized())
        hits_alice = RepoScanner(cfg_alice).scan_line("README.md", 1, "/" + "home" + "/alice/work")
        self.assertTrue(any(h.rule_id == "RG-PATH-001" for h in hits_alice))

    def test_network_rules_and_allowances(self) -> None:
        scanner = RepoScanner(_make_config())

        ts_fqdn = "box1.alpha-beta." + "ts" + ".net"
        lan_ip_1 = ".".join(["192", "168", "1", "36"])
        lan_ip_2 = ".".join(["10", "0", "4", "12"])
        lan_ip_3 = ".".join(["172", "20", "5", "9"])
        cgnat_ip = ".".join(["100", "114", "98", "77"])
        ts_ipv6 = ":".join(["fd7a", "115c", "a1e0", "ab12", "", "1"])
        priv_url = "http://" + "internalbox" + ":8080/v1"

        self.assertTrue(any(h.rule_id == "RG-NET-001" for h in scanner.scan_line("a.py", 1, f"url = 'https://{ts_fqdn}'")))
        for ip in (lan_ip_1, lan_ip_2, lan_ip_3):
            self.assertTrue(any(h.rule_id == "RG-NET-002" for h in scanner.scan_line("a.py", 1, f"HOST={ip}")))
        self.assertTrue(any(h.rule_id == "RG-NET-003" for h in scanner.scan_line("a.py", 1, f"HOST={cgnat_ip}")))
        self.assertTrue(any(h.rule_id == "RG-NET-003" for h in scanner.scan_line("a.py", 1, f"HOST={ts_ipv6}")))
        self.assertTrue(any(h.rule_id == "RG-NET-004" for h in scanner.scan_line("a.py", 1, f'URL = "{priv_url}"')))

        # Loopback and RFC 5737 doc ranges must be allowed cleanly.
        for ok in ("http://127.0.0.1:8080", "http://localhost:3000", "0.0.0.0", "192.0.2.10", "198.51.100.5", "203.0.113.42"):
            self.assertEqual(scanner.scan_line("a.py", 1, f'v = "{ok}"'), [], f"Unexpected hit for {ok}")

    def test_identities_and_smart_host_splitting(self) -> None:
        normal_scanner = RepoScanner(_make_config(strict=False))
        strict_scanner = RepoScanner(_make_config(strict=True))

        # Personal identity always blocked.
        self.assertTrue(
            any(h.rule_id == "RG-ID-001" for h in normal_scanner.scan_line("doc.md", 1, "Author: Taylor Exampleperson"))
        )
        self.assertTrue(
            any(h.rule_id == "RG-ID-001" for h in normal_scanner.scan_line("doc.md", 1, "Contact taylor@" + "private-domain.test"))
        )

        # strict_hosts always blocked standalone.
        self.assertTrue(
            any(h.rule_id == "RG-HOST-001" for h in normal_scanner.scan_line("doc.md", 1, "Deployed on lab-node-7 today"))
        )

        # context_hosts allowed in plain prose/CSS, blocked in network syntax.
        self.assertEqual(normal_scanner.scan_line("style.css", 1, "button { pointer-events: none; }"), [])
        self.assertEqual(normal_scanner.scan_line("notes.md", 1, "The helios renderer works fast."), [])
        self.assertTrue(
            any(h.rule_id == "RG-HOST-002" for h in normal_scanner.scan_line("cfg.py", 1, "URL = 'ht" + "tp://helios:4000'"))
        )
        self.assertTrue(
            any(h.rule_id == "RG-HOST-002" for h in normal_scanner.scan_line("deploy.sh", 1, "ssh ops@" + "pointer"))
        )
        self.assertTrue(
            any(h.rule_id == "RG-HOST-002" for h in normal_scanner.scan_line("cfg.toml", 1, 'host = "' + 'pointer"'))
        )

        # strict_only_hosts allowed as prose in normal mode, blocked in --strict mode.
        self.assertEqual(normal_scanner.scan_line("notes.md", 1, "Using reefnode for inference"), [])
        self.assertTrue(
            any(h.rule_id == "RG-HOST-003" for h in strict_scanner.scan_line("notes.md", 1, "Using reefnode for inference"))
        )

    def test_repo_policy_hard_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo_dir = Path(td)
            (repo_dir / ".repo-guard.json").write_text(
                json.dumps(
                    {
                        "allow_paths": ["*"],
                        "allow_terms": ["helios", "reefnode", "texamplehandle"],
                        "disable_rules": ["RG-SEC-002", "RG-PATH-001", "RG-NET-001"],
                    }
                ),
                encoding="utf-8",
            )
            policy = load_repo_policy(repo_dir)
            self.assertTrue(policy.warnings, "Expected warning for forbidden disable_rules key")

            scanner = RepoScanner(_make_config(strict=True, repo_policy=policy))
            # Non-ceiling context/strict host allowed via .repo-guard.json.
            self.assertEqual(scanner.scan_line("docs.md", 1, "Mentioning reefnode in docs"), [])
            self.assertEqual(scanner.scan_line("docs.md", 1, 'host = "' + 'helios"'), [])

            # Hard-ceiling categories MUST still block even with allow_paths=["*"]!
            aws = "AKIA" + "9999888877776666"
            lan_ip = ".".join(["192", "168", "9", "9"])
            ts_host = "box.demo." + "ts" + ".net"
            home_p = "/" + "home" + "/jdoe/app"

            self.assertTrue(any(h.rule_id == "RG-SEC-002" for h in scanner.scan_line("docs.md", 1, aws)))
            self.assertTrue(any(h.rule_id == "RG-NET-002" for h in scanner.scan_line("docs.md", 1, lan_ip)))
            self.assertTrue(any(h.rule_id == "RG-NET-001" for h in scanner.scan_line("docs.md", 1, ts_host)))
            self.assertTrue(any(h.rule_id == "RG-PATH-001" for h in scanner.scan_line("docs.md", 1, home_p)))
            self.assertTrue(any(h.rule_id == "RG-ID-001" for h in scanner.scan_line("docs.md", 1, "texamplehandle")))

    def test_init_local_creates_0600_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / "sub" / "private-patterns.json"
            out_path, pats = init_local_config(
                config_path=cfg_path,
                add_identities=["Taylor Exampleperson"],
                add_strict_hosts=["lab-node-9"],
                include_tailscale=False,
            )
            self.assertEqual(out_path, cfg_path)
            self.assertTrue(cfg_path.is_file())
            mode = stat.S_IMODE(cfg_path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertIn("Taylor Exampleperson", pats.private_identities)
            self.assertIn("lab-node-9", pats.strict_hosts)

    def test_commit_msg_skips_git_comments(self) -> None:
        scanner = RepoScanner(_make_config())
        bad_ip = ".".join(["192", "168", "1", "36"])
        msg_only_comment = f"feat: clean commit\n# On branch main\n# modified: {bad_ip}\n"
        self.assertEqual(scan_commit_message(scanner, msg_only_comment), [])
        msg_leak = "feat: add config for Taylor Exampleperson\n"
        hits = scan_commit_message(scanner, msg_leak)
        self.assertTrue(any(h.rule_id == "RG-ID-001" for h in hits))


class TestGitHooksIntegration(unittest.TestCase):
    """End-to-end tests running real git pre-commit, commit-msg, and pre-push hooks."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.hooks_dir = self.base / "hooks"
        self.hooks_dir.mkdir(parents=True)
        self.repo_dir = self.base / "work"
        self.repo_dir.mkdir()
        self.remote_dir = self.base / "remote.git"
        self.cfg_path = self.base / "private-patterns.json"

        # Write isolated private-patterns.json for deterministic hook tests.
        init_local_config(
            config_path=self.cfg_path,
            add_identities=["Taylor Exampleperson", "taylor@" + "private-domain.test"],
            add_strict_hosts=["lab-node-7"],
            add_context_hosts=["reefnode"],
            add_strict_only_hosts=["reefnode"],
            include_tailscale=False,
        )

        # Install executable hooks matching production global hook wrapper behavior.
        self._write_hook(
            "pre-commit",
            f'#!/usr/bin/env bash\nset -euo pipefail\nexec "{BIN_PATH}" check-staged\n',
        )
        self._write_hook(
            "commit-msg",
            f'#!/usr/bin/env bash\nset -euo pipefail\nexec "{BIN_PATH}" check-commit-msg "$1"\n',
        )
        self._write_hook(
            "pre-push",
            f'#!/usr/bin/env bash\nset -euo pipefail\nexec "{BIN_PATH}" check-push "${{1:-}}" "${{2:-}}"\n',
        )

        self.env = os.environ.copy()
        self.env["REPO_GUARD_CONFIG"] = str(self.cfg_path)

        self._git(["init", "-b", "main"], cwd=self.repo_dir, check=True)
        self._git(["config", "core.hooksPath", str(self.hooks_dir)], cwd=self.repo_dir, check=True)
        self._git(["config", "user.name", "OSS Maintainer"], cwd=self.repo_dir, check=True)
        self._git(["config", "user.email", "maintainer@example.com"], cwd=self.repo_dir, check=True)

        self._git(["init", "--bare", str(self.remote_dir)], cwd=self.base, check=True)
        self._git(["remote", "add", "origin", str(self.remote_dir)], cwd=self.repo_dir, check=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_hook(self, name: str, body: str) -> None:
        p = self.hooks_dir / name
        p.write_text(body, encoding="utf-8")
        os.chmod(p, 0o755)

    def _git(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.repo_dir),
            env=self.env,
            capture_output=True,
            text=True,
            check=check,
        )

    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BIN_PATH), *args],
            cwd=str(self.repo_dir),
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_live_hooks_block_leaks_and_allow_clean_12factor(self) -> None:
        # 1. Clean 12-Factor commit + .env.example passes with exit 0.
        (self.repo_dir / ".env.example").write_text(
            "API_BASE_URL=http://127.0.0.1:8080\nAPI_KEY=your_api_key_here\n",
            encoding="utf-8",
        )
        (self.repo_dir / "app.py").write_text(
            'import os\nfrom pathlib import Path\nBASE = os.environ.get("API_BASE_URL", "http://127.0.0.1:8080")\nCFG = Path.home() / ".config" / "app"\n',
            encoding="utf-8",
        )
        self._git(["add", ".env.example", "app.py"], check=True)
        res = self._git(["commit", "-m", "feat: add portable 12-factor app"])
        self.assertEqual(res.returncode, 0, f"Clean commit failed: {res.stderr}")

        # 2. Staged secret blocked by pre-commit.
        secret_tok = "sk_" + "live_" + "9876543210abcdefghij"
        (self.repo_dir / "leak.py").write_text(f'KEY = "{secret_tok}"\n', encoding="utf-8")
        self._git(["add", "leak.py"], check=True)
        res = self._git(["commit", "-m", "feat: add payment config"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-SEC-004", res.stderr)
        self.assertNotIn(secret_tok, res.stderr)
        self._git(["reset", "HEAD", "leak.py"], check=True)
        (self.repo_dir / "leak.py").unlink()

        # 3. Hardcoded /home/<user> path blocked by pre-commit.
        bad_home = "/" + "home" + "/jdoe/secret-dir"
        (self.repo_dir / "paths.py").write_text(f'DATA = "{bad_home}"\n', encoding="utf-8")
        self._git(["add", "paths.py"], check=True)
        res = self._git(["commit", "-m", "feat: add paths"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-PATH-001", res.stderr)
        self._git(["reset", "HEAD", "paths.py"], check=True)
        (self.repo_dir / "paths.py").unlink()

        # 4. *.ts.net, RFC 1918 LAN IP, and Tailscale CGNAT IP blocked by pre-commit.
        ts_fqdn = "node1.demo." + "ts" + ".net"
        lan_ip = ".".join(["192", "168", "1", "36"])
        cgnat_ip = ".".join(["100", "114", "98", "77"])
        (self.repo_dir / "net.py").write_text(
            f'A = "{ts_fqdn}"\nB = "{lan_ip}"\nC = "{cgnat_ip}"\n',
            encoding="utf-8",
        )
        self._git(["add", "net.py"], check=True)
        res = self._git(["commit", "-m", "feat: add network endpoints"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-NET-001", res.stderr)
        self.assertIn("RG-NET-002", res.stderr)
        self.assertIn("RG-NET-003", res.stderr)
        self._git(["reset", "HEAD", "net.py"], check=True)
        (self.repo_dir / "net.py").unlink()

        # 5. Private identity / personal email blocked by pre-commit AND commit-msg.
        priv_email = "taylor@" + "private-domain.test"
        (self.repo_dir / "author.txt").write_text(f"Maintainer: {priv_email}\n", encoding="utf-8")
        self._git(["add", "author.txt"], check=True)
        res = self._git(["commit", "-m", "docs: add author"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-ID-001", res.stderr)
        self._git(["reset", "HEAD", "author.txt"], check=True)
        (self.repo_dir / "author.txt").unlink()

        (self.repo_dir / "clean.txt").write_text("hello world\n", encoding="utf-8")
        self._git(["add", "clean.txt"], check=True)
        res = self._git(["commit", "-m", f"docs: credited to {priv_email}"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-ID-001", res.stderr)
        self._git(["reset", "HEAD", "clean.txt"], check=True)
        (self.repo_dir / "clean.txt").unlink()

        # 6. .env blocked by pre-commit.
        (self.repo_dir / ".env").write_text("PORT=8080\n", encoding="utf-8")
        self._git(["add", "-f", ".env"], check=True)
        res = self._git(["commit", "-m", "chore: add env"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-FILE-001", res.stderr)
        self._git(["reset", "HEAD", ".env"], check=True)
        (self.repo_dir / ".env").unlink()

        # 7. Clean push succeeds to bare remote.
        res_push_ok = self._git(["push", "-u", "origin", "main"])
        self.assertEqual(res_push_ok.returncode, 0, f"Clean push failed: {res_push_ok.stderr}")

        # 8. Clean repo passes audit-repo --strict.
        res_audit_ok = self._run_cli(["audit-repo", "--strict", str(self.repo_dir)])
        self.assertEqual(res_audit_ok.returncode, 0, res_audit_ok.stderr)

        # 9. pre-push blocks pushing a commit if a leak slipped past local pre-commit.
        leaked_ip = ".".join(["100", "114", "98", "77"])
        (self.repo_dir / "slipped.py").write_text(f'TARGET = "{leaked_ip}"\n', encoding="utf-8")
        self._git(["add", "slipped.py"], check=True)
        # Simulate bypassed commit in isolated test to verify pre-push defense-in-depth.
        self._git(["commit", "--no-verify", "-m", "feat: slipped commit"], check=True)

        res_push_block = self._git(["push", "origin", "main"])
        self.assertNotEqual(res_push_block.returncode, 0)
        self.assertIn("RG-NET-003", res_push_block.stderr)

        # audit-repo --strict also catches it.
        res_audit_fail = self._run_cli(["audit-repo", "--strict", str(self.repo_dir)])
        self.assertEqual(res_audit_fail.returncode, 1)
        self.assertIn("RG-NET-003", res_audit_fail.stderr)


if __name__ == "__main__":
    unittest.main()
