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
import time
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

    def test_ui_emoji_guard_blocks_literal_and_encoded_emojis_with_zero_false_positives(self) -> None:
        scanner = RepoScanner(_make_config())

        # Dynamically build emoji fixtures so test file contains zero literal emojis.
        rocket = chr(0x1F680)
        bolt = chr(0x26A1)
        warn_vs16 = chr(0x26A0) + chr(0xFE0F)
        wrench_smp = chr(0x1F6E0)
        keycap = "1" + chr(0xFE0F) + chr(0x20E3)
        flag_us = chr(0x1F1FA) + chr(0x1F1F8)
        zwj_family = chr(0x1F469) + chr(0x200D) + chr(0x1F4BB)

        blocked_cases = [
            ("public/index.html", f"<button>{rocket} Deploy</button>"),
            ("src/App.tsx", f"const badge = '{bolt} Fast';"),
            ("src/Banner.vue", f"<p>{warn_vs16} Disk almost full</p>"),
            ("src/Toolbar.svelte", f"<span>{wrench_smp} Tools</span>"),
            ("ui/Main.qml", f'text: "{keycap} First step"'),
            ("public/header.html", f"<span>{flag_us} EN</span>"),
            ("public/app.js", f'el.textContent = "{zwj_family} Engineer";'),
            ("public/index.html", "<span>&#x1F680; Launch</span>"),
            ("public/index.html", "<span>&#128640; Launch</span>"),
            ("public/index.html", "<span>&#x26A0;&#xFE0F; Caution</span>"),
            ("src/ui.ts", r'const label = "\u{1F4AC} Reply";'),
            ("src/ui.js", r'const icon = "\uD83D\uDE80";'),
            ("src/ui.ts", r'const warn = "\u26A0\uFE0F";'),
            ("public/styles.css", r'.cta::before { content: "\1F680"; }'),
            ("public/styles.scss", r'.pill::after { content: "\01F4AC "; }'),
        ]
        for rel_path, line in blocked_cases:
            hits = scanner.scan_line(rel_path, 1, line)
            self.assertTrue(
                any(h.rule_id == "RG-UI-001" for h in hits),
                f"Expected RG-UI-001 for {rel_path}: {line!r}",
            )

        # Clean monochrome symbols, SVG icons, tests, regex ranges, and non-UI docs must NOT trigger RG-UI-001.
        allowed_cases = [
            ("public/index.html", "<button>&#x2713; Save &copy; 2026 &rarr;</button>"),
            ("src/App.tsx", 'const glyphs = "✓ ✗ ✕ ✎ ✦ ▸ ▶ ○ ● ★ → ↗ ↩ ⌘ © ® ™ — …";'),
            ("public/styles.css", '.item::before { content: "\\2022 "; }'),
            ("src/validator.ts", r"const rangeRe = /[\u{1F000}-\u{1FAFF}]/u;"),
            ("tests/app.test.tsx", f'expect(strip("{rocket} ok")).toBe("ok");'),
            ("src/__tests__/ui.spec.ts", f'const fixture = "{bolt}";'),
            ("tests/fixtures/emoji.html", f"<p>{rocket}</p>"),
            ("README.md", f"# Demo {rocket}"),
            ("scripts/cli.py", f'print("{rocket} done")'),
        ]
        for rel_path, line in allowed_cases:
            hits = scanner.scan_line(rel_path, 1, line)
            self.assertEqual(
                [h for h in hits if h.rule_id == "RG-UI-001"],
                [],
                f"Unexpected RG-UI-001 for {rel_path}: {line!r} -> {hits}",
            )

    def test_prefilter_parity_edge_cases_and_linear_time_host_scan(self) -> None:
        patterns = PrivatePatterns(
            usernames=["devuser99"],
            home_paths=["/" + "home" + "/devuser99"],
            tailnet_domains=["alpha-beta." + "ts" + ".net"],
            strict_hosts=["lab-node-7", "alpha-beta", "Multi Word Host", "dot.host"],
            context_hosts=["pointer", "helios", "reefnode", "my.ctx", "ping", "alpha"],
            strict_only_hosts=["reefnode", "Strict Multi"],
            private_identities=["Taylor Exampleperson", "texamplehandle", "taylor@" + "private-domain.test"],
            extra_blocked_terms=["secret-codename", "two words term"],
        )
        scanner = RepoScanner(GuardConfig(patterns=patterns.normalized(), strict=True))

        # Verify scan_text matches scan_line identically across tricky context-host,
        # ordering, Unicode casefold (U+0130, U+0131, U+017F, U+212A), and multi-word rules.
        lines = [
            "Hosts: dot.host lab-node-7 alpha-beta Multi   Word Host",
            "Strict: reefnode Strict  Multi secret-codename two  words\tterm",
            "Context URL: ht" + "tps://user@helios:8443/v1 and red" + "is://my.ctx:6379",
            "Context port/tld: pointer:8080 helios.local reefnode.home.arpa",
            "Context cli: ssh ops@pointer && ssh alpha@alpha && ping ping",
            "Context repeated cli: ssh a@pointer ssh b@pointer",
            "Context user@host: a@pointer@pointer and a@b@pointer and @pointer",
            'Context assign: host = "pointer" server_host: helios vllm_host="my.ctx" host="pointer"foo',
            "Unicode fold: ht" + "tp://hel\u0130os:8080 host=hel\u0131os host=helio\u017f API_\u212aEY = \"prod_9f8e7d6c5b4a3210\"",
            "Clean prose with non-ASCII em-dash — pointer-events: none; cursor: pointer;",
        ]
        for rel_path in ("ops.sh", "public/app.js"):
            text = "\n".join(lines) + "\n"
            via_text = scanner.scan_text(rel_path, text)
            via_lines = []
            for idx, line in enumerate(lines, start=1):
                via_lines.extend(scanner.scan_line(rel_path, idx, line))
            self.assertEqual(via_text, via_lines, f"scan_text/scan_line mismatch for {rel_path}")

        # Verify exact context-host edge semantics (a@pointer@pointer matches once; @pointer does not match).
        at_hits = [h for h in scanner.scan_line("ops.sh", 1, "a@pointer@pointer") if h.rule_id == "RG-HOST-002"]
        self.assertEqual(len(at_hits), 1)
        bare_at_hits = [h for h in scanner.scan_line("ops.sh", 1, "@pointer") if h.rule_id == "RG-HOST-002"]
        self.assertEqual(bare_at_hits, [])

        # Regression guard against O(N^2) backtracking on long lines in user@host and cli context rules.
        t0 = time.perf_counter()
        self.assertEqual(scanner.scan_line("big.txt", 1, "a" * 50_000 + " @pointer"), [])
        hit_u = scanner.scan_line("big.txt", 2, "a" * 50_000 + " u@pointer")
        self.assertTrue(any(h.rule_id == "RG-HOST-002" for h in hit_u))
        self.assertEqual(scanner.scan_line("big.txt", 3, "ssh " * 5_000 + "foo.pointer"), [])
        hit_cli = scanner.scan_line("big.txt", 4, "ssh " * 5_000 + "pointer")
        self.assertTrue(any(h.rule_id == "RG-HOST-002" for h in hit_cli))
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"Long-line host scan regressed to {elapsed:.3f}s")


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

        # 6b. User-facing UI emoji blocked by pre-commit; clean monochrome SVG UI allowed.
        rocket = chr(0x1F680)
        (self.repo_dir / "index.html").write_text(f"<button>{rocket} Launch</button>\n", encoding="utf-8")
        self._git(["add", "index.html"], check=True)
        res = self._git(["commit", "-m", "feat: add launch button"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RG-UI-001", res.stderr)
        self._git(["reset", "HEAD", "index.html"], check=True)

        (self.repo_dir / "index.html").write_text(
            '<button><svg aria-hidden="true" viewBox="0 0 16 16"></svg> Launch</button>\n',
            encoding="utf-8",
        )
        self._git(["add", "index.html"], check=True)
        res_ui_ok = self._git(["commit", "-m", "feat: add clean svg launch button"])
        self.assertEqual(res_ui_ok.returncode, 0, f"Clean UI commit failed: {res_ui_ok.stderr}")

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
