# repo-guard

Deterministic global Git hooks and 12-Factor open-source hygiene guardrail written in zero-dependency Python 3 stdlib.

`repo-guard` blocks accidental commits or pushes of secrets, credentials, hardcoded OS home paths (`/home/<user>/`, `/Users/<user>/`, `C:\Users\<user>\`), private LAN/tailnet IPs, `*.ts.net` FQDNs, private infrastructure hostnames, and personal identities — **before** they enter Git history or leave your machine.

## Design Principles (12-Factor Factor III)

- **Zero environment assumptions in source**: `repo-guard` contains no hardcoded usernames, hostnames, domains, or personal identities.
- **Private local pattern store**: Machine-specific patterns live outside any repository at `$REPO_GUARD_CONFIG` or `$XDG_CONFIG_HOME/repo-guard/private-patterns.json` (`0600`), merged at runtime with auto-detected `getpass.getuser()`, `socket.gethostname()`, and `Path.home()`.
- **Hard security ceiling**: Optional per-repository `.repo-guard.json` (`allow_terms`, `allow_paths`, `allow_author_emails`) can narrow non-ceiling rules only. It can **never** disable `secret`, `tailnet_fqdn`, `private_ip`, `home_path`, or `personal_identity` rules.
- **Redacted previews**: Findings report exact `file:line`, rule ID, redacted snippet (never echoing full secrets), and an actionable 12-Factor remediation hint.

## Quick Start

```bash
# 1. Initialize your machine-local private patterns (0600, outside any repo)
repo-guard init-local \
  --add-identity "Jane Doe" \
  --add-identity "janedoe.example"

# 2. Install global Git hooks (example using ~/.config/git/hooks)
git config --global core.hooksPath "$HOME/.config/git/hooks"

# 3. Audit any repository before open-sourcing
repo-guard audit-repo --strict /path/to/your-repo
```

## Commands

| Command | Purpose |
|---|---|
| `repo-guard init-local` | Create/refresh `$XDG_CONFIG_HOME/repo-guard/private-patterns.json` (`0600`) from local user, `$HOME`, hostname, read-only `tailscale status --json` (if installed), and CLI flags. |
| `repo-guard check-staged` | Scan staged filenames and added diff lines (`pre-commit`). |
| `repo-guard check-commit-msg <file>` | Scan commit message text (`commit-msg`). |
| `repo-guard check-push [remote] [url]` | Scan commit diffs, filenames, messages, and author metadata for refs on stdin (`pre-push`). |
| `repo-guard audit-repo [--strict] [--history] [path]` | Full repository audit for open-source publish readiness. |

## Rule Reference

| Rule ID | Category | Hard Ceiling | What It Blocks |
|---|---|---|---|
| `RG-FILE-001` | `secret` | Yes | `.env`, `.env.*` (allowing `.env.example`/`.sample`/`.template`/`.dist`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.enc`, `id_rsa*`, `id_ed25519*`, `credentials.json`, `secrets.*`, `vault.key`, `vault.enc`, `queues.json` |
| `RG-SEC-001..009` | `secret` | Yes | PEM private keys, AWS keys, GitHub tokens, Stripe keys, OpenAI/Anthropic keys, Slack tokens, JWTs, Luhn-validated payment PANs, hardcoded non-placeholder secret assignments |
| `RG-PATH-001` | `home_path` | Yes | Hardcoded `/home/<user>/`, `/Users/<user>/`, `C:\Users\<user>\` (generic doc placeholders like `/home/user/` allowed unless matching local username) |
| `RG-NET-001` | `tailnet_fqdn` | Yes | Any `*.ts.net` hostname or configured local tailnet domain |
| `RG-NET-002` | `private_ip` | Yes | RFC 1918 private LAN IPv4 ranges (allows loopback `127.0.0.1` / `0.0.0.0` and RFC 5737 doc ranges `192.0.2.x`, `198.51.100.x`, `203.0.113.x`) |
| `RG-NET-003` | `private_ip` | Yes | Tailscale CGNAT IPv4 (`100.64/10`) and ULA IPv6 |
| `RG-NET-004` | `private_url` | No | Hardcoded non-loopback `http(s)://<private-host>:<port>` URLs |
| `RG-ID-001` | `personal_identity` | Yes | Configured personal names, handles, emails, and private domains |
| `RG-HOST-001` | `private_host` | No | Configured `strict_hosts` (standalone tokens) |
| `RG-HOST-002` | `private_host_context` | No | Configured `context_hosts` paired with URL/port/SSH/host config syntax |
| `RG-HOST-003` | `private_host_strict` | No | Configured `strict_only_hosts` standalone in `--strict` mode |

## Per-Repository Policy (`.repo-guard.json`)

```json
{
  "allow_paths": ["docs/architecture.md"],
  "allow_terms": ["internal-demo-host"],
  "allow_author_emails": ["dev@example.com"]
}
```

Hard-ceiling categories (`secret`, `tailnet_fqdn`, `private_ip`, `home_path`, `personal_identity`) can never be disabled by `.repo-guard.json`.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
