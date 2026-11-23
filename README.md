# Repo Guard

Block secrets, private hostnames, local paths, and personal emails from entering your Git history.

Repo Guard runs as global Git hooks (`pre-commit`, `commit-msg`, `pre-push`) and as a strict pre-publish repository auditor. It runs on plain Python 3 with zero third-party packages and keeps your private pattern list outside Git.

## Installation

Requires Python 3.11+ and Git. Ensure `$HOME/.local/bin` is on your `PATH`.

```bash
chmod +x bin/repo-guard
ln -sf "$PWD/bin/repo-guard" "$HOME/.local/bin/repo-guard"
```

## Quick Start

Initialize your machine-local pattern file (`0600`, stored outside any repo):

```bash
repo-guard init-local \
  --add-identity "Jane Doe" \
  --add-identity "janedoe.example"
```

Expected output: `repo-guard initialized local private config at ~/.config/repo-guard/private-patterns.json (mode 0600)`.

Enable global Git hooks so every repository on your machine is checked before commit and push:

```bash
git config --global core.hooksPath "$HOME/.config/git/hooks"
```

Audit any repository before open-sourcing or pushing publicly:

```bash
repo-guard audit-repo --strict /path/to/your-repo
```

Clean repositories print `repo-guard PASS [audit-repo --strict]: 0 findings` and exit `0`. Any match exits `1` with the exact `file:line`, rule ID, redacted snippet, and fix suggestion.

## Commands

| Command | Purpose |
| :--- | :--- |
| `repo-guard init-local` | Generate `$XDG_CONFIG_HOME/repo-guard/private-patterns.json` (`0600`) from local user, hostname, Tailscale status, and CLI flags |
| `repo-guard check-staged` | Scan staged filenames and added diff lines (`pre-commit`) |
| `repo-guard check-commit-msg <file>` | Scan commit messages (`commit-msg`) |
| `repo-guard check-push [remote] [url]` | Scan commit diffs, messages, and author metadata before push (`pre-push`) |
| `repo-guard audit-repo [--strict] [--history] [path]` | Full repository audit for open-source publish readiness |

## Rule Reference

| Rule ID | Hard Ceiling | What It Blocks |
| :--- | :---: | :--- |
| `RG-FILE-001` | Yes | `.env`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `credentials.json`, `secrets.*`, `vault.*` (allows `.env.example`) |
| `RG-SEC-001..009` | Yes | Private keys, AWS/GitHub/Stripe/LLM/Slack tokens, JWTs, Luhn-valid card PANs, hardcoded secrets |
| `RG-PATH-001` | Yes | Hardcoded `/home/<user>/`, `/Users/<user>/`, or `C:\Users\<user>\` paths |
| `RG-NET-001..003` | Yes | `*.ts.net` domains, RFC 1918 LAN IPs, Tailscale CGNAT, and ULA IPv6 (allows loopback and RFC 5737 doc IPs) |
| `RG-NET-004` | No | Hardcoded non-loopback `http(s)://<private-host>:<port>` URLs |
| `RG-ID-001` | Yes | Configured personal names, handles, emails, and private domains |
| `RG-HOST-001..003` | No | Configured private infrastructure hostnames |
| `RG-UI-001` | No | Literal or encoded Unicode emojis in user-facing UI files (`.html`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.css`, `.qml`, `.svg`, frontend `.js`/`.ts`) |

## Per-Repository Policy

Override the private pattern file path with `REPO_GUARD_CONFIG` (see [`.env.example`](.env.example)). Add an optional `.repo-guard.json` to allow known non-secret terms or fixture paths:

```json
{
  "allow_paths": ["docs/architecture.md"],
  "allow_terms": ["internal-demo-host"],
  "allow_author_emails": ["dev@example.com"]
}
```

Hard-ceiling rules (`secret`, `tailnet_fqdn`, `private_ip`, `home_path`, `personal_identity`) can never be disabled by per-repo config.

## Development & Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
