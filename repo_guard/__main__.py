"""Allow running repo-guard via `python3 -m repo_guard`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
