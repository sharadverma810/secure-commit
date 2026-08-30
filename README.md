# secure-commit
Experimenting with shift-left techniques to prevent secrets (keys, passwords, tokens, etc.) from being committed in a .NET project.

## Fully local commit protection

This repo uses a local-only Git hook and a PowerShell scanner. It does not require:

- any online service
- any remote project or package host
- any external secret-scanning tool install
- any cloud dependency

### Setup

From the repo root:

```powershell
git config core.hooksPath .githooks
```

That is all you need for the default local commit check.

### How it works

The hook calls the local scanner script at [.githooks/check-secrets.ps1](.githooks/check-secrets.ps1), which scans the staged git diff for common secret patterns such as:

- `Password=...`
- `apiKey`, `token`, `secret`
- `ghp_...`
- `AKIA...`
- `BEGIN PRIVATE KEY`
- `xoxb-...`
- connection strings with embedded credentials

If a staged file contains a suspicious value, the commit is blocked.

### Local test files

The repo includes safe demo examples under [demo-secret-leaks](demo-secret-leaks). These are intentionally excluded from the local scanner to make the repo easy to test without leaking real data.

### Recommended references

- Gitleaks: https://github.com/gitleaks/gitleaks
- pre-commit-hooks: https://github.com/pre-commit/pre-commit-hooks

These are useful as reference sources, but this repo's active protection is intentionally self-contained and local-only.
