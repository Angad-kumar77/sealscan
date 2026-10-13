# sealscan

**Scan before you ship.** A local-only command line scanner that finds
hardcoded secrets, insecure code patterns and risky open-source licenses in
one pass.

- **100% local.** No network calls, no telemetry, no accounts. Files are read
  in memory and nothing is uploaded or stored.
- **Zero dependencies.** Standard library only.
- **Five categories in one engine.** Leaked secrets, insecure code (Python,
  JavaScript, Java, Go), risky licenses, risky container/CORS config, and
  unpinned dependency versions — in a single scan.
- **CI friendly.** Exit codes, JSON and SARIF output, pre-commit hook.

## Install

```bash
pip install sealscan
```

From source:

```bash
git clone <your-repo-url>
cd sealscan
pip install -e .
```

Requires Python 3.9 or newer.

## Usage

```bash
sealscan .                          # scan the current directory
sealscan path/to/project            # scan another directory
sealscan app.py                     # scan a single file
sealscan . --min-severity high      # hide low and medium findings
sealscan . --only secret,license    # choose categories
sealscan . --format json            # json output (also: sarif, text)
sealscan . -f sarif -o results.sarif
sealscan --list-rules               # show every rule and its id
```

Example output:

```
[CRITICAL] SECRET-AWS-ACCESS-KEY  src/app.py:2
    AWS access key ID found
    > AKIA******LE
[HIGH] LICENSE-GPL  package.json:1
    Project declares this license
    > GPL-3.0

sealscan: scanned 5 files, 2 issues (critical: 1, high: 1)
```

Secret values are always redacted in every output format.

## What it detects

| Category | Examples |
|---|---|
| `secret` | AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, npm, OpenAI, Anthropic, Twilio, Mailgun, Heroku, Azure, PayPal/Braintree, Discord and Telegram keys/tokens, private key blocks, JWTs, passwords in URLs, hardcoded credentials, committed `.env` and key files |
| `vulnerability` | Python: `eval`/`exec`, `shell=True`, `os.system`, unsafe `pickle`/`yaml.load`, weak hashes, disabled TLS verification, SQL built with string formatting. JavaScript: `innerHTML`, `document.write`, `child_process.exec`. Java: `Runtime.exec`, unsafe deserialization, weak hashes, trust-all TLS, concatenated SQL. Go: shell `exec.Command`, weak hashes, disabled TLS verification, `fmt.Sprintf` SQL |
| `license` | AGPL, SSPL, GPL, LGPL, EUPL, BUSL and NonCommercial licenses found in `LICENSE` files, SPDX headers, and `package.json`, `composer.json`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Cargo.toml` |
| `config` | Dockerfiles pinned to `:latest`, no `USER` instruction (root), `ADD` from a remote URL; docker-compose `privileged: true`, host networking, a mounted Docker socket; wildcard CORS origins |
| `dependency` | Unpinned versions in `requirements.txt`; wildcard/`latest` versions in `requirements.txt` and `package.json` |

Run `sealscan --list-rules` for the full list.

## Ignoring files and findings

- `.gitignore` files are respected automatically (including nested ones).
  Use `--no-gitignore` to scan ignored files too.
- Add a `.sealscanignore` file (same syntax as `.gitignore`) for extra excludes.
- Silence one line with a comment: `# sealscan:ignore` (or `// sealscan:ignore`).
- Common folders such as `.git`, `node_modules`, `.venv` and `dist` are skipped.

## Configuration

Create `.sealscan.json` in the directory you scan (or pass `--config FILE`):

```json
{
  "ignore": ["tests/", "vendor/"],
  "disable_rules": ["VULN-PY-WEAK-HASH"],
  "min_severity": "low",
  "fail_on": "high"
}
```

Command line flags override the config file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` (default: `high`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage or configuration error |

Severities, lowest to highest: `low`, `medium`, `high`, `critical`.

## Use in CI and Git

**pre-commit** (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: <your-repo-url>
    rev: v0.1.0
    hooks:
      - id: sealscan
```

**GitHub Actions** (after the package is published to PyPI):

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install sealscan
- run: sealscan . --fail-on high
```

**GitHub code scanning** (findings appear in the Security tab):

```yaml
- run: sealscan . --format sarif --output sealscan.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sealscan.sarif
```

## Limitations

sealscan is pattern based, so it is fast and fully offline but not perfect.
Expect some false positives (use `sealscan:ignore` or the config file) and
some misses. License detection covers declared licenses in your own project;
it does not resolve the licenses of your installed dependencies. Treat it as a
safety net, not a guarantee.

## Development

```bash
pip install -e .
python -m unittest discover -v
sealscan .
```

## License

MIT
