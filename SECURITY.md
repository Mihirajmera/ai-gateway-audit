# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub's private vulnerability reporting:

**https://github.com/Mihirajmera/ai-gateway-audit/security/advisories/new**

What to expect:

- **Acknowledgement within 5 business days.**
- **An assessment within 14 days**: whether it's accepted as a vulnerability, its severity, and a planned fix.
- **Coordinated disclosure**: a fix is released and the advisory published together, normally within 90 days of the report. You'll be credited in the advisory unless you'd rather not be.

Useful things to include: the version or commit, the input file that triggers the problem (with real secrets removed), and what you expected to happen.

## Scope

This tool parses configuration files that contain secrets and may come from untrusted sources. Especially relevant reports:

- A secret (provider key, master key, password, connection-string credential) that survives redaction and appears in the Markdown report, CSV, evidence JSON, OSCAL or JSON output.
- A crafted config, Compose or `.env` file that causes code execution, writes outside the `--out` folder, or hangs the scanner.
- A way to change an evidence file without breaking its SHA-256 hash.

A check that should fire but doesn't is a normal bug: please open an issue.

## Design notes

- Configs are only read, never executed. YAML is loaded with `yaml.safe_load`.
- Secrets are redacted during parsing, before anything is checked, written or hashed.
- The tool makes no network calls.
- Dependencies are pinned by hash, GitHub Actions are pinned to commit SHAs, and CodeQL, OpenSSF Scorecard and ClusterFuzzLite run in CI.
