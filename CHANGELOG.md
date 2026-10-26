# Changelog

## 0.1.0 (2026-10-26)

First release.

- Ten checks for LiteLLM gateways (GWA-01 to GWA-10): plain-text credentials, master key, prompts in logs, keys in the gateway database, shared admin login, spend caps, image pinning, TLS verification, API docs and request size limits.
- Reads LiteLLM `config.yaml`, Docker Compose services running a LiteLLM image (including `env_file:` references) and `.env` files, combined per folder.
- Checks that need deployment files are reported as NOT ASSESSED when none are found, never as passed.
- Reviewed exceptions with a decision, reason, approver and expiry date; expired exceptions reopen the finding.
- Outputs: reviewer report, findings CSV, hashed evidence per deployment and OSCAL 1.1.2 assessment results; reproducible with `SOURCE_DATE_EPOCH`.
- `--fail-on` for CI gates and `--format json` for other tools.
