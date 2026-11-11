# Changelog

## 0.1.0 (2026-11-11)

First release.

- Eleven checks for LiteLLM gateways (GWA-01 to GWA-11): plain-text credentials, master key, prompts in logs, keys in the gateway database, shared admin login, spend caps, image pinning, TLS verification, API docs, request size limits, and known high or critical LiteLLM advisories for the release in the image tag.
- GWA-11 recommends the lowest release that clears every listed advisory, not just the one that fixes the first match, and is NOT ASSESSED when the image tag doesn't name a version.
- Reads LiteLLM `config.yaml`, Docker Compose services running a LiteLLM image (including `env_file:` references) and `.env` files, combined per folder.
- Checks that need deployment files are reported as NOT ASSESSED when none are found, never as passed.
- Reviewed exceptions with a decision, reason, approver and expiry date; expired exceptions reopen the finding.
- Outputs: reviewer report, findings CSV, hashed evidence per deployment and OSCAL 1.1.2 assessment results; reproducible with `SOURCE_DATE_EPOCH`.
- `--fail-on` for CI gates and `--format json` for other tools.
