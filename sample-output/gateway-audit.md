# AI Gateway Audit: 2026-10-12

**2 gateway deployments**, **14 open findings** (7 high, 4 medium, 3 low).

| Deployment | Sources | High | Medium | Low | Not assessed |
|---|---|---:|---:|---:|---:|
| [hardened](#hardened) | `hardened/config.yaml`, `hardened/docker-compose.yml` | 0 | 0 | 0 | 0 |
| [insecure](#insecure) | `insecure/config.yaml`, `insecure/docker-compose.yml` | 7 | 4 | 3 | 0 |

## Control results

| Check | Control | hardened | insecure | Frameworks |
|---|---|---|---|---|
| GWA-01 | Provider credentials are not stored in plain text | PASS | FAIL | NIST 800-53 IA-5(7), SC-28; SOC 2 CC6.1; OWASP LLM LLM02 |
| GWA-02 | The proxy requires a master key that is not stored in plain text | PASS | FAIL | NIST 800-53 AC-3, IA-2, IA-5(7); SOC 2 CC6.1; OWASP LLM LLM10 |
| GWA-03 | Prompts and responses are kept out of logs | PASS | FAIL | NIST 800-53 AU-3(3), SI-12; SOC 2 C1.1; OWASP LLM LLM02 |
| GWA-04 | Provider keys are not held in the gateway database | PASS | FAIL | NIST 800-53 SC-12, SC-28; SOC 2 CC6.1; OWASP LLM LLM02 |
| GWA-05 | The admin UI does not accept a shared environment login | PASS | FAIL | NIST 800-53 AC-2, IA-2; SOC 2 CC6.1, CC6.2 |
| GWA-06 | Spend is capped globally and per key | PASS | FAIL | NIST 800-53 SC-6; SOC 2 A1.1; OWASP LLM LLM10 |
| GWA-07 | The gateway image is pinned by digest | PASS | FAIL | NIST 800-53 CM-2, SI-7; SOC 2 CC8.1; OWASP LLM LLM03 |
| GWA-08 | TLS certificates are verified on calls to providers | PASS | FAIL | NIST 800-53 SC-8, SC-23; SOC 2 CC6.7 |
| GWA-09 | Interactive API documentation is disabled | PASS | FAIL | NIST 800-53 CM-7 |
| GWA-10 | Request and upload sizes are limited | PASS | FAIL | NIST 800-53 SC-5, CM-7; OWASP LLM LLM10 |

---

<a id="hardened"></a>
## hardened

- **Folder:** `hardened`
- **Evidence:** `evidence/hardened.json` (sha256 `666766d3f652d747…`)
- **Sources read:**
  - `hardened/config.yaml` (litellm-config, sha256 `787612c751da7043…`)
  - `hardened/docker-compose.yml` (compose, sha256 `6e5993665145f570…`)

### Findings

No findings.

---

<a id="insecure"></a>
## insecure

- **Folder:** `insecure`
- **Evidence:** `evidence/insecure.json` (sha256 `928a34e1a6a4bb68…`)
- **Sources read:**
  - `insecure/config.yaml` (litellm-config, sha256 `044166f085c68d1f…`)
  - `insecure/docker-compose.yml` (compose, sha256 `2514814ed6317c71…`)

### Findings

| Check | Severity | Finding | Recommendation | Status |
|---|---|---|---|---|
| GWA-01 | high | `model_list[0].litellm_params.api_key` in `insecure/config.yaml` is a credential written in plain text. | Reference it with os.environ/NAME (or ${NAME} in Compose) and load it from a secret manager. Rotate it: anyone who can read this file has had it. | **open** |
| GWA-01 | high | `DATABASE_URL` in `insecure/docker-compose.yml` is a credential written in plain text. | Reference it with os.environ/NAME (or ${NAME} in Compose) and load it from a secret manager. Rotate it: anyone who can read this file has had it. | **open** |
| GWA-02 | high | The master key is written in plain text in the LiteLLM config. It grants admin access to every model, key and budget on the proxy. | Set master_key: os.environ/LITELLM_MASTER_KEY and rotate the key. | **open** |
| GWA-03 | high | store_prompts_in_spend_logs is on: every prompt and response is written to the gateway database, next to the spend records. | Turn it off. If you need content for debugging, log a sample, redact it, and set a retention limit. | **open** |
| GWA-05 | high | UI_PASSWORD is written in plain text in `insecure/docker-compose.yml`. | Remove it, rotate it, and move admins to named accounts or SSO. | **open** |
| GWA-07 | high | Service `litellm` runs `ghcr.io/berriai/litellm:main-stable`, a moving tag. Whatever is published under it next runs with every provider key. LiteLLM's October 2026 compromise repointed latest, main-latest and main-stable to a malicious image. | Pin a reviewed release by digest: image: …litellm@sha256:<digest>. | **open** |
| GWA-08 | high | ssl_verify is off, so provider certificates aren't checked and anyone on the network path can read prompts and provider keys. | Remove ssl_verify: false. For a private CA, set ssl_verify to the CA bundle path. | **open** |
| GWA-03 | medium | Prompts and responses are sent to langfuse because turn_off_message_logging is not set. | Set litellm_settings.turn_off_message_logging: true so callbacks receive metadata only, or document why each destination may hold message content. | **open** |
| GWA-04 | medium | store_model_in_db is on and no key management system is configured, so provider keys added through the UI or API are stored in the gateway database. One query can read them all, which is what the October 2026 LiteLLM payload did. | Keep provider keys in a secret manager (general_settings.key_management_system) and reference them from the config, or restrict and monitor access to the credentials tables. | **open** |
| GWA-05 | medium | The admin UI accepts the shared UI_USERNAME / UI_PASSWORD login (or the master key when UI_PASSWORD is unset), so admin actions can't be tied to a person. | Create named proxy_admin users or connect SSO, then set general_settings.disable_env_credential_login: true. | **open** |
| GWA-06 | medium | There is no global spend cap. A leaked virtual key or a runaway agent can spend without limit, and stolen gateway access is used to run attackers' workloads. | Set litellm_settings.max_budget (and budget_duration) to a limit someone has approved. | **open** |
| GWA-06 | low | Virtual keys can be created with no budget limit. | Set litellm_settings.upperbound_key_generate_params.max_budget so no key can exceed it. | **open** |
| GWA-09 | low | NO_DOCS, NO_REDOC, NO_OPENAPI are not set to True, so the proxy publishes interactive API documentation describing every admin route. | Set NO_DOCS, NO_REDOC and NO_OPENAPI to "True" in production. Each controls a separate page. | **open** |
| GWA-10 | low | max_request_size_mb and allowed_file_extensions are not set, so request bodies and file uploads are not limited. | Set general_settings.max_request_size_mb and an allowed_file_extensions allowlist ([] rejects all uploads). | **open** |

## Needs evidence from outside the configuration

A configuration file can't prove these. Collect evidence for them separately:

- **M-01:** Outbound traffic from the gateway is limited to approved model providers (NIST 800-53 SC-7(5))
- **M-02:** The admin UI and management routes are not reachable from the internet (NIST 800-53 AC-17, SC-7)
- **M-03:** Provider keys are rotated and their use is monitored (NIST 800-53 IA-5(1), AU-6)
- **M-04:** The gateway database is encrypted and access to it is restricted (NIST 800-53 SC-28, AC-6)

## Sign-off

I have reviewed the findings above and the decisions recorded for each.

| Role | Name | Date |
|---|---|---|
| Gateway owner | | |
| Reviewer | | |
