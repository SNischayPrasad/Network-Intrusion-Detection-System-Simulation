# 07 · Security & Privacy

## Why IDS data is itself sensitive
An IDS database is a map of the organisation:
- **Who talks to whom:** IP addresses often identify people and devices.
- **When they talk:** work patterns and behaviour.
- **Which services exist:** an attacker's reconnaissance for free.
- **What the defenders noticed, and what they did not:** detection gaps and thresholds tell an attacker how to stay below the radar.

Analyst notes can contain names, suspicions and incident details. In many jurisdictions, IP addresses and user activity are **personal data** (for example under GDPR or India's DPDP Act). A leaked IDS database therefore creates privacy, legal and security risk at the same time.

## Controls: implemented vs production
| Control | This project (implemented) | Production would add |
|---|---|---|
| **Use synthetic data** | 100% synthetic flows; RFC 5737 IPs only; the simulator only posts to loopback | Data-processing agreements, minimisation and retention policies for real telemetry |
| **Avoid packet payload storage** | The schema has no payload field; `extra="forbid"` rejects a `payload` key (TC-28) | Metadata-only flow sensors; if PCAP is ever needed, short retention and encryption |
| **Protect monitoring dashboards** | Sign-in required; key kept in `sessionStorage` (cleared when the tab closes); CSP and anti-framing headers | SSO (OIDC/SAML) with **MFA**, session timeouts, VPN or zero-trust access |
| **Authenticate analysts** | API keys compared in constant time (`hmac.compare_digest`) | Per-user identities, short-lived tokens, key rotation |
| **Implement authorisation** | RBAC: sensor, analyst, admin, enforced **server-side** on every route (TC-33) | Fine-grained permissions (per team, per data set) |
| **Encrypt traffic** | Localhost only | TLS 1.2+ everywhere, HSTS, mTLS between sensors and the collector |
| **Protect security logs** | DB and logs git-ignored; the audit log is append-only in application code | Encryption at rest, write-once storage or hash chaining, backups, access monitoring |
| **Sanitise dashboard output** | React escapes all text; notes have control characters stripped; Markdown reports escape analyst text | Output encoding reviews, a strict CSP for the SPA |
| **Rate limit APIs** | Sliding-window limiter, HTTP 429 with `Retry-After` | Gateway/WAF rate limits, per-identity quotas |
| **Secrets in environment variables** | `.env` (git-ignored), `.env.example` documented; a startup warning when dev keys are used | A secret manager (Vault, AWS/Azure/GCP secret stores) |
| **Maintain audit logs** | ALERT_CREATED, STATUS_CHANGED, NOTE_ADDED, RULE_UPDATED with actor, role and timestamp | Forward to the SIEM; alert on rule weakening |
| **Protect incident notes** | Only the analyst and admin roles can read or write; length limits | Field-level encryption, need-to-know access |
| **Least privilege** | The sensor key cannot read alerts; analysts cannot change rules | Separate service accounts; admin actions with approval |
| **Input validation** | Pydantic + semantic validation; parameterised SQL; regex-checked path IDs | Fuzz testing, schema versioning |
| **Error handling** | Generic 500s; stack traces only in server logs | Centralised error monitoring |
| **Model files** | Pickles git-ignored and loaded only from local `models/` | Signed model artefacts, safetensors/ONNX formats |

## Secure-coding checklist used in this repo
- [x] No secrets in source control
- [x] Validate all input (type, range, format, length)
- [x] Parameterised SQL only
- [x] Server-side authorisation on every endpoint
- [x] No sensitive data in URLs (the API key travels in a header)
- [x] Fail safely: a bad rule threshold or SIEM-export failure never crashes detection
- [x] Idempotent ingestion (duplicate `flow_id` returns 409)
- [x] Audit every privileged action
