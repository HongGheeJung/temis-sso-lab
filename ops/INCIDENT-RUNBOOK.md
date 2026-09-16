# Authentication incident runbook

Classify the symptom as availability, unauthorized access, key exposure, replay, or data integrity. Assign an incident lead and preserve timestamps, deployment identifiers, request IDs, redacted structured logs, and low-cardinality metrics.

For suspected private-key exposure, publish and activate a new key, revoke affected sessions and refresh grants, then retire the exposed key after the deliberate emergency token policy is applied. For Redis loss, fail login and authenticated session reads closed. For PostgreSQL loss, mark readiness down and prevent state changes. For JWKS loss, use only an unexpired validated cache; unknown keys fail closed.

Recovery is complete only after the E2E failure matrix passes and an isolated database restore succeeds. Document impact and corrective actions without copying credentials, cookies, authorization codes, or bearer tokens into the incident record.
