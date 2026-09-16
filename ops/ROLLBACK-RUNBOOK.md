# Rollback runbook

1. Freeze deployments and record the current image digest, migration revision, active signing key, and incident request IDs.
2. Stop traffic growth with the documented rate limit; do not disable authentication checks.
3. Roll application instances back to the last compatible image. During expand/contract, roll back the application before the schema.
4. Keep both old and new public keys published until every token signed by the old active key has expired.
5. Verify login, refresh, logout, Resource API 401/403 behavior, readiness, and dependency metrics.
6. Resume traffic gradually and record the final evidence. Forward repair uses a reviewed migration; production data is not manually rewritten during the incident.
