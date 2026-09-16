# End-to-end failure matrix

| Boundary | Injected failure | Expected result | Evidence |
| --- | --- | --- | --- |
| BFF login | OAuth state missing or replayed | 401, no session cookie | BFF security test and rejected counter |
| SSO token | authorization code replay or wrong PKCE | 401, code remains unusable | OAuth regression test |
| Resource API | issuer, audience, azp, or signature mismatch | 401 | Resource API binding test |
| Resource API | valid token without required scope | 403 | scope test |
| JWKS | unknown kid after one refresh | 401, bounded upstream call | JWKS refresh test |
| Redis | authenticated session is deleted | 401 until a new server session is created | automated Redis session-loss test |
| PostgreSQL | connection unavailable | readiness down, no partial write | manual Compose drill; not asserted by `lab:test` |
| Key rotation | retire requested before overlap | operation rejected; old token remains valid | automated cryptographic overlap test |
| Migration | expand and contract order is reversed | stop rollout, deploy compatible schema | live sequential Alembic run plus migration contract test |
| Backup | checksum mismatch | restore does not start | restore script output |
| Application rollback | old reader against contracted schema | rollback application before schema | manual runbook drill; not asserted by `lab:test` |

Automated evidence is produced by `lab:test`; rows explicitly marked manual are operator exercises and are not claimed as executed by the package. Run the whole matrix after changes to OAuth, token claims, key ring, migrations, or dependency clients. Store request IDs and aggregate metrics, never credentials or tokens.
