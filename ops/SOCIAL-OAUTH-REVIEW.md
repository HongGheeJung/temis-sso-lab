# Social OAuth review corrections

Branch: `fix/social-oauth-review`. Based on GitHub main `1cbad40`.
No production deployment or database migration is required by this change.

## Behavior

- Kakao callback uses the value returned by `FlowStore.consume`. Adapters are
  constructed with named arguments. Every outbound HTTP client has an async context.
- Google validates the callback identity once using the existing OIDC service.
  Both first and repeat login then use the same account mapping helper. The
  state and provider code are never reused after a not-linked exception.
- Provider + subject identifies an account. Matching email never automatically
  links an existing account. An email collision uses a random lab-only address.
  Existing non-active users cannot log in through a linked social identity.
- All three successful callbacks now return `TokenBundle` JSON with `no-store`,
  `no-cache`, and `no-referrer` headers, and clear the browser-binding cookie.
  They no longer redirect to `/docs` with access/refresh tokens in the URL.
  This deliberately changes the lab API contract: callers read the JSON body.
  It is not a production browser session or a frontend handoff implementation.
- Naver/Kakao `POST /oauth/{provider}/revoke` requires a social-login bearer
  token with audience `lab-client`, an active DB user, and empty JSON `{}`.
  It never accepts provider tokens from the caller. The successful callback
  retains the provider token in server memory for 5 minutes, keyed by provider
  and user ID. Restart/expiry returns 409 and requires a fresh provider login.
  Run one worker. This is a lab implementation, not durable token storage.
- The provider profile must match the authenticated user's exact link before
  remote revocation and local deletion. Failed operations retain the link.
  Success also removes the temporary server-side provider credential.
- The social bearer verifier explicitly checks `lab-client`. It does not widen
  the default audience accepted by other API endpoints. The regression tests
  now use real signed bearer tokens without overriding the auth dependency.
- Remote revocation and local deletion cannot be one atomic transaction. A local
  DB commit failure after remote success requires reconnect/recovery.
- Credentials default to empty. Unconfigured providers return 503 instead of
  preventing unrelated application startup. Kakao secret is optional.
- Redirect URIs are configurable; defaults remain loopback development URLs.
  Non-loopback callbacks require HTTPS. Configure secure cookies for HTTPS.
- Naver/Kakao routes now retrieve REST adapters from `ProviderRegistry`.
  Unused Kakao OIDC verification code and its dedicated tests have been removed.
  Kakao uses REST profile identity only; Google OIDC verification is retained.


## Naver documentation correction

Checked 2026-10-30:
https://developers.naver.com/docs/login/api/api.md

The current official specification sections 3.3 and 4.4 explicitly document
`POST https://nid.naver.com/oauth2.0/revoke`, `token`, and `token_type_hint`.
Successful revocation returns an empty HTTP 200, including already-invalid
input tokens. Therefore the review's proposed replacement with the historical
`grant_type=delete` flow is not applied. The existing endpoint test stays and
coverage is added for a defensive rejection of error JSON in HTTP 200.
Token revocation should not be described as deleting all Naver consent data.

## Verification

Install with `python -m pip install -e '.[dev]'` in an activated Python 3.12+
virtual environment. Tests use mocked provider HTTP and an isolated in-memory
SQLite DB; no real credentials are required. SQLAlchemy asyncio and aiosqlite
are declared dependencies for reproducibility.

Run from a fresh temporary directory (outside the repo) so existing lab keyring
metadata cannot reference missing/real signing keys. Example in PowerShell:

```powershell
$repo = (Get-Location).Path
$run = Join-Path $env:TEMP ([guid]::NewGuid().ToString())
New-Item -ItemType Directory $run | Out-Null
Push-Location $run
python -m pytest --noconftest -c "$repo/pyproject.toml" "$repo/tests/oauth_review" "$repo/tests/test_naver_adapter.py" "$repo/tests/test_kakao_registry.py" "$repo/tests/test_google_account_link.py" -k "not account_link_requires and not callback_orchestrates and not external_identity_link" -q
Pop-Location
```

`--noconftest` bypasses legacy tests/conftest.py, which automatically migrates
Postgres and flushes Redis. Do not run that legacy setup against shared data.
59 tests pass. Three existing PostgreSQL-dependent tests are deselected; the
new tests independently exercise persistent account creation, repeat login,
email collision, blocked users and transactional link deletion using SQLite.
Changed production files pass Ruff and strict mypy. The complete PostgreSQL/
Redis suite and real provider browser tests have not run in this environment.

For actual smoke tests, configure each provider console with the exact URI in
.env, then test login, repeat login, provider rejection, and revoke using a token
from the same provider account. FlowStore is process-local, as before: run one
worker for the lab; distributed storage and restart recovery remain out of scope.
