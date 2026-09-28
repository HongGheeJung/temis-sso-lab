# External IdP release checklist

## Common boundary

- Redirect URI is an exact allowlisted HTTPS value.
- State is random, short-lived, single-use, and bound to the initiating browser.
- Authorization Code flows use PKCE S256; OIDC flows additionally bind nonce.
- Provider issuer, audience, signature algorithm, expiry, and subject are verified where applicable.
- Account keys are `(provider, subject)`. Email never performs an automatic merge.
- Provider tokens and client credentials never enter browser storage, URLs, metrics, or logs.

## Provider differences

| Provider | Stable subject | Email rule | Disconnect operation |
| --- | --- | --- | --- |
| Google | verified ID token `sub` | use only verified claim | revoke token, then local session revoke |
| Naver | profile `response.id` | optional, unverified profile attribute | `/oauth2.0/revoke` POST form |
| Kakao | profile `id` or verified OIDC `sub` | require availability, consent, validity, verification flags | distinguish logout from unlink |

## Deterministic test boundary

The course suite uses local signed claims and `httpx.MockTransport`. It performs no
DNS lookup or provider request. A real-provider smoke test is a separate opt-in job
whose credentials come only from runtime environment variables and whose output is
redacted.
