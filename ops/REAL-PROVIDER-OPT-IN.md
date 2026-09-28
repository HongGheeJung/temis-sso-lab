# Real-provider opt-in smoke test

The default course suite never contacts Google, Naver, or Kakao. After local tests
pass, an operator may enable a separate smoke-test process and provide credentials
only through its runtime environment:

- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- `NAVER_CLIENT_ID` and `NAVER_CLIENT_SECRET`
- `KAKAO_CLIENT_ID` and, only when configured for the app, `KAKAO_CLIENT_SECRET`

Register an exact callback URI for each provider. A local callback can use a
loopback URI; the deployed callback must use HTTPS. Keep the smoke process disabled
in CI unless a protected environment supplies the variables. Never print the
environment, authorization response, code, provider token, ID token, cookie, or
profile body. Record only provider name, bounded outcome, redacted error category,
and request ID.

The opt-in job must first run the deterministic MockTransport suite. If that suite
fails, do not make a real-provider request. Remove its short-lived provider grants
and revoke the local session after the smoke check.
