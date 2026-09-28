# Official provider references

Provider contracts change independently of this course. Before a real integration,
compare the adapter with the current official documentation:

## Google

- [OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)

## Naver

- [Naver Login development guide](https://developers.naver.com/docs/login/devguide/devguide.md)
- [Naver Login profile API](https://developers.naver.com/docs/login/profile/profile.md)

## Kakao

- [Kakao Login REST API](https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api)
- [Kakao Login sample](https://developers.kakao.com/docs/latest/ko/kakaologin/sample)
- [Kakao Login test checklist](https://developers.kakao.com/docs/latest/ko/kakaologin/prerequisite#test)

Endpoint shape in the deterministic fixtures teaches the contract, but the actual
redirect URI, consent items, client authentication method, app status, and console
registration values must follow the provider console and its current documentation.
When they disagree with this course, the current console documentation wins.
