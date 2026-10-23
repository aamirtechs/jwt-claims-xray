# Changelog

## 1.0.0 - 2026-10-23

- Initial release.
- Decode header and payload with registered-claim humanising: exp, iat and nbf become local and UTC times with a countdown
- Verify HS256, RS256 and ES256 signatures locally with WebCrypto
- Claim diffing: paste two tokens and see added, removed and changed claims
- Redacted copy mode that masks the signature and sensitive claims for tickets
- Works offline after load and never puts a token in the URL
