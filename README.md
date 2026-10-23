# JWT Claims Xray
Live page: https://aamirtechs.github.io/jwt-claims-xray/

Decode, verify (HS256/RS256/ES256) and expiry-check JWTs entirely offline, with a visible zero-network guarantee and a redacted share mode. It runs entirely in your browser, so the files and data you work with never leave your device.

## Features
- Decode header and payload with registered-claim humanising: exp, iat and nbf become local and UTC times with a countdown
- Verify HS256, RS256 and ES256 signatures locally with WebCrypto
- Claim diffing: paste two tokens and see added, removed and changed claims
- Redacted copy mode that masks the signature and sensitive claims for tickets
- Works offline after load and never puts a token in the URL

## How it works
Paste a token to decode and inspect it, optionally paste a secret or public key to verify its signature with WebCrypto, and optionally paste a second token to diff claims. Everything runs in the page; no token ever leaves the tab.

## Privacy
Runs 100% in your browser. Your files never leave this device, nothing is uploaded,
and there is no tracking.

## Development
Core logic lives in `src/logic.js` and is shared by the page and the tests.
Run the tests with `npm test`.

## License
MIT, Copyright 2026 Amir Hussain.
