# Good First Issues

## Add support for importing a JWKS to pick a verification key by kid
Scope: small, self-contained change in index.html or src/logic.js with a test in tests/logic.test.js where logic changes.
Good for a first contribution: no build step, run npm test to verify.

## Show a warning when the alg header is none or mismatched with the key type
Scope: keep the change local to the browser page, add no network calls, and keep the privacy line intact.
Good for a first contribution: follow the existing patterns in the page wiring.

## Add a one-click sample token generator built from obviously fake claims
Scope: cover the new behaviour with at least one real test case and update the README feature list.
Good for a first contribution: ask in the issue if any part of the scope is unclear.
