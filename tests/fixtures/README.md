# Actual cvld public trust publications

These unchanged JSON responses were captured by the running global/community
cvld door in [cchr CI](https://github.com/corbet-foss/cchr/actions/runs/36911320705).
The services use a temporary libSQL store and synthetic users, real software
WebAuthn credentials, and real BBS proofs. No external account is involved.

`initial.json` and `ordinary.json` are byte-identical despite registration, lobby,
voucher admission, credential issuance and renewal. The remaining responses and
announcements follow all/any/threshold settings, schema version 2, then revocation
of the member's last passkey. Native and wasm tests consume these original bytes
through the follower and Charter; they do not substitute verification verdicts.

`provenance.json` records producer commit, cvld commit, successful CI URL and
SHA-256 for every capture. `scripts/check-fixtures.py` detects altered captures.
`import-door-evidence.py` imports a downloaded successful cchr `door-evidence`
artifact. The hash manifest is an audit record, not a cryptographic trust root.

csrn tests replay this evidence; they do not start cvld themselves. The cchr CI
producer runs real HTTP door services afresh. The separate csrn HTTP tests use
real local TLS to exercise origin authentication, refusal and response bounds.
These are public trust publications only, with synthetic fixture material.

The current captures also include actual authorized-device-signed bundles for
all, any, threshold and schema changes. `publishing-root.json` comes independently
from synthetic deployment configuration before the producer fetches a feed.
It is not derived from the returned `key_ring`. Only the public verification
ring is captured; the synthetic private seed is not part of this artifact.

Those unchanged historical credentials predate the mandatory signed
`cplc.community-credential.v2` purpose and `issuance_action`. Current Guard
therefore consumes them only as explicit legacy-format refusals, including when
their original credential signature remains valid. The captures and provenance
are retained exactly; no missing claim is added or re-signed under their root.

A separate real-signature owner fixture in `tests/it/door.rs` uses an independently
configured synthetic csgn issuer and Ed25519 device. It first authenticates the
original public policy/schema/revocation contents through their original
Charter, then signs those same public terms under its own fixture root. It
tests the current follower/Charter/Guard composition, whole-bundle tampering,
trusted configured action and epoch invalidation without inventing Global gate
claims or changing the policy. This is consumer crypto/owner evidence, not an
updated full cvld/cplc issuance capture. Fresh complete issuer captures and
runtime qualification remain required; these new source vectors have not run.
