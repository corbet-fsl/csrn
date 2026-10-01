# Assurance contract as implemented

FSL facade: `Assurance` only wires `cchr::Charter` and `cnvy::feed::Follower`. `feed` and `http` re-export Envoy APIs for compatibility.
All follower state transitions and native HTTPS live in the LGPL Envoy leaf.
Neither stores member data,
keys, logs, a duplicate trust revision or a policy evaluator.

## API and ports

`Assurance::new(origin, community, Config)`, `start(now)`, `next(now)`,
`on_feed(id, bytes, authenticated_origin, now)`, `on_announcement(id, bytes, now)`,
`on_change(revision, now)`, `on_policy_epoch(epoch, now)`, `refresh(now)`, `on_error(id, now, jitter)`, `current(now)`, `stop()`.
Config contains explicit refresh, minimum poll, request, backoff and maximum
staleness durations. All times are injected Unix seconds. No timer, background
thread, singleton storage or network task is started. No unused storage port is
invented for this volatile machine; a server restart starts unbootstrapped.

The injected network port is an owned `Request` output and a matching completion
input. `on_change` must come from the configured public feed; a member epoch hint
must come from already verified credential metadata, never an arbitrary member
request integer. A false high hint can deny availability until restart, but
cannot grant authority. Request exposes only operation ID, Fetch or Poll(public revision), exact
existing cvld path/body and exclusive deadline. The enclosing runtime must cancel
transport at that deadline or on stop/change; dropping a native execute future
cancels its I/O. Follower's operation ID also rejects any late completion. It
never creates another live operation before completing, fencing or timing out the
current one. The runtime must obey cancellation to preserve the I/O bound.

`http::Http` (optional native `http` feature) accepts only an exact HTTPS origin,
uses reqwest with redirect refusal, no ambient credentials, cookies, proxy or
referrer, no retry middleware, a generic User-Agent, ten-second connect timeout
and remaining request deadline as total timeout. Only configured origin plus the
two fixed paths can be requested. Body collection is checked chunk by chunk, not
merely against Content-Length: at most cchr's 32 MiB for a feed and 1024 bytes for
an announcement. All non-success statuses fail. Explicit operator CA roots may
supplement the public store; certificate and hostname checks stay enabled.

A `Received` has no public constructor. Its `authority(receive_time, fresh_for)`
converts only a successful HTTPS feed response into cchr's privileged origin
assertion, with the response's ring/current revision and a 1–300-second receipt
window. Charter still verifies every signed field and floor. An adapter supplied
by a browser has the same obligation: authenticate the configured origin, bypass
body caches, reject redirects and never assert authority from untrusted bytes.
No TLS deployment or browser networking runtime is shipped.

## States and failure semantics

Stopped → Fetching → Following. Network, invalid trust, malformed announcement,
wrong response kind or timeout → Backoff. No known fresh charter, expired signed
material, newer announced revision, clock regression or exceeded maximum staleness
makes the facade Unavailable. Follower's state describes I/O; facade readiness is
derived from both children, not a second persisted trust state.

A poll response is at most 1024 bytes, rejects duplicate/unknown fields and must
have a positive epoch, nondecreasing revision and `changed` exactly matching a
higher revision. Announcements are hints, not signed material or permanent floors.
A newer revision or member-presented policy epoch fences a pending poll and
requests a feed promptly; hints cannot
bypass backoff. A fetched publication behind either revision or epoch hint cannot restore readiness.
A periodic fetch runs even when announcements are lost. Empty/unchanged polls
are spaced by the configured minimum interval, preventing immediate-reply loops.

Exponential retry delay starts at the explicit initial value, doubles to the
configured cap, and uses caller-supplied entropy for bounded positive jitter.
At most one request can exist; caps are enforced for any supplied jitter.
Successful verified refresh resets backoff. Rejected candidates preserve Charter's
old valid material; no error extends its signed deadline or the last successful
refresh time. During a transient outage, current material remains usable only
until both signed expiry and maximum staleness permit it, and only while no newer
revision is pending. Stop refuses all reads and fences completions; restart
requires fresh authenticated bootstrap while retaining the existing Charter's
in-process rollback floors. New process state never reuses a cached feed alone.

Clock regression fails closed and cancels pending work. A monotonic operation
counter never wraps; exhaustion refuses work. Configuration caps request timeout
at 300 seconds (minimum 26 for cvld's 25-second long poll), maximum backoff and
staleness at one day; refresh must fit the staleness budget. Checked deadline
arithmetic refuses overflow. Fixed errors omit payloads, identifiers and causes.

## Validation and open work

CI checks main declarations and unique locked first-party revisions, fmt, strict Clippy, native tests,
wasm32 build and identical deterministic state-machine vectors on wasm. Tests
exercise startup, changes, expiry, loss, delay, repeated failures, bounded storms,
clock regression, cancellation/stop/restart, obsolete replies, malformed events,
corruption and signed rollback. Native HTTPS tests use real local TLS and verify
request privacy, origin bootstrap, redirect and oversized-response refusal,
including chunked bodies without Content-Length.

Native and wasm also replay unchanged bytes from the running cvld door producer
in cchr CI: unchanged feed after registration/issuance/renewal, followed by
all/any/threshold policy edits, schema change and last-passkey revocation with
their actual announcements. These exercise the full follower→Charter path.
The csrn job replays captures; cchr separately launches the actual door.
`tests/fixtures/provenance.json` records immutable producer/door revisions, CI
source and per-file SHA-256; CI verifies these hashes before testing. No mocked
verification verdicts or cvld server dependency enter the consumer graph.

Charter exposes a borrowed Guard policy containing the original signed full
settings and separate revocations. Guard verifies these envelopes, the device
signature and the profile, then delegates rich policy to Rulebook. These captures
verify byte preservation; they do not assert admission without a valid bundle.
The full cvld→guard→forum path still requires the door owner's current device
registration authority and matching signed credential evidence. Production TLS bootstrap provisioning, browser transport and embedding
cancellation/scheduling are adapter integration responsibilities. No deployment,
registry publication, payments or external test accounts are involved.
