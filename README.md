# csrn — Assurance

A thin Rust facade connecting [Charter](https://github.com/corbet-foss/cchr) to
cvld's public trust feed. The follower lives in
[cnvy — Envoy](https://github.com/corbet-foss/cnvy); it owns retries, cancellation
and scheduling. The `feed` and `http` modules re-export that leaf. Assurance owns no
second policy evaluator, trust revision, member registry or database.

The caller supplies Unix time and executes returned `Request` values. Only
`/v1/trust_feed` and `/v1/trust_changes` can be requested. Feed responses go to
Charter with authenticated origin evidence. Announcements cause a fetch; they
never become trust material. Timed refresh recovers lost announcements.

```rust
# fn example(now: u64) -> csrn::Result<()> {
use csrn::{Assurance, feed::Config};
let config = Config {
    refresh_seconds: 60, poll_seconds: 2, request_seconds: 30,
    initial_backoff_seconds: 2, maximum_backoff_seconds: 60,
    maximum_staleness_seconds: 120,
};
let mut assurance = Assurance::new("https://alpha.example.test", "alpha", config)?;
let request = assurance.start(now)?;
assert_eq!(request.path(), "/v1/trust_feed");
// Execute through the configured transport, then call on_feed with authenticated
// origin evidence and receive time. Poll next(now); stop() fences late replies.
# Ok(()) }
```

Optional `http` provides a native HTTPS adapter with bounded response collection,
redirect refusal, no cookies/bearers/proxy inheritance and a generic User-Agent.
Its `Received::authority` stamps successful origin-authenticated responses with
the caller's receive time. Browser runtimes supply their own network adapter;
the same synchronous state machine and vectors run on wasm.

Read [docs/CONTRACT.md](docs/CONTRACT.md) for states, ports, deadlines and limits.
FSL-1.1-ALv2. Nothing is published to a registry.

## Scope

### Purpose

The forum's link to cvld, wiring Charter and Envoy so the forum holds current, verified community material.

### Owns

- Wires cchr and cnvy and derives one readiness from both.
- Hands Gather immutable, scoped verified material together with the cvld-owned csgn and cgrd verification capabilities.
- Accepts the signed settings resulting from admin actions; this is the only path by which policy reaches cfrm.

### Never

- No second signature or policy checker, no loading of private keys, no per-member admission queries, and no copying of snapshots into a persistent member database.
- Holds no trust revision of its own and no member registry.
- A fresh publication alone is never positive admission.
- No trust scores or confidence levels; gates are on or off.

### States

Derived readiness only: Unready, Current, or Unavailable, from Charter freshness and Envoy state. A newer revision, a newer verified policy epoch, expiry, clock regression, or exceeded maximum staleness makes it Unavailable.

### Test obligations

- Real feed-to-Charter-to-guard integration: an invalid, missing, or stale publication refuses entry and change.
- Feed failures and epoch updates propagate to Gather without facade-built verdicts.
- A member-presented newer policy epoch closes readiness until an authenticated feed catches up; a false high hint may deny availability but never grants authority.

## Reuse and candidates

Reuse cchr/csgn/cshm for trust verification and schema semantics. Envoy owns the extracted feed
state machine and native HTTPS adapter. cvld's actual public
POST actions are the protocol. Importing its server package into the runtime
would couple a device consumer to issuer secrets/storage and the server graph.

[reqwest](https://docs.rs/reqwest/latest/reqwest/) and its
[redirect policy](https://docs.rs/reqwest/latest/reqwest/redirect/struct.Policy.html)
provide native HTTP/TLS; `Policy::none` enforces refusal. serde supplies bounded
announcement decoding and url validates origins. Generic retry crates such as
backoff can schedule retries, but do not own the required response-generation,
announcement and Charter freshness state; a small explicit machine keeps these
transitions deterministic and testable without a runtime or hidden wall clock.

`VerifiedCharter::admission_policy(action, now, maximum_snapshot_age)` borrows the
original signed full policy and separate revocations for Guard. Guard delegates
policy to Rulebook and requires a valid credential, device signature and profile.
A fresh publication alone is not positive admission. Native and wasm tests also
verify the actual door's authorized-device bundles through Assurance and Guard;
production forum wiring remains downstream.

## Real door evidence

Native and wasm tests replay unchanged public feed and announcement bytes from
[Charter’s running cvld door tests](https://github.com/corbet-foss/cchr/blob/main/.github/workflows/ci.yml).
They cover all/any/threshold policy edits, schema changes and last-passkey
revocation; ordinary registration, issuance and renewal leave the feed unchanged.
[Fixture provenance](tests/fixtures/README.md) records exact producer revisions
and SHA-256 digests. Native tests run a real local TLS server, including refusal
of a valid-TLS response whose publishing ring lacks configured authority.

## Dependency maintenance and coverage

First-party dependencies follow `main`; Cargo.lock records one exact revision
per crate. CI checks the entire resolved graph, including optional declarations.
Dependabot covers Cargo and GitHub Actions (there is no npm manifest here).
The merge workflow uses GitHub metadata only and requires every substantive CI
job and all published checks to succeed on the exact Dependabot head. It never
executes PR code with write permissions or bypasses branch protection.

[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) supplies LLVM line and
branch measurements; the strict gate and exclusions are in [COVERAGE.md](docs/COVERAGE.md).
