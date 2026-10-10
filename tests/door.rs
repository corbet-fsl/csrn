mod support;
use csrn::{
    Assurance, Error,
    cchr::{Configuration, Error as TrustError, Kind},
    feed::{Action, Config},
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;
const ISSUANCE_ACTION: &str = "community.admit";
const NOW: u64 = 1_800_000_003;
const ORIGIN: &str = "https://alpha.example.test";
const INITIAL: &[u8] = include_bytes!("fixtures/initial.json");
const ORDINARY: &[u8] = include_bytes!("fixtures/ordinary.json");
const UPDATES: [(&[u8], &[u8]); 5] = [
    (
        include_bytes!("fixtures/all-announcement.json"),
        include_bytes!("fixtures/all.json"),
    ),
    (
        include_bytes!("fixtures/any-announcement.json"),
        include_bytes!("fixtures/any.json"),
    ),
    (
        include_bytes!("fixtures/threshold-announcement.json"),
        include_bytes!("fixtures/threshold.json"),
    ),
    (
        include_bytes!("fixtures/schema-announcement.json"),
        include_bytes!("fixtures/schema.json"),
    ),
    (
        include_bytes!("fixtures/revoked-announcement.json"),
        include_bytes!("fixtures/revoked.json"),
    ),
];
fn configuration() -> Configuration {
    let root: Value =
        serde_json::from_slice(include_bytes!("fixtures/publishing-root.json")).unwrap();
    Configuration {
        origin: ORIGIN.into(),
        community: "alpha".into(),
        key_ring: serde_json::from_value(root["key_ring"].clone()).unwrap(),
        minimum_revision: root["minimum_revision"].as_u64().unwrap(),
        ring_revision: 0,
    }
}
fn config() -> Config {
    Config {
        refresh_seconds: 40,
        poll_seconds: 2,
        request_seconds: 26,
        initial_backoff_seconds: 2,
        maximum_backoff_seconds: 16,
        retry_entropy: 0,
        maximum_staleness_seconds: 60,
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_door_policy_schema_and_revocation_announcements_drive_the_follower() {
    assert_eq!(INITIAL, ORDINARY);
    let mut a = Assurance::new(configuration(), config()).unwrap();
    let request = a.start(NOW).unwrap();
    a.on_feed(request.id(), INITIAL, NOW).unwrap();
    let mut now = NOW;
    for (announcement, bytes) in UPDATES {
        now += 2;
        let poll = a.next(now).unwrap().unwrap();
        assert!(matches!(poll.action(), Action::Poll { .. }));
        a.on_announcement(poll.id(), announcement, now).unwrap();
        assert_eq!(a.current(now).unwrap_err(), Error::Unavailable);
        let fetch = a.next(now).unwrap().unwrap();
        assert_eq!(fetch.action(), Action::Fetch);
        a.on_feed(fetch.id(), bytes, now).unwrap();
        let raw: Value = serde_json::from_slice(bytes).unwrap();
        let current = a.current(now).unwrap();
        assert_eq!(current.revision(), raw["revision"].as_u64().unwrap());
        assert_eq!(
            current.publication(Kind::Settings).signed_bytes(),
            serde_json::from_value::<Vec<u8>>(raw["settings"].clone()).unwrap()
        );
        let policy = current
            .admission_policy(ISSUANCE_ACTION, now, 86_400)
            .unwrap();
        assert_eq!(
            policy.policy.settings,
            current.publication(Kind::Settings).signed_bytes()
        );
        assert_eq!(
            policy.revocations,
            current.publication(Kind::Revocations).signed_bytes()
        );
        assert_eq!(
            a.on_announcement(poll.id(), announcement, now),
            Err(Error::Obsolete)
        );
    }
    a.refresh(now).unwrap();
    let fetch = a.next(now).unwrap().unwrap();
    assert_eq!(
        a.on_feed(fetch.id(), INITIAL, now),
        Err(Error::Trust(TrustError::Rollback))
    );
    assert!(a.current(now).is_ok());
    assert!(a.current(now + 60).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_door_legacy_bundles_never_become_action_bound_authority() {
    let bundles: &[&[u8]] = &[
        include_bytes!("fixtures/all-bundle.json"),
        include_bytes!("fixtures/any-bundle.json"),
        include_bytes!("fixtures/threshold-bundle.json"),
        include_bytes!("fixtures/schema-bundle.json"),
    ];
    let mut assurance = Assurance::new(configuration(), config()).unwrap();
    let fetch = assurance.start(NOW).unwrap();
    assurance.on_feed(fetch.id(), INITIAL, NOW).unwrap();
    let mut now = NOW;
    let mut last = None;
    for ((announcement, feed), capture) in UPDATES.iter().zip(bundles) {
        now += 2;
        let poll = assurance.next(now).unwrap().unwrap();
        assurance
            .on_announcement(poll.id(), announcement, now)
            .unwrap();
        assert_eq!(assurance.current(now).unwrap_err(), Error::Unavailable);
        let fetch = assurance.next(now).unwrap().unwrap();
        assurance.on_feed(fetch.id(), feed, now).unwrap();
        let capture: Value = serde_json::from_slice(capture).unwrap();
        let bundle: cgrd::Bundle = serde_json::from_value(capture["bundle"].clone()).unwrap();
        assert_eq!(capture["action"].as_str().unwrap(), ISSUANCE_ACTION);
        let current = assurance.current(now).unwrap();
        let policy = current
            .admission_policy(ISSUANCE_ACTION, now, 86_400)
            .unwrap();
        let schema = current.publication(Kind::Schema).signed_bytes();
        // The historical credential signature is genuine. Its old payload has
        // no signed v2 purpose/action and must never acquire those claims here.
        let body: cgrd::BundleContent = serde_json::from_slice(&bundle.payload).unwrap();
        let credential = policy
            .policy
            .keys
            .verify(&body.credential, csgn::Kind::Credential, now)
            .unwrap();
        let payload: Value = serde_json::from_slice(credential.payload()).unwrap();
        assert!(payload.get("purpose").is_none());
        assert!(payload.get("issuance_action").is_none());
        assert_eq!(
            cgrd::check_published(&bundle, &policy, schema),
            cgrd::Admission::Refused {
                reasons: vec![cgrd::Refusal::Credential]
            }
        );
        let mut changed = bundle.clone();
        changed.payload.push(b' ');
        assert_eq!(
            cgrd::check_published(&changed, &policy, schema),
            cgrd::Admission::Refused {
                reasons: vec![cgrd::Refusal::Credential]
            }
        );
        last = Some(bundle);
    }
    now += 2;
    let (announcement, feed) = UPDATES[4];
    let poll = assurance.next(now).unwrap().unwrap();
    assurance
        .on_announcement(poll.id(), announcement, now)
        .unwrap();
    assert_eq!(assurance.current(now).unwrap_err(), Error::Unavailable);
    let fetch = assurance.next(now).unwrap().unwrap();
    assurance.on_feed(fetch.id(), feed, now).unwrap();
    let bundle = last.unwrap();
    let current = assurance.current(now).unwrap();
    let policy = current
        .admission_policy(ISSUANCE_ACTION, now, 86_400)
        .unwrap();
    // Legacy format refuses before epoch/device checks. The separate current
    // owner fixture below retains genuine binding and epoch refusal scenarios.
    assert_eq!(
        cgrd::check_published(
            &bundle,
            &policy,
            current.publication(Kind::Schema).signed_bytes()
        ),
        cgrd::Admission::Refused {
            reasons: vec![cgrd::Refusal::Credential]
        }
    );
    assert_eq!(assurance.current(now + 61).unwrap_err(), Error::Unavailable);
}

fn signed_owner_feed(issuer: &mut csgn::Signer, original: &csrn::cchr::VerifiedCharter) -> Value {
    use serde_json::json;
    let revision = original.revision();
    let epoch = original.policy_epoch();
    assert!(
        original
            .publication(Kind::Settings)
            .content()
            .get("action/community.admit")
            .is_some()
    );
    let mut feed =
        json!({"revision":revision,"policy_epoch":epoch,"key_ring":issuer.key_ring().to_cbor()});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
        "policy_epoch":epoch,"key_ring":issuer.key_ring().to_cbor(),
        "schema_version":original.schema().version});
    feed["manifest"] = json!(support::sign(
        issuer,
        csgn::Kind::SettingsSnapshot,
        manifest
    ));
    // These public terms were already authenticated by the ORIGINAL Charter.
    // Sign them only under the independent fixture root; no captured private
    // seed is known or used, and no Global requirement is stripped or invented.
    for (name, kind, publication) in [
        ("settings", csgn::Kind::SettingsSnapshot, Kind::Settings),
        ("schema", csgn::Kind::SchemaSnapshot, Kind::Schema),
        (
            "schema_versions",
            csgn::Kind::SchemaSnapshot,
            Kind::SchemaVersions,
        ),
        (
            "communities",
            csgn::Kind::CommunitiesSnapshot,
            Kind::Communities,
        ),
        (
            "revocations",
            csgn::Kind::RevocationListSnapshot,
            Kind::Revocations,
        ),
    ] {
        feed[name] = json!(support::sign(
            issuer,
            kind,
            json!({"community":"alpha","revision":revision,"policy_epoch":epoch,
                "content":original.publication(publication).content()})
        ));
    }
    feed
}

fn signed_owner_bundle(
    issuer: &mut csgn::Signer,
    device: &SigningKey,
    epoch: u64,
    schema_version: u32,
    issuance_action: &str,
) -> cgrd::Bundle {
    use serde_json::json;
    let credential = support::sign(
        issuer,
        csgn::Kind::Credential,
        json!(cgrd::Credential {
            purpose: cgrd::CredentialPurpose::CommunityCredentialV2,
            issuance_action: issuance_action.into(),
            community: "alpha".into(),
            member: "fixture-member".into(),
            handle: "mountain".into(),
            schema_version,
            policy_epoch: epoch,
            gates: vec![cgrd::Gate {
                gate: "cvch".into(),
                provider: "sponsor".into(),
                valid_until: support::NOW + 500,
            }],
            pins: vec![],
            devices: vec![device.verifying_key().to_bytes()],
        }),
    );
    let body = cgrd::BundleContent {
        community: "alpha".into(),
        member: "fixture-member".into(),
        device: device.verifying_key().to_bytes(),
        hpke_key: None,
        credential,
        profile: serde_json::from_value(json!({"scope":"public","profile":{
            "community":"alpha","schema_version":schema_version,"public":{}
        }}))
        .unwrap(),
        openings: vec![],
    };
    let payload = serde_json::to_vec(&body).unwrap();
    let signature = device
        .sign(&cgrd::binding_bytes(&payload))
        .to_bytes()
        .to_vec();
    cgrd::Bundle { payload, signature }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn current_signed_owner_bundles_preserve_follower_guard_binding_and_epoch_checks() {
    // This is a real-signature consumer/owner fixture, not current cvld/cplc
    // producer evidence. Complete fresh issuer captures remain independently
    // required. The signer/device are unrelated to the frozen deployment root.
    let mut original = csrn::cchr::Charter::new(configuration()).unwrap();
    original.install(INITIAL, NOW).unwrap();
    let mut issuer = support::signer();
    let device = SigningKey::from_bytes(&[81; 32]);
    let mut assurance = Assurance::new(support::configuration(ORIGIN, "alpha"), config()).unwrap();
    let request = assurance.start(NOW).unwrap();
    let feed = signed_owner_feed(&mut issuer, original.current(NOW).unwrap());
    assurance
        .on_feed(request.id(), &support::bytes(&feed), NOW)
        .unwrap();
    let mut now = NOW;
    let mut last = None;
    for (_, feed) in &UPDATES[..4] {
        now += 2;
        original.install(feed, now).unwrap();
        let source = original.current(now).unwrap();
        let revision = source.revision();
        let epoch = source.policy_epoch();
        let schema_version = source.schema().version;
        let poll = assurance.next(now).unwrap().unwrap();
        assert!(matches!(poll.action(), Action::Poll { .. }));
        // Announcements schedule refresh; only the following signed feed can
        // establish authority, exactly as in the existing follower vectors.
        assurance
            .on_announcement(
                poll.id(),
                &support::bytes(&serde_json::json!({"revision":revision,
                    "policy_epoch":epoch,"changed":true})),
                now,
            )
            .unwrap();
        assert_eq!(assurance.current(now).unwrap_err(), Error::Unavailable);
        let fetch = assurance.next(now).unwrap().unwrap();
        assert_eq!(fetch.action(), Action::Fetch);
        let signed_feed = signed_owner_feed(&mut issuer, source);
        assurance
            .on_feed(fetch.id(), &support::bytes(&signed_feed), now)
            .unwrap();
        let bundle =
            signed_owner_bundle(&mut issuer, &device, epoch, schema_version, ISSUANCE_ACTION);
        let current = assurance.current(now).unwrap();
        assert_eq!(current.revision(), revision);
        assert_eq!(current.policy_epoch(), epoch);
        assert_eq!(current.schema().version, schema_version);
        let policy = current
            .admission_policy(ISSUANCE_ACTION, now, 86_400)
            .unwrap();
        assert_eq!(policy.policy.expected_issuance_action, ISSUANCE_ACTION);
        let schema = current.publication(Kind::Schema).signed_bytes();
        assert!(cgrd::check_published(&bundle, &policy, schema).is_admitted());
        let mut changed = bundle.clone();
        changed.payload.push(b' ');
        assert_eq!(
            cgrd::check_published(&changed, &policy, schema),
            cgrd::Admission::Refused {
                reasons: vec![cgrd::Refusal::Binding]
            }
        );
        let wrong_action =
            signed_owner_bundle(&mut issuer, &device, epoch, schema_version, "other.admit");
        assert_eq!(
            cgrd::check_published(&wrong_action, &policy, schema),
            cgrd::Admission::Refused {
                reasons: vec![cgrd::Refusal::Credential]
            }
        );
        last = Some(bundle);
    }
    now += 2;
    original.install(UPDATES[4].1, now).unwrap();
    let signed_feed = signed_owner_feed(&mut issuer, original.current(now).unwrap());
    assurance.refresh(now).unwrap();
    let fetch = assurance.next(now).unwrap().unwrap();
    assurance
        .on_feed(fetch.id(), &support::bytes(&signed_feed), now)
        .unwrap();
    let current = assurance.current(now).unwrap();
    let policy = current
        .admission_policy(ISSUANCE_ACTION, now, 86_400)
        .unwrap();
    // The original last-passkey removal is an epoch increase; its captured
    // member/device lists are empty. Do not fabricate a matching revocation.
    assert_eq!(
        cgrd::check_published(
            &last.unwrap(),
            &policy,
            current.publication(Kind::Schema).signed_bytes()
        ),
        cgrd::Admission::Refused {
            reasons: vec![cgrd::Refusal::Version]
        }
    );
    assert_eq!(assurance.current(now + 61).unwrap_err(), Error::Unavailable);
}
