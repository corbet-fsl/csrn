use csrn::{
    Assurance, Error,
    cchr::{AuthenticatedOrigin, Error as TrustError, Kind},
    feed::{Action, Config},
};
use serde_json::Value;
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
fn authority() -> AuthenticatedOrigin {
    let first: Value = serde_json::from_slice(INITIAL).unwrap();
    let ring: Vec<u8> = serde_json::from_value(first["key_ring"].clone()).unwrap();
    AuthenticatedOrigin::from_authenticated_response(
        ORIGIN,
        "alpha",
        &ring,
        first["revision"].as_u64().unwrap(),
        NOW,
        NOW + 300,
    )
    .unwrap()
}
fn config() -> Config {
    Config {
        refresh_seconds: 40,
        poll_seconds: 2,
        request_seconds: 26,
        initial_backoff_seconds: 2,
        maximum_backoff_seconds: 16,
        maximum_staleness_seconds: 60,
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_door_policy_schema_and_revocation_announcements_drive_the_follower() {
    assert_eq!(INITIAL, ORDINARY);
    let authority = authority();
    let mut a = Assurance::new(ORIGIN, "alpha", config()).unwrap();
    let request = a.start(NOW).unwrap();
    a.on_feed(request.id(), INITIAL, &authority, NOW).unwrap();
    let mut now = NOW;
    for (announcement, bytes) in UPDATES {
        now += 2;
        let poll = a.next(now).unwrap().unwrap();
        assert!(matches!(poll.action(), Action::Poll { .. }));
        a.on_announcement(poll.id(), announcement, now).unwrap();
        assert_eq!(a.current(now).unwrap_err(), Error::Unavailable);
        let fetch = a.next(now).unwrap().unwrap();
        assert_eq!(fetch.action(), Action::Fetch);
        a.on_feed(fetch.id(), bytes, &authority, now).unwrap();
        let raw: Value = serde_json::from_slice(bytes).unwrap();
        let current = a.current(now).unwrap();
        assert_eq!(current.revision(), raw["revision"].as_u64().unwrap());
        assert_eq!(
            current.publication(Kind::Settings).signed_bytes(),
            serde_json::from_value::<Vec<u8>>(raw["settings"].clone()).unwrap()
        );
        let policy = current.admission_policy("admission", now, 86_400).unwrap();
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
        a.on_feed(fetch.id(), INITIAL, &authority, now),
        Err(Error::Trust(TrustError::Rollback))
    );
    assert!(a.current(now).is_ok());
    assert!(a.current(now + 60).is_err());
}
