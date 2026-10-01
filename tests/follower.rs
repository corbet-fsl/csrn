mod support;
use csrn::{
    Assurance, Error,
    feed::{Action, Config, State},
};
use support::*;
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
fn ready() -> (Assurance, csgn::Signer) {
    let mut signer = signer();
    let feed = feed(&mut signer, 10, 1);
    let authority = authority(&signer);
    let mut a = Assurance::new(ORIGIN, "alpha", config()).unwrap();
    let request = a.start(NOW).unwrap();
    a.on_feed(request.id(), &bytes(&feed), &authority, NOW)
        .unwrap();
    (a, signer)
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn startup_announcements_and_atomic_install() {
    let (mut a, mut s) = ready();
    assert_eq!(a.feed_state(), State::Following);
    assert_eq!(a.current(NOW).unwrap().revision(), 10);
    assert!(a.next(NOW + 1).unwrap().is_none());
    let poll = a.next(NOW + 2).unwrap().unwrap();
    assert_eq!(poll.path(), "/v1/trust_changes");
    assert_eq!(poll.body(), serde_json::json!({"revision":10}));
    a.on_announcement(
        poll.id(),
        br#"{"revision":11,"policy_epoch":2,"changed":true}"#,
        NOW + 2,
    )
    .unwrap();
    assert!(a.current(NOW + 2).is_err());
    let request = a.next(NOW + 2).unwrap().unwrap();
    assert_eq!(request.action(), Action::Fetch);
    assert_eq!(request.body(), serde_json::json!({}));
    let current = feed(&mut s, 11, 2);
    a.on_feed(request.id(), &bytes(&current), &authority(&s), NOW + 2)
        .unwrap();
    assert_eq!(a.current(NOW + 2).unwrap().revision(), 11);
    assert_eq!(
        a.on_announcement(poll.id(), br#"{}"#, NOW + 2),
        Err(Error::Obsolete)
    );
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lost_announcements_refresh_and_failure_never_extends_freshness() {
    let (mut a, _) = ready();
    // No change delivery: the bounded timer still fetches public material.
    let refresh = a.next(NOW + 40).unwrap().unwrap();
    assert_eq!(refresh.action(), Action::Fetch);
    a.on_error(refresh.id(), NOW + 40, u64::MAX).unwrap();
    assert_eq!(a.feed_state(), State::Backoff);
    assert!(a.next(NOW + 41).unwrap().is_none());
    assert!(a.current(NOW + 59).is_ok());
    assert_eq!(a.current(NOW + 60).unwrap_err(), Error::Unavailable);
    let retry = a.next(NOW + 60).unwrap().unwrap();
    assert_eq!(retry.action(), Action::Fetch);
    assert!(a.next(NOW + 60).unwrap().is_none());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancellations_duplicates_clock_regression_and_restart_are_fenced() {
    let (mut a, mut s) = ready();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    a.stop();
    assert_eq!(a.feed_state(), State::Stopped);
    assert!(a.current(NOW + 2).is_err());
    assert_eq!(
        a.on_announcement(poll.id(), br#"{}"#, NOW + 2),
        Err(Error::Obsolete)
    );
    let fresh = a.start(NOW + 2).unwrap();
    assert!(fresh.id() > poll.id());
    assert!(a.current(NOW + 2).is_err());
    let v = feed(&mut s, 9, 1);
    assert_eq!(
        a.on_feed(fresh.id(), &bytes(&v), &authority(&s), NOW + 2),
        Err(Error::Trust(csrn::cchr::Error::Rollback))
    );
    let next = a.next(NOW + 5).unwrap().unwrap();
    assert_eq!(a.next(NOW + 4), Err(Error::ClockRegression));
    assert_eq!(a.on_error(next.id(), NOW + 5, 0), Err(Error::Obsolete));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn timeout_and_retry_storms_have_one_bounded_operation() {
    let mut a = Assurance::new(ORIGIN, "alpha", config()).unwrap();
    let initial = a.start(NOW).unwrap();
    assert!(a.next(NOW + 25).unwrap().is_none());
    assert!(a.next(NOW + 26).unwrap().is_none());
    assert_eq!(a.on_error(initial.id(), NOW + 26, 0), Err(Error::Obsolete));
    let mut count = 0;
    for offset in 27..200 {
        if let Some(r) = a.next(NOW + offset).unwrap() {
            count += 1;
            a.on_error(r.id(), NOW + offset, 0).unwrap();
            for _ in 0..20 {
                a.on_change(u64::MAX, NOW + offset).unwrap();
                assert!(a.next(NOW + offset).unwrap().is_none());
            }
        }
    }
    assert!((1..=15).contains(&count));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_announcements_and_corrupt_feed_cannot_become_trust() {
    let (mut a, s) = ready();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    assert_eq!(
        a.on_announcement(
            poll.id(),
            br#"{"revision":11,"policy_epoch":2,"changed":false}"#,
            NOW + 2
        ),
        Err(Error::Response)
    );
    assert_eq!(a.current(NOW + 2).unwrap().revision(), 10);
    let fetch = a.next(NOW + 4).unwrap().unwrap();
    assert!(
        a.on_feed(fetch.id(), b"{}", &authority(&s), NOW + 4)
            .is_err()
    );
    assert_eq!(a.current(NOW + 4).unwrap().revision(), 10);
    a.on_change(11, NOW + 4).unwrap();
    assert!(a.current(NOW + 4).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn member_epoch_hint_forces_refresh_without_becoming_authority() {
    let (mut a, mut s) = ready();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    a.on_policy_epoch(2, NOW + 2).unwrap();
    assert!(a.current(NOW + 2).is_err());
    assert_eq!(
        a.on_announcement(poll.id(), b"{}", NOW + 2),
        Err(Error::Obsolete)
    );
    let refresh = a.next(NOW + 2).unwrap().unwrap();
    let old = feed(&mut s, 11, 1);
    assert_eq!(
        a.on_feed(refresh.id(), &bytes(&old), &authority(&s), NOW + 2),
        Err(Error::BehindAnnouncement)
    );
    assert!(a.current(NOW + 2).is_err());
    let fresh = a.next(NOW + 4).unwrap().unwrap();
    let new = feed(&mut s, 12, 2);
    a.on_feed(fresh.id(), &bytes(&new), &authority(&s), NOW + 4)
        .unwrap();
    assert_eq!(a.current(NOW + 4).unwrap().policy_epoch(), 2);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn facade_readiness_is_derived_from_both_owner_states() {
    let mut unready = Assurance::new(ORIGIN, "alpha", config()).unwrap();
    assert_eq!(unready.readiness(NOW), csrn::Readiness::Unready);
    let (mut current, _) = ready();
    assert_eq!(current.readiness(NOW), csrn::Readiness::Current);
    assert_eq!(current.readiness(NOW + 61), csrn::Readiness::Unavailable);
}
