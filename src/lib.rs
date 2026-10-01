//! Assurance wires Charter and the feed follower. Domain logic stays below.
#![forbid(unsafe_code)]
pub use cchr;
pub use cnvy::feed;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use cnvy::http;
pub use cnvy::{Error, Result};
use feed::{Config, Follower, Request};
/// Derived readiness, with no separately retained trust state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    Unready,
    Current,
    Unavailable,
}
pub struct Assurance {
    charter: cchr::Charter,
    follower: Follower,
}
impl Assurance {
    pub fn new(origin: &str, community: &str, config: Config) -> Result<Self> {
        Ok(Self {
            charter: cchr::Charter::new(origin, community).map_err(Error::Trust)?,
            follower: Follower::new(config)?,
        })
    }
    pub fn start(&mut self, now: u64) -> Result<Request> {
        self.follower.start(now)
    }
    pub fn stop(&mut self) {
        self.follower.stop();
    }
    pub fn current(&mut self, now: u64) -> Result<&cchr::VerifiedCharter> {
        let value = self.charter.current(now).map_err(Error::Trust)?;
        self.follower
            .permits_current(value.revision(), value.policy_epoch(), now)?;
        Ok(value)
    }
    /// Derive readiness at injected Unix seconds from both child owners.
    pub fn readiness(&mut self, now: u64) -> Readiness {
        match self.current(now) {
            Ok(_) => Readiness::Current,
            Err(Error::Trust(cchr::Error::Unavailable)) => Readiness::Unready,
            Err(_) => Readiness::Unavailable,
        }
    }
    pub fn next(&mut self, now: u64) -> Result<Option<Request>> {
        let revision = self.charter.current(now).map(|v| v.revision()).unwrap_or(0);
        self.follower.next(revision, now)
    }
    pub fn on_change(&mut self, revision: u64, now: u64) -> Result<()> {
        let current = self.charter.current(now).map(|v| v.revision()).unwrap_or(0);
        self.follower.on_change(revision, current, now)
    }
    pub fn refresh(&mut self, now: u64) -> Result<()> {
        self.follower.refresh(now)
    }
    pub fn on_policy_epoch(&mut self, epoch: u64, now: u64) -> Result<()> {
        let current = self
            .charter
            .current(now)
            .map(|v| v.policy_epoch())
            .unwrap_or(0);
        self.follower.on_policy_epoch(epoch, current, now)
    }
    pub fn on_feed(
        &mut self,
        id: u64,
        bytes: &[u8],
        origin: &cchr::AuthenticatedOrigin,
        now: u64,
    ) -> Result<()> {
        self.follower
            .feed(id, bytes, origin, &mut self.charter, now)
    }
    pub fn on_announcement(&mut self, id: u64, bytes: &[u8], now: u64) -> Result<()> {
        self.follower.announcement(id, bytes, now)
    }
    pub fn on_error(&mut self, id: u64, now: u64, jitter: u64) -> Result<()> {
        self.follower.failed(id, now, jitter)
    }
    pub fn feed_state(&self) -> feed::State {
        self.follower.state()
    }
}
