//! The loaded feeds of the library.
//!
//! A feed is fetched off the request path, parsed into an immutable snapshot
//! and indexed. The snapshot and its index are installed as one unit, so a
//! reader never sees a half-parsed list.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::index::IpIndex;
use crate::model::{Evidence, ProviderId};
use crate::provider::FeedSnapshot;

/// One loaded feed.
pub struct LoadedFeed {
    /// The snapshot the publisher published.
    pub snapshot: FeedSnapshot,
    index: IpIndex,
}

impl LoadedFeed {
    /// Creates a loaded feed and the index over its observations.
    pub fn new(snapshot: FeedSnapshot) -> Self {
        let index = IpIndex::build(&snapshot.entries);
        Self { snapshot, index }
    }

    /// The observations that apply to an address.
    pub fn lookup(&self, ip: IpAddr) -> Vec<Evidence> {
        self.index
            .matches(ip)
            .into_iter()
            .filter_map(|position| self.snapshot.entries.get(position))
            .cloned()
            .collect()
    }

    /// The number of observations the feed holds.
    pub fn len(&self) -> usize {
        self.snapshot.entries.len()
    }

    /// Whether the feed holds no observation.
    pub fn is_empty(&self) -> bool {
        self.snapshot.entries.is_empty()
    }
}

impl std::fmt::Debug for LoadedFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedFeed")
            .field("provider", &self.snapshot.provider)
            .field("entries", &self.snapshot.entries.len())
            .finish()
    }
}

/// The feeds that are currently loaded.
///
/// The registry holds one feed per provider. Installing a feed replaces the
/// previous one of that provider and releases it.
#[derive(Clone, Debug, Default)]
pub struct LoadedFeeds {
    feeds: HashMap<ProviderId, Arc<LoadedFeed>>,
}

impl LoadedFeeds {
    /// The feed of a provider.
    pub fn get(&self, provider: ProviderId) -> Option<&LoadedFeed> {
        self.feeds.get(&provider).map(|feed| feed.as_ref())
    }

    /// Installs a feed, replacing the previous one of the provider.
    pub fn install(&mut self, provider: ProviderId, feed: Arc<LoadedFeed>) {
        self.feeds.insert(provider, feed);
    }

    /// The number of loaded feeds.
    pub fn len(&self) -> usize {
        self.feeds.len()
    }

    /// Whether no feed is loaded.
    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }
}
