//! The loaded feeds of the library.
//!
//! A feed is fetched off the request path, parsed into an immutable snapshot
//! and indexed. The snapshot and its index are installed as one unit, so a
//! reader never sees a half-parsed list.

use std::collections::HashMap;
use std::sync::Arc;

use crate::index::IpIndex;
use crate::model::ProviderId;
use crate::provider::FeedSnapshot;

/// One loaded feed.
pub struct LoadedFeed {
    /// The snapshot the publisher published.
    pub snapshot: FeedSnapshot,
    /// The index built from the snapshot.
    pub index: IpIndex,
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
    pub fn get(&self, provider: &ProviderId) -> Option<&Arc<LoadedFeed>> {
        self.feeds.get(provider)
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
