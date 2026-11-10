//! The address index of a loaded feed.
//!
//! The index holds the observations of one snapshot: the observations about an
//! exact address in a map, and the observations about a network in one bucket
//! per prefix length. A lookup returns the observations about the exact address
//! and the observations of the most specific network that contains it.
//!
//! The index holds the positions of the observations rather than the
//! observations themselves, so that a snapshot is not copied into the index.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{Evidence, MatchScope, normalize};

/// The upstream value that carries the address an exact observation is about.
///
/// A snapshot holds observations and nothing else, so an observation about an
/// exact address records that address in its upstream values for the index to
/// resolve it.
pub const ADDRESS_KEY: &str = "address";

/// The observations of one feed, indexed for lookup.
#[derive(Clone, Debug, Default)]
pub struct IpIndex {
    exact: HashMap<IpAddr, Vec<usize>>,
    prefixes: HashMap<u8, Vec<(IpNet, Vec<usize>)>>,
}

impl IpIndex {
    /// Builds an index over the observations of a snapshot.
    ///
    /// An observation about an exact address that does not record its address
    /// is not indexed, because the index cannot resolve it.
    pub fn build(entries: &[Evidence]) -> Self {
        let mut index = Self::default();

        for (position, entry) in entries.iter().enumerate() {
            match entry.scope {
                MatchScope::Exact => {
                    let Some(address) = address_of(entry) else {
                        tracing::warn!(
                            provider = %entry.provider,
                            "an observation about an exact address does not record its address"
                        );
                        continue;
                    };
                    index.exact.entry(address).or_default().push(position);
                }
                MatchScope::Prefix { network } => {
                    let network = network.trunc();
                    let bucket = index.prefixes.entry(network.prefix_len()).or_default();
                    match bucket.iter_mut().find(|(listed, _)| *listed == network) {
                        Some((_, positions)) => positions.push(position),
                        None => bucket.push((network, vec![position])),
                    }
                }
            }
        }

        for bucket in index.prefixes.values_mut() {
            bucket.sort_by_key(|(network, _)| *network);
        }

        index
    }

    /// The positions of the observations that apply to an address.
    ///
    /// The positions are the ones of the observations the index was built
    /// from. The observations about the exact address come first, followed by
    /// the observations of the most specific network that contains it.
    pub fn matches(&self, ip: IpAddr) -> Vec<usize> {
        let ip = normalize(ip);
        let mut found = self.exact.get(&ip).cloned().unwrap_or_default();

        if let Some(positions) = self.longest_prefix(ip) {
            found.extend(positions.iter().copied());
        }

        found
    }

    /// The number of observations the index holds.
    pub fn len(&self) -> usize {
        self.exact.values().map(Vec::len).sum::<usize>()
            + self
                .prefixes
                .values()
                .map(|bucket| {
                    bucket
                        .iter()
                        .map(|(_, positions)| positions.len())
                        .sum::<usize>()
                })
                .sum::<usize>()
    }

    /// Whether the index holds no observation.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most specific network that contains the address.
    fn longest_prefix(&self, ip: IpAddr) -> Option<&Vec<usize>> {
        let longest = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        for length in (0..=longest).rev() {
            let Some(bucket) = self.prefixes.get(&length) else {
                continue;
            };
            let Ok(network) = IpNet::new(ip, length) else {
                continue;
            };
            let network = network.trunc();

            if let Ok(position) = bucket.binary_search_by(|probe| probe.0.cmp(&network)) {
                return Some(&bucket[position].1);
            }
        }

        None
    }
}

/// The address an exact observation is about.
fn address_of(entry: &Evidence) -> Option<IpAddr> {
    let address = entry.upstream_values.get(ADDRESS_KEY)?;
    address.parse().ok().map(normalize)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use ipnet::IpNet;
    use time::OffsetDateTime;

    use super::IpIndex;
    use crate::model::{
        Assertion, Evidence, EvidenceStrength, MatchScope, ProviderId, SourceFamily, ThreatCategory,
    };

    fn exact(address: &str) -> Evidence {
        let mut upstream_values = BTreeMap::new();
        upstream_values.insert(super::ADDRESS_KEY.to_string(), address.to_string());
        Evidence {
            provider: ProviderId::new("test"),
            family: SourceFamily::new("test"),
            assertion: Assertion::Attack,
            category: ThreatCategory::WebAttack,
            upstream_category: None,
            strength: EvidenceStrength::Indicative,
            scope: MatchScope::Exact,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            upstream_values,
        }
    }

    fn prefix(network: &str) -> Evidence {
        Evidence {
            provider: ProviderId::new("test"),
            family: SourceFamily::new("test"),
            assertion: Assertion::NetworkControl,
            category: ThreatCategory::MaliciousNetwork,
            upstream_category: None,
            strength: EvidenceStrength::Indicative,
            scope: MatchScope::Prefix {
                network: network.parse::<IpNet>().unwrap(),
            },
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            upstream_values: BTreeMap::new(),
        }
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_most_specific_network_wins() {
        let entries = [prefix("45.32.0.0/16"), prefix("45.32.1.0/24")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            entries[found[0]].scope,
            MatchScope::Prefix {
                network: "45.32.1.0/24".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn a_shorter_network_is_used_when_no_longer_one_matches() {
        let entries = [prefix("45.32.0.0/16")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            entries[found[0]].scope,
            MatchScope::Prefix {
                network: "45.32.0.0/16".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn every_observation_of_a_network_is_found() {
        let entries = [prefix("45.32.0.0/16"), prefix("45.32.0.0/16")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(found.len(), 2);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn an_exact_address_is_resolved() {
        let entries = [exact("45.32.1.1")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(entries[found[0]].scope, MatchScope::Exact);
        assert!(index.matches(address("45.32.1.2")).is_empty());
    }

    #[test]
    fn an_exact_address_and_its_network_are_both_found() {
        let entries = [exact("45.32.1.1"), prefix("45.32.0.0/16")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(found.len(), 2);
    }

    #[test]
    fn an_ipv6_prefix_is_matched() {
        let entries = [prefix("2001:db8::/32"), prefix("2001:db8:1::/48")];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("2001:db8:1::1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            entries[found[0]].scope,
            MatchScope::Prefix {
                network: "2001:db8:1::/48".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn an_address_of_the_other_family_never_matches() {
        let entries = [prefix("45.32.0.0/16")];
        let index = IpIndex::build(&entries);

        assert!(index.matches(address("2001:db8::1")).is_empty());
    }

    #[test]
    fn an_observation_without_an_address_is_not_indexed() {
        let mut entry = exact("45.32.1.1");
        entry.upstream_values.clear();
        let index = IpIndex::build(&[entry]);

        assert!(index.is_empty());
    }

    #[test]
    fn the_expiry_of_an_observation_is_carried() {
        let mut entry = exact("45.32.1.1");
        entry.expires_at = Some(OffsetDateTime::UNIX_EPOCH);
        let entries = [entry];
        let index = IpIndex::build(&entries);
        let found = index.matches(address("45.32.1.1"));

        assert_eq!(
            entries[found[0]].expires_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
    }
}
