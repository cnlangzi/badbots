//! The address index of a loaded feed.
//!
//! The index holds the observations of one snapshot: the observations about an
//! exact address in a map, and the observations about a network in one bucket
//! per prefix length. A lookup returns the observations about the exact address
//! and the observations of the most specific network that contains it.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{Evidence, MatchScope, normalize};

/// The raw value that carries the address an exact observation is about.
///
/// A snapshot holds observations and nothing else, so an observation about an
/// exact address records that address in its raw values for the index to
/// resolve it.
pub const ADDRESS_KEY: &str = "address";

/// The observations of one feed, indexed for lookup.
#[derive(Clone, Debug, Default)]
pub struct IpIndex {
    exact: HashMap<IpAddr, Vec<Evidence>>,
    prefixes: HashMap<u8, Vec<(IpNet, Vec<Evidence>)>>,
}

impl IpIndex {
    /// Builds an index from the observations of a snapshot.
    pub fn build(entries: &[Evidence]) -> Self {
        let mut index = Self::default();

        for entry in entries {
            match entry.scope {
                MatchScope::Exact => {
                    let Some(address) = address_of(entry) else {
                        continue;
                    };
                    index.exact.entry(address).or_default().push(entry.clone());
                }
                MatchScope::Prefix { network } => {
                    let network = network.trunc();
                    index
                        .prefixes
                        .entry(network.prefix_len())
                        .or_default()
                        .push((network, vec![entry.clone()]));
                }
            }
        }

        for bucket in index.prefixes.values_mut() {
            bucket.sort_by_key(|entry| entry.0);
        }

        index
    }

    /// The observations that apply to an address.
    ///
    /// The observations about the exact address come first, followed by the
    /// observations of the most specific network that contains the address.
    pub fn lookup(&self, ip: IpAddr) -> Vec<Evidence> {
        let ip = normalize(ip);
        let mut found = self.exact.get(&ip).cloned().unwrap_or_default();

        if let Some((_, observations)) = self.longest_prefix(ip) {
            found.extend(observations.iter().cloned());
        }

        found
    }

    /// The number of observations the index holds.
    pub fn len(&self) -> usize {
        self.exact.values().map(Vec::len).sum::<usize>()
            + self
                .prefixes
                .values()
                .map(|bucket| bucket.len())
                .sum::<usize>()
    }

    /// Whether the index holds no observation.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The most specific network that contains the address.
    fn longest_prefix(&self, ip: IpAddr) -> Option<&(IpNet, Vec<Evidence>)> {
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
                return Some(&bucket[position]);
            }
        }

        None
    }
}

/// The address an exact observation is about.
fn address_of(entry: &Evidence) -> Option<IpAddr> {
    let address = entry.raw_values.get(ADDRESS_KEY)?;
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
        let mut raw_values = BTreeMap::new();
        raw_values.insert(super::ADDRESS_KEY.to_string(), address.to_string());
        Evidence {
            provider: ProviderId::new("test"),
            family: SourceFamily::new("test"),
            assertion: Assertion::Attack,
            category: ThreatCategory::WebAttack,
            raw_category: None,
            strength: EvidenceStrength::Indicative,
            scope: MatchScope::Exact,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            raw_values,
        }
    }

    fn prefix(network: &str) -> Evidence {
        Evidence {
            provider: ProviderId::new("test"),
            family: SourceFamily::new("test"),
            assertion: Assertion::NetworkControl,
            category: ThreatCategory::MaliciousNetwork,
            raw_category: None,
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
            raw_values: BTreeMap::new(),
        }
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_most_specific_network_wins() {
        let index = IpIndex::build(&[prefix("45.32.0.0/16"), prefix("45.32.1.0/24")]);
        let found = index.lookup(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].scope,
            MatchScope::Prefix {
                network: "45.32.1.0/24".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn a_shorter_network_is_used_when_no_longer_one_matches() {
        let index = IpIndex::build(&[prefix("45.32.0.0/16")]);
        let found = index.lookup(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].scope,
            MatchScope::Prefix {
                network: "45.32.0.0/16".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn an_exact_address_is_resolved() {
        let index = IpIndex::build(&[exact("45.32.1.1")]);
        let found = index.lookup(address("45.32.1.1"));

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].scope, MatchScope::Exact);
        assert!(index.lookup(address("45.32.1.2")).is_empty());
    }

    #[test]
    fn an_ipv6_prefix_is_matched() {
        let index = IpIndex::build(&[prefix("2001:db8::/32"), prefix("2001:db8:1::/48")]);
        let found = index.lookup(address("2001:db8:1::1"));

        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].scope,
            MatchScope::Prefix {
                network: "2001:db8:1::/48".parse::<IpNet>().unwrap()
            }
        );
    }

    #[test]
    fn an_address_of_the_other_family_never_matches() {
        let index = IpIndex::build(&[prefix("45.32.0.0/16")]);
        assert!(index.lookup(address("2001:db8::1")).is_empty());
    }

    #[test]
    fn an_observation_without_an_address_is_not_indexed() {
        let mut entry = exact("45.32.1.1");
        entry.raw_values.clear();
        let index = IpIndex::build(&[entry]);

        assert!(index.is_empty());
    }

    #[test]
    fn the_expiry_of_an_observation_is_carried() {
        let mut entry = exact("45.32.1.1");
        entry.expires_at = Some(OffsetDateTime::UNIX_EPOCH);
        let index = IpIndex::build(&[entry]);
        let found = index.lookup(address("45.32.1.1"));

        assert_eq!(found[0].expires_at, Some(OffsetDateTime::UNIX_EPOCH));
    }
}
