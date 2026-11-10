//! Address helpers.

use std::net::IpAddr;

use ipnet::IpNet;

/// Normalizes an address for lookup and comparison.
///
/// An IPv4-mapped IPv6 address is folded back to its IPv4 form so that the same
/// host is not counted twice.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Whether an address belongs to the shared address space of carrier grade
/// NAT (`100.64.0.0/10`).
fn is_shared_address_space(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] & 0b1100_0000 == 0b0100_0000
}

/// Whether an address can be assessed against public reputation data.
///
/// Loopback, private, link-local, shared, multicast, documentation and other
/// non-routable addresses have no public reputation, so they are never looked up.
pub fn is_assessable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || is_shared_address_space(&v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// Whether a network contains an address.
pub fn network_contains(network: &IpNet, ip: IpAddr) -> bool {
    network.contains(&normalize(ip))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{is_assessable, network_contains, normalize};
    use ipnet::IpNet;

    #[test]
    fn folds_ipv4_mapped_addresses() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808));
        assert_eq!(normalize(mapped), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn rejects_non_routable_addresses() {
        assert!(!is_assessable("127.0.0.1".parse().unwrap()));
        assert!(!is_assessable("10.0.0.1".parse().unwrap()));
        assert!(!is_assessable("192.168.1.1".parse().unwrap()));
        assert!(!is_assessable("169.254.1.1".parse().unwrap()));
        assert!(!is_assessable("224.0.0.1".parse().unwrap()));
        assert!(!is_assessable("0.0.0.0".parse().unwrap()));
        assert!(!is_assessable("::1".parse::<IpAddr>().unwrap()));
        assert!(!is_assessable("fd00::1".parse::<IpAddr>().unwrap()));
        assert!(!is_assessable("fe80::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn accepts_public_addresses() {
        assert!(is_assessable("8.8.8.8".parse().unwrap()));
        assert!(is_assessable(
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn checks_network_membership() {
        let network: IpNet = "45.32.0.0/16".parse().unwrap();
        assert!(network_contains(&network, "45.32.1.1".parse().unwrap()));
        assert!(!network_contains(&network, "45.33.1.1".parse().unwrap()));
    }
}
