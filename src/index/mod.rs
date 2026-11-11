//! The local address index.
//!
//! The index turns the observations of a snapshot into an answer for a single
//! address, so that the request path never has to walk a list.

pub mod ip_index;

pub use ip_index::IpIndex;
