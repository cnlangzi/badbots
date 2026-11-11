# Spamhaus DROP

The Spamhaus DROP provider reads the networks that professional spam and
cyber-crime operations lease or steal. The publisher states this about a
range, never about a single address, so under the strict policy an observation
from this provider may only corroborate the observation of another source
family.

## Setup

1. Enable the crate feature:

   ```toml
   [dependencies]
   badbots = { version = "0.2", features = ["spamhaus"] }
   ```

2. Enable the provider:

   ```rust
   let bots = BadBots::builder().enable_spamhaus().build()?;
   ```

3. Refresh the lists off the request path:

   ```rust
   let report = bots.refresh_feeds().await;
   ```

The provider needs no API key. The requests are:

```text
GET https://www.spamhaus.org/drop/drop_v4.json
GET https://www.spamhaus.org/drop/drop_v6.json
```

The plain-text lists are not used. The publisher marks them for deprecation and
they lag the JSON lists.

## Quota

| Statement | Kind |
|---|---|
| The publisher asks for no more than one download per hour | Publisher statement (upstream documentation) |
| The local minimum interval defaults to one hour | Configuration default of this library |
| A refresh inside the minimum interval issues no request and is reported with the time that is left | Behaviour of this library |
| The local budget guard allows 10,000 requests per day | Configuration default of this library |

The interval is configurable through `SpamhausConfig::min_refresh_interval`. A
host that refreshes more often than the publisher allows risks being blocked
by the publisher, so the library does not do it.

## Data scope

The body of each list is JSON Lines: one object per line, the last of which is
the metadata object.

| Field | Use |
|---|---|
| `cidr` | The network the observation covers, recorded as the scope |
| `sblid` | Recorded as an upstream value |
| `rir` | Recorded as an upstream value |
| `metadata.timestamp` | The publication time, the base of the expiry |
| `metadata.copyright` | The attribution |
| `metadata.terms` | The terms, part of the attribution |

An observation about a network has the scope `Prefix`, the assertion
`NetworkControl`, the threat category `MaliciousNetwork` and the strength
`Corroborating`. The metadata object is not an entry.

## Freshness

| Rule | Value |
|---|---|
| An observation expires | 26 hours after the publication time |
| The list may be fetched again | One hour after the last refresh, whether it succeeded or not |

The publisher states that the list is refreshed daily. The 26 hours leave room
for the publication of the list to be late without the data becoming stale.

## Terms and attribution

The publisher owns the data and states its own terms of use. A host that uses
this provider is bound by those terms; this library does not restate or
reinterpret them. The snapshot keeps the upstream copyright and the upstream
terms URL verbatim in its attribution, so that a host that displays or
redistributes derived data can reproduce the credit the publisher asks for.

## Known false-positive profile

A DROP listing is a statement about a range. The publisher has been reported to
remove ranges that turned out to be legitimate, and whole-range listings have
produced collateral damage for hosting customers.

This library therefore never convicts an address on the strength of this
provider alone under the strict policy:

| Situation | Strict policy | Lenient policy |
|---|---|---|
| A DROP hit without any other evidence | A `Unknown` verdict with the reason `InsufficientEvidence`, and never a vote | A `Bad` verdict |
| A DROP hit together with an attack observation of an exact address from another source family | A `Bad` verdict | A `Bad` verdict |

The observation is prefix-scoped, so under the strict policy it never satisfies
the single-source conviction path. `Config::network_scope_policy` may be set to
`NetworkScopePolicy::Allow` to let prefix-scoped observations satisfy it, and
the same collateral damage applies to a host that does. The knob governs the
strict policy only: the lenient policy counts a range-wide observation, because
it is chosen deliberately by a host that has already reached its own
conclusion.
