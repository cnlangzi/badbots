# Blocklist.de

The Blocklist.de provider reads two products of one lineage. The per-address
query counts the attack events a partner's sensors observed. The per-service
lists name the addresses those sensors saw. Both carry the same family, so an
observation from either of them counts as one vote.

## Setup

1. Enable the crate feature:

   ```toml
   [dependencies]
   badbots = { version = "0.2", features = ["blocklist_de"] }
   ```

2. Enable the provider:

   ```rust
   let bots = BadBots::builder().enable_blocklist_de().build()?;
   ```

The provider needs no API key. The requests are:

```text
GET https://api.blocklist.de/api.php?ip={ip}&start={unix}&end={unix}&format=json
GET https://lists.blocklist.de/lists/{service}.txt
```

The per-address query is part of the verification of an address:

```rust
let verdict = bots.verify_ip(client_ip).await;
```

The per-service lists are part of `refresh_feeds`:

```rust
let report = bots.refresh_feeds().await;
```

Both parts can be switched off separately through
`BlocklistDeConfig::use_per_address_query` and
`BlocklistDeConfig::use_service_lists`.

## Quota

| Statement | Kind |
|---|---|
| The publisher states no rate limit for the per-address query | Publisher statement (upstream documentation) |
| The publisher asks for no more than one download of the lists per half hour | Publisher statement (upstream documentation) |
| The local minimum interval of the lists defaults to 30 minutes | Configuration default of this library |
| The local budget guard allows 10,000 queries per day | Configuration default of this library |

The query costs one request per verification per address. The budget is
configurable through `BlocklistDeConfig::daily_quota`.

## Data scope

The per-address query answers with the number of attack events and the number
of abuse notifications that were sent to the address's provider.

| Field | Use |
|---|---|
| `attacks` | The number of events, the count of the observation |
| `reports` | The number of abuse notifications, recorded as an upstream value only |

The publisher writes the counts as numbers when they are zero and as strings
when they are not, so both shapes are read.

The notification count is never a corroboration count. It says how often the
publisher complained to the address's provider, not how often the address
attacked something.

An address with fewer than three attack events produces no observation. An
address with three or more produces one `Corroborating` observation with the
scope `Exact`, the threat category `GenericAbuse` and the family
`blocklist_de`.

The per-service lists hold one address per line and are gzip-compressed. The
services are `all`, `ssh`, `apache`, `imap`, `ftp`, `sip`, `bots`,
`bruteforcelogin` and `strongips`. A membership produces an `Indicative`
observation with the scope `Exact`, because a membership carries no count.

The list `all` is the union of the service lists. An address that a service
list names gets its observation from that list, because the service list says
more than the union does. An address that only the union names gets the
observation of the union.

| Service | Threat category |
|---|---|
| `ssh`, `imap`, `ftp`, `sip`, `bruteforcelogin` | `BruteForce` |
| `apache` | `WebAttack` |
| `mail` | `SpamAbuse` |
| `bots`, `all`, `strongips` | `GenericAbuse` |

## Freshness

| Rule | Value |
|---|---|
| A query observation expires | The earlier of 48 hours after the query and `Config::positive_ttl`, 30 days by default |
| The interval the query asks about | 48 hours ending at the query, configurable through `BlocklistDeConfig::window` |
| A list observation of `strongips` expires | 7 days after the retrieval |
| A list observation of the other lists expires | 48 hours after the retrieval |
| The lists may be fetched again | 30 minutes after the last refresh, whether it succeeded or not |

The library expires the answer of the query at the earlier of the expiry the
publisher declares and the host bound, so a claim is never kept for longer
than `Config::positive_ttl`. The lists carry no timestamp per entry, so the
observation time of a list membership is the retrieval time and the evidence
records that it has no per-entry observation time.

## Terms and attribution

The publisher owns the data and states its own terms of use. A host that uses
this provider is bound by those terms; this library does not restate or
reinterpret them. The lists carry no attribution line, so the snapshot keeps
an empty attribution rather than an invented one.

## Known false-positive profile

The partner's sensors observe attempts, not successes. An address that only
ever tried to log in is listed next to an address that got in.

This library therefore separates the two products of the publisher:

| Situation | Strict policy | Lenient policy |
|---|---|---|
| A list membership without any other evidence | A `Unknown` verdict with the reason `InsufficientEvidence`, and never a vote | A `Bad` verdict |
| A query answer with three or more attack events | A `Corroborating` observation that adds a vote | A `Bad` verdict |
| Only Blocklist.de observed the address | Never a `Bad` verdict, because a family votes once | A `Bad` verdict |

The DShield list republishes the data of this publisher under a
`blocklistde` label. Such an observation keeps the family `blocklist_de`, so a
list and its origin never count as two votes.
