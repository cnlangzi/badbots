# DShield

The DShield provider reads the lists that the sensors of the SANS ISC
cooperation publish. One list names the subnets that were seen scanning, the
other names the addresses that were seen attacking.

## Setup

1. Enable the crate feature:

   ```toml
   [dependencies]
   badbots = { version = "0.1", features = ["dshield"] }
   ```

2. Enable the provider and identify the operator:

   ```rust
   let bots = BadBots::builder()
       .enable_dshield()
       .build()?;
   ```

3. Refresh the lists off the request path:

   ```rust
   let report = bots.refresh_feeds().await;
   ```

The provider needs no API key. The requests are:

```text
GET https://feeds.dshield.org/block.txt
GET https://feeds.dshield.org/threatintel.txt
```

The mirror on `isc.sans.edu` is not used. The two are served with different
content, so mixing them makes a verdict irreproducible.

The publisher blocks requests that do not identify their sender, so the request
carries a user agent. The compiled-in default identifies the library and gives
a contact address; a host that runs at scale should set its own through
`DShieldConfig::user_agent`:

```rust
let bots = BadBots::builder()
    .enable_dshield()
    .config(config_with_your_own_user_agent)
    .build()?;
```

## Quota

| Statement | Kind |
|---|---|
| The publisher asks for no more than one download per hour | Publisher statement (upstream documentation) |
| The local minimum interval defaults to one hour | Configuration default of this library |
| A refresh inside the minimum interval issues no request and is reported with the time that is left | Behaviour of this library |
| The local budget guard allows 10,000 requests per day | Configuration default of this library |

The interval is configurable through `DShieldConfig::min_refresh_interval`.

## Data scope

`block.txt` holds one record per line, separated by tabs:

| Column | Use |
|---|---|
| Start address, end address | Recorded as raw values |
| Prefix length | The network the observation covers |
| Targets count | The number of targets that saw activity, the count of the observation |
| Network name, country, contact address | Recorded as raw values |

A record describes a range, so it produces an `Indicative` observation with the
scope `Prefix`, the assertion `Reconnaissance` and the threat category
`Scanner`. A record that does not hold all of its columns is skipped, because
the rest of the file still describes usable observations.

`threatintel.txt` holds one record per line, separated by tabs:

| Column | Use |
|---|---|
| First seen date | Recorded as a raw value |
| Last seen date | The observation time, the base of the expiry |
| Address | The address the observation is about |
| Label | The kind of activity, the rule input |
| Country | Recorded as a raw value |

An address that was last seen outside the last seven days is not an
observation any more.

Only the labels that name an attack or an abuse are read. Every other label
describes a context, and several of them name legitimate services.

| Label | Observation |
|---|---|
| `dshieldssh` | An `Attack` observation of the scope `Exact`, the strength `Corroborating` |
| `webscanner` | An `Attack` observation of the scope `Exact`, the strength `Corroborating` |
| `forumspam` | An `Abuse` observation of the strength `Indicative` |
| A label that begins with `blocklistde` | An observation of the strength `Indicative` that keeps the family `blocklist_de` |

A label that begins with `blocklistde` names the data of another publisher.
The observation keeps the family of that publisher, so a list and its origin
never count as two votes. The publisher names the services of that list by
their name and by the port they serve, and the observation carries the threat
category of the service:

| Label suffix | Service | Threat category |
|---|---|---|
| `22` | `ssh` | `BruteForce` |
| `21` | `ftp` | `BruteForce` |
| `110`, `143`, `993`, `courierimap` | `imap` | `BruteForce` |
| `80`, `443`, `apache` | `apache` | `WebAttack` |
| `25` | `mail` | `SpamAbuse` |
| `bruteforcelogin` | `bruteforcelogin` | `BruteForce` |
| `bots` | `bots` | `GenericAbuse` |

A suffix that names no service produces an `Abuse` observation of the threat
category `GenericAbuse`.

## Freshness

| Rule | Value |
|---|---|
| The list of the subnets covers | The three days before the publication time |
| A subnet observation expires | 3 days after the publication time |
| An address observation expires | 7 days after the last sighting |
| The lists may be fetched again | One hour after the last refresh, whether it succeeded or not |

The publisher writes the publication time in ISO 8601, with or without an
offset. The header of `block.txt` names it `updated`, the header of
`threatintel.txt` names it `last update`.

## Terms and attribution

The publisher owns the data and states its own terms of use. A host that uses
this provider is bound by those terms; this library does not restate or
reinterpret them. The lists carry no attribution line, so the snapshot keeps
an empty attribution rather than an invented one. The header lines of the
lists are kept verbatim, so that a host that displays derived data can show
what the publisher published.

## Known false-positive profile

The sensors observe what they see. A subnet record says that targets saw
scanning from that range, not that every address of the range scanned, and an
address record says that the sensors saw an attack, not that the attack
succeeded.

This library therefore keeps the two lists apart:

| Situation | Effect |
|---|---|
| A subnet record without any other evidence | A `Suspect` verdict, and never a vote |
| An address record with an attack label | A `Corroborating` observation that adds a vote |
| Only DShield observed the address | Never a `Bad` verdict, because a family votes once |

The publisher also lists the addresses of open resolvers, exit nodes and
services that merely receive traffic. Those labels produce no observation at
all.
