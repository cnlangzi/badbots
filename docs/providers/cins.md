# CINS Army list

The CINS provider reads the CINS Army list, the list of the addresses whose
recent reputation is very poor or that tripped a designated number of trusted
alerts across the Sentinel sensors that CINS deploys around the world. The
list is a subset of the CINS Active Threat Intelligence ruleset. It names one
address per line, so its observations are a statement about a single address
and they corroborate the observations of the other providers.

The list is free, needs no account and no API key, and the publisher caps it
at 15,000 addresses.

## Setup

1. Enable the crate feature:

   ```sh
   cargo add badbots --features cins
   ```

2. Enable the provider:

   ```rust
   let bots = BadBots::builder()
       .enable_cins()
       .build()?;
   ```

3. Refresh the list off the request path:

   ```rust
   let report = bots.refresh_feeds().await;
   ```

The provider needs no API key. The request is:

```text
GET https://cinsscore.com/list/ci-badguys.txt
```

## Quota

| Statement | Kind |
|---|---|
| The publisher states no limit on the downloads of the list | Publisher statement (upstream documentation) |
| The local minimum interval defaults to 24 hours | Configuration default of this library |
| A refresh inside the minimum interval issues no request and is reported with the time that is left | Behaviour of this library |
| The local budget guard allows 10,000 requests per day | Configuration default of this library |

The interval is configurable through `CinsConfig::min_refresh_interval`.

## Data scope

The list holds one IPv4 address per line. A line that begins with `#` is a
header line and is kept verbatim, so a file that carries one does not empty the
index. The published file carries no header today.

An address of the list produces an `Attack` observation with the scope `Exact`,
the assertion `Attack` and the threat category `GenericAbuse`. The publisher
names no behaviour per address, so the category is the one that fits no
narrower behaviour. The publisher states no observation time and no publication
time either, so the observation carries neither.

Every token of a line is parsed on its own:

| Token | Result |
|---|---|
| An address | An observation |
| A range, such as `45.32.1.0/24` | No observation, because the observation of a range belongs to a source of ranges |
| A token that is no address | No observation |
| Two addresses glued together | No observation, because no address may ever be guessed |

A list that names no address at all is a parse error, so that a list whose
format changed empties no index and keeps the snapshot that was loaded before.

The list holds IPv4 addresses only, so an IPv6 address is never named by it and
its coverage of that family is partial.

## Freshness

| Rule | Value |
|---|---|
| The publication time is read from | Nowhere, because the list states none |
| An observation expires | 24 hours after the moment the list was fetched |
| The list may be fetched again | 24 hours after the last refresh, whether it succeeded or not |

The publisher states no cadence for the list. The file that was observed
carried the day of the observation in its `Last-Modified` header, so the list
is regenerated every day in practice and the interval is a day.

## Terms and attribution

The publisher states no license and no terms of use. It states that the list
is "a simple text file, with which you can parse and use in any way you see
fit". The snapshot carries the credit line of the publisher:

```rust
let attribution = bots.feed_attribution(badbots::ProviderId::CINS);
```

## Known false-positive profile

The publisher states that false positives are rare and names
`cins@sentinelips.com` as the address an operator reaches when its own
address is on the list by mistake.

The publisher distributes the list through Emerging Threats as part of its
Open Source Community, so a host that reads that list as well sees the same
addresses twice. This library reads no list of Emerging Threats, so nothing
changes inside it.

The list overlaps heavily with the other lists this library reads. A
measurement of the lists found that about 29 percent of the 15,000 addresses
of the CINS Army list are also named by the DShield threat intelligence list
and that about 2 percent are also named by the Blocklist.de service lists. The
two providers remain two source families with sensors of their own, so an
address they both name still carries two votes, but the list adds far less new
address coverage than its size suggests.

The publisher also states that the list is community sourced, that is, that it
draws reputation data from trusted sources of the InfoSec community next to
the alert activity of its own sensors. Its observations are therefore not
necessarily independent of a community feed that the host reads itself, and
the credit of an address it names does not always rest on the sensors of the
publisher alone.

This library therefore keeps the list apart:

| Situation | Strict policy | Lenient policy |
|---|---|---|
| An address that only the CINS Army list names | A `Unknown` verdict with the reason `InsufficientEvidence`, and never a conviction on its own | A `Bad` verdict |
| The CINS Army list and another family name the address | A `Bad` verdict | A `Bad` verdict |
