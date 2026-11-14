# steeman

The steeman provider reads the list of the addresses that the intrusion
detection systems of Jeroen Steeman saw attacking. It is the only list of the
publisher that is a statement about a single address, so its observations
corroborate the observations of the other providers.

## Setup

1. Enable the crate feature:

   ```sh
   cargo add badbots --features steeman
   ```

2. Enable the provider:

   ```rust
   let bots = BadBots::builder()
       .enable_steeman()
       .build()?;
   ```

3. Refresh the list off the request path:

   ```rust
   let report = bots.refresh_feeds().await;
   ```

The provider needs no API key. The request is:

```text
GET https://www.steeman.org/Level2_IP_Block_List.txt
```

The publisher states the rules of his lists on
`https://www.steeman.org/IPBlock`.

## Quota

| Statement | Kind |
|---|---|
| The publisher asks for no more than two downloads a day | Publisher statement (upstream documentation) |
| The local minimum interval defaults to 24 hours | Configuration default of this library |
| A refresh inside the minimum interval issues no request and is reported with the time that is left | Behaviour of this library |
| The local budget guard allows 10,000 requests per day | Configuration default of this library |

The interval is configurable through `SteemanConfig::min_refresh_interval`.

## Data scope

The list holds one address per line. The lines that begin with `#` are the
header of the list and are kept verbatim.

An address of the list produces an `Attack` observation with the scope `Exact`,
the assertion `Attack` and the threat category `GenericAbuse`. The publisher
does not say when he saw the address, so the observation carries no
observation time and the publication time of the list is the only time it
carries.

The publisher's file loses a line break now and then, so a line may hold two
addresses glued together, and a line may hold a range. Every token of a line
is parsed on its own:

| Token | Result |
|---|---|
| An address | An observation |
| A range, such as `45.32.1.0/24` | No observation, because the observation of a range belongs to a source of ranges |
| A token that is no address | No observation |
| Two addresses glued together | No observation, because no address may ever be guessed |

A list that names no address at all is a parse error, so that a list whose
format changed empties no index and keeps the snapshot that was loaded before.

The count the header states is not compared with the number of the parsed
observations: the count of the publisher is already known to differ from the
content of his files by a few entries. The count stays in the header lines,
which a host can read.

The list holds IPv4 addresses only, so an IPv6 address is never named by it and
its coverage of that family is partial.

## Freshness

| Rule | Value |
|---|---|
| The publication time is read from | The header of the list |
| An observation expires | 48 hours after the publication time, or 48 hours after the retrieval when the header carries no time |
| The list may be fetched again | 24 hours after the last refresh, whether it succeeded or not |

The publisher writes the publication time as `D/M/YYYY H:mm:ss UTC`. The hour
is on a twenty-four-hour clock, and a meridiem may be named, in which case the
hour is on a twelve-hour clock. The day and the month are read in either
order, and the two orders name dates that lie a month apart from each other.
The list is published every day, so the date it names lies close to the moment
of the retrieval: the later of the two dates is the one the publisher means,
as long as it does not lie more than a day after the retrieval. A header that
carries no readable time leaves the publication time unset, and the
observations then run from the moment the list was fetched.

## Terms and attribution

The publisher owns the data and states his own terms of use. A host that uses
this provider is bound by those terms. The snapshot carries the credit and the
terms of the publisher:

```rust
let attribution = bots.feed_attribution(badbots::ProviderId::STEEMAN);
```

## Known false-positive profile

The publisher consults AbuseIPDB before he decides that an address belongs in
his list. An address that the steeman list and AbuseIPDB both name is
therefore corroborated by data that partly comes from AbuseIPDB, and the two
are not independent of each other.

The publisher also states that his approach has a lot of collateral damage and
that it is not advisable for an operator whose commercial interest is at heart.

The list is the only one of the publisher that is a statement about a single
address. His other lists hold whole ranges of cloud and hosting providers,
carry no documented provenance or aggregate third-party feeds, so this library
reads none of them.

This library therefore keeps the list apart:

| Situation | Strict policy | Lenient policy |
|---|---|---|
| An address that only the steeman list names | A `Unknown` verdict with the reason `InsufficientEvidence`, and never a conviction on its own | A `Bad` verdict |
| The steeman list and another family name the address | A `Bad` verdict | A `Bad` verdict |
