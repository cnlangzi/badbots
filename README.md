# badbots

[![crates.io](https://img.shields.io/crates/v/badbots.svg)](https://crates.io/crates/badbots)
[![docs.rs](https://img.shields.io/docsrs/badbots.svg)](https://docs.rs/badbots)

`badbots` is a Rust library that assesses how likely an inbound request's source
IP address is to be hostile. Its users are web applications, reverse proxies,
WAFs and CDNs that need a decision plus the evidence behind it, and that then
apply their own enforcement policy.

The library is **precision-first**: an address is flagged only when a source
makes a specific, current, verifiable claim that it committed an attack. A false
positive is far more costly than a false negative, so the design accepts short
coverage rather than noisy verdicts. A host that has already reached its own
conclusion about a client and only wants an independent opinion about the
client's address switches the library to the lenient policy, which accepts any
report of doubt.

The library never blocks, bans or otherwise enforces a policy, and it holds no
allowlist of its own: an exemption is the host's own decision.

The library answers two questions about an inbound request: is this client a
bot, and is this address hostile. The host calls it when it has already
detected attack behaviour. The bot question is free and may be asked on every
request. The address question costs the quota of the upstream sources and is
asked only when the host is already suspicious.

## Quickstart

```sh
cargo add badbots --features full
```

```rust
use badbots::{BadBots, Config};

let bots = BadBots::builder()
    .config(Config::default())
    .enable_abuseipdb()
    .abuseipdb_api_key(std::env::var("BADBOTS_ABUSEIPDB_API_KEY").unwrap())
    .build()?;

// The bot question: free, synchronous, no provider involved.
let bot = bots.assess_user_agent(Some(user_agent));

// The address question: the local answer, and a verification in the background.
let verdict = bots.assess_ip(client_ip);

// The address question: the answer of the upstream.
let verdict = bots.verify_ip(client_ip).await;

match verdict.classification {
    badbots::Classification::Bad => { /* the host decides what to do */ }
    badbots::Classification::Unknown => { /* no conviction was reached */ }
}
```

## The entry points and what they cost

| Entry point | Network I/O | Upstream quota | The caller |
|---|---|---|---|
| `assess_user_agent` | none | none | is not blocked |
| `assess_ip` | none | none of its own; the verification it queues spends the quota of the providers it asks | is not blocked |
| `verify_ip` | one request per consulted provider | one lookup per consulted provider | waits for the answer |
| `refresh_feeds` | one request per list publisher | one download per list publisher | waits for the answer |

## Getting an answer

The host decides when to ask the library and what to do with the answer.

```rust
// Every request: the bot question.
let bot = bots.assess_user_agent(Some(user_agent));

// The host is already suspicious: the local answer.
let verdict = bots.assess_ip(client_ip);

// The host has to decide now: wait for the upstream.
let verdict = bots.verify_ip(client_ip).await;
```

`assess_ip` answers from the local state: the answers that are cached, the
failures that are remembered and the lists that are loaded. It performs no
network I/O on the calling thread. When the answer is not `Bad`, it makes sure
that a verification of the address runs, so that the answer of the next request
is drawn from a fresher source. An address that cannot be assessed — a private,
loopback or otherwise non-routable address — is never verified and never
reaches an upstream, and a library without a lookup provider has nothing to
verify.

`verify_ip` waits for that verification. At most one verification runs for an
address: a second caller waits for the running one instead of starting another.
The answers and the failures of a verification are remembered, so the next
assessment of the address reports them without another request.

The upstream requests of a verification run on a worker thread that belongs to
the library, on a runtime that belongs to the library. The runtime of the host
is never used for them, and the thread of the caller is never blocked by them.
The worker starts with the first verification and stops when the last handle of
the library is dropped, so a host that only asks the bot question pays for
nothing.

## The two verdicts

| Verdict | Meaning |
|---|---|
| `Bad` | The evidence bar of the policy was satisfied. |
| `Unknown` | The evidence bar of the policy was not satisfied. The reason distinguishes the cases. |

There is no "clean" verdict and no numeric score. Absence of intelligence is
reported as `Unknown`, never as a clean bill of health.

| Reason | Meaning |
|---|---|
| `Convicted` | The verdict is `Bad`. |
| `InsufficientEvidence` | Observations exist but do not satisfy the evidence bar. |
| `EvidenceExpired` | Evidence existed but had expired. |
| `NoEvidence` | Providers were consulted and reported nothing. |
| `NoCoverage` | Nothing was consulted successfully. |

### The two policies

The evidence bar and the order of the providers are chosen once, when the
library instance is built, because both decide which providers are worth
spending quota on. `Config::evidence_policy` carries the policy and
`BadBotsBuilder::evidence_policy` sets it:

```rust
let bots = BadBots::builder()
    .evidence_policy(badbots::EvidencePolicy::Lenient)
    .build()?;
```

| | `EvidencePolicy::Strict` | `EvidencePolicy::Lenient` |
|---|---|---|
| The evidence bar | One `Convicting` observation about this exact address, or two observations from different source families that corroborate each other | Every valid observation that no provider withdrew |
| The order of the providers | The providers that may convict on their own are asked first, then the others | The providers are asked from the cheapest to the most expensive one |
| A prefix-scoped observation | Never convicts on its own, but adds a vote to another family's observation | Convicts on its own |
| An `Indicative` observation | Never convicts on its own | Convicts on its own |

The strict policy is the default and keeps the precision-first design of the
library: a false positive is far more costly than a false negative. The lenient
policy is for a host that has already reached its own conclusion about a client
and wants an independent opinion about the client's address, where any report
of doubt is enough.

Under the strict policy, prefix-scoped observations never convict on their own:
a network listing is a statement about a range, and whole-range listings have
produced real collateral damage for hosting customers. A prefix-scoped
observation may add a vote to another family's observation.
`Config::network_scope_policy` can be set to `NetworkScopePolicy::Allow` to let
prefix-scoped observations satisfy the single-source path as well. The knob
governs the strict policy only: the lenient bar already accepts range-wide
observations, so it has no meaning there.

### The suppressions

A suppression speaks for the provider that published it and constrains the
evidence of that provider alone.

| Suppression | Effect under the strict policy | Effect under the lenient policy |
|---|---|---|
| `Safe` | The observations of the provider are void | The observations of the provider are void |
| `Benign` | The observations may corroborate another family but never convict on their own | The observations do not convict on their own but coexist with another family's observations |

Neither of them constrains the evidence of another provider, so an address that
one provider suppresses may still be convicted by another.

## Coverage

The verdict carries a coverage record that distinguishes "checked and found
nothing" from "never checked".

| Level | Meaning |
|---|---|
| `definitive` | The provider evaluated this address and returned a verdict, including "no malicious evidence". |
| `partial` | The provider was consulted but its statement about this address is weak. |
| `failed` | The provider errored, timed out, was rate limited or exhausted its budget. |

A provider that fails never discards the evidence of another provider. The
failure is recorded in `coverage.failed` and the verdict is computed from the
evidence that was gathered. A failed lookup is remembered for `failure_ttl`, so
a provider that is unreachable is not asked again inside that window, and the
remembered failure is reported in the coverage of the assessments that follow.

A list provider is consulted about every address that is assessed. An address
it produced an observation for is `definitive`, an address it did not match is
`partial`.

## Providers

| Provider | Feature | Capability | Lookup cost | Quota guard | Convicts alone |
|---|---|---|---|---|---|
| [AbuseIPDB](docs/providers/abuseipdb.md) | `abuseipdb` | Primary | Medium | 1,000 per day | Yes, with score ≥ 75, ≥ 2 distinct reporters, a report within 30 days and an inbound-attack category |
| [CrowdSec CTI](docs/providers/crowdsec.md) | `crowdsec` | Primary | High | 120 per month | Yes, with a malicious reputation and a malicious behavior, or a blocklist classification or reference |
| [Blocklist.de](docs/providers/blocklist-de.md) | `blocklist_de` | Corroborating | Low | 10,000 per day | No, only the attack count of the per-address query adds a vote |
| [Spamhaus DROP](docs/providers/spamhaus.md) | `spamhaus` | Corroborating | — | 10,000 per day | No, a listing is a statement about a range |
| [DShield](docs/providers/dshield.md) | `dshield` | Corroborating | — | 10,000 per day | No, only an attack record adds a vote |

Every provider is opt-in twice over: the Cargo feature has to be compiled in
**and** the configuration has to enable the provider. A provider that is
enabled in the configuration but whose feature is absent is reported as
`ConfigError::MissingFeature` when the library is built.

The `full` feature enables every provider the crate ships.

The lookup cost is what the lenient policy orders the lookup providers by. A
provider the host registers states its own cost through
`LookupProvider::cost()`. The publishers that publish a list have no lookup
provider at all, and the lists are consulted first under either policy.

### The order of the providers

A verification spends the quota of as few providers as it can.

Under the strict policy:

1. The loaded lists are merged first. They are local and free, and their
   findings can complete a corroboration without spending any quota.
2. The Primary providers are asked one at a time. A Primary provider may
   convict on its own, which makes every later request unnecessary, so the
   sequence ends as soon as the findings satisfy the evidence bar.
3. The providers that cannot convict on their own are asked together, because
   asking them one at a time would only add latency. The phase waits for every
   provider it asked: the quota of a request is spent when the request is sent,
   so an abandoned request would spend quota and lose the answer.

Under the lenient policy:

1. The loaded lists are merged first, for the same reason.
2. The lookup providers are asked one at a time, from the cheapest to the most
   expensive one, and the sequence ends at the first provider that reports an
   observation. A provider that reports nothing is not a hit, so the
   consultation moves on to the next one.

An assessment composes its verdict in the same order and stops at the same
point, so the coverage it reports is the coverage a verification would report.

## The list providers

Three of the providers publish a list instead of answering about one address:
Spamhaus DROP, the Blocklist.de service lists and DShield. The library never
fetches a list on its own; the host decides when that happens:

```rust
let report = bots.refresh_feeds().await;
```

A refresh is off the request path, and the result of it is local state: the
evidence of a list is reachable from `assess_ip` without any network I/O.

Each list publisher states how often its list may be downloaded, and the
library honours that interval. A refresh inside the interval issues no request
and is reported with the time that is left. The interval applies to a failed
refresh as well, so a publisher that is unreachable is not asked again and
again. A refresh that fails keeps the list that was loaded before, so a
publisher that is unreachable does not empty the index.

| List | Refresh interval |
|---|---|
| Spamhaus DROP | 1 hour |
| Blocklist.de service lists | 30 minutes |
| DShield | 1 hour |

A list never convicts an address on its own under the strict policy. Two
observations of the same source family count as one vote, so a list and a
mirror of it never make a verdict stronger.

The publisher of a list may ask for its credit and its terms to be
reproduced. The loaded list keeps them verbatim:

```rust
let attribution = bots.feed_attribution(badbots::ProviderId::SPAMHAUS);
```

## Registering a provider

A host with a source of threat intelligence of its own registers it with the
library. The registration takes the quota of the provider and a factory that
builds it:

```rust
let bots = BadBots::builder()
    .config(config)
    .lookup_provider(daily_guard(500), |runtime| {
        Arc::new(InternalIntelProvider::new(runtime, "https://intel.internal/v1"))
    })
    .feed_provider(monthly_guard(10), |runtime| {
        Arc::new(InternalListProvider::new(runtime))
    })
    .build()?;
```

The library builds the provider while it builds the library and hands it the
runtime the provider performs its requests in: the HTTP client the host
configured, the clock the host injected, the configured request timeout and the
quota of the registration. A provider that brought its own runtime would answer
with another clock, would not use the proxy and the certificate configuration of
the host, and its quota would not appear in the provider status.

A registered provider is consulted like every other provider: its requests run
on the worker thread of the library, its answers are cached under its own
provider id, its observations corroborate according to its own source family,
and it appears in `provider_status()` with the quota it spends. The identifier
of a registered provider has to be unique, because the cache is keyed by it: a
build with two providers of the same id fails with `ConfigError::Invalid`.

A registered lookup provider states what a lookup of it costs through
`LookupProvider::cost()`. The lenient policy asks the lookup providers from the
cheapest to the most expensive one, so a host that registers a provider knows
where it is asked. The method has no default: a provider that silently
inherited a price class would sit in the wrong position of the order without
anyone noticing.

The engine takes the identity of a provider from the provider itself, so a
finding cannot claim the identity of another provider. A host that wants its
provider to count as one vote with a built-in provider reports the source family
of that provider.

## Operator policy mapping

The library decides how likely an address is; the host application decides what
to do about it.

| Verdict | Suggested first step | Suggested second step |
|---|---|---|
| `Bad` | Block or challenge, according to the host's policy | Keep the evidence for the incident record |
| `Unknown` with reason `NoCoverage` | Treat as unclassified | Check that the providers are reachable and enabled |
| `Unknown` with reason `NoEvidence` | Treat as unclassified | Refresh the intelligence before the next decision |
| `Unknown` with reason `EvidenceExpired` | Treat as unclassified | The claim about the address is too old to act on |
| `Unknown` with reason `InsufficientEvidence` | Observe, rate limit or step up a challenge | Tighten the policy after measuring the false-positive rate |

The verdict carries the evidence it was derived from, including the upstream
values, so a host that needs a different granularity of trust can derive its own
policy from `verdict.evidence` without asking the library for a score. The
observations of a provider that withdrew its own claim are absent from the
verdict.

## The user-agent dimension

`assess_user_agent` reports whether the request looks like it came from a bot:

```rust
let bot = bots.assess_user_agent(Some(user_agent));
bot.is_bot;             // whether the client is a bot
bot.ua_state;           // the syntactic state of the header
bot.claimed_family;     // the family the user agent claims
```

The call performs no network I/O, spends no quota and touches no cache, so it
may be made on every request.

The two dimensions are independent: a user agent never changes the address
verdict, and the address verdict never changes the user-agent verdict. A user
agent that claims to be a well-known crawler is never treated as verified. The
library performs no ownership verification and no reverse-DNS lookup.

## Deployment

The library runs inside the process of the host, and everything it keeps lives
in that process:

| State | Where it lives | What bounds it |
|---|---|---|
| The quota guard | the process of the host | the quota of the provider |
| The lookup cache | the process of the host | `cache_capacity` and the TTLs of the host |
| The loaded lists | the process of the host | the refresh interval of the publisher |
| The refresh interval | the process of the host | the interval the publisher states |

Two processes therefore keep two quotas, two caches and two sets of lists. A
host that runs more than one process has to divide the quota of a provider
between its processes, or route the assessments of an address to one of them.

The worker thread of the library belongs to that process as well: it is started
by the first verification and stopped with the last handle of the library, so
the process is never held open by it.

### The budget of an upstream key

The budget of an upstream key belongs to every process that spends it. By
default every process counts its own budget, so a host that shares one key
between its processes spends the quota of that key once per process. A host
divides the budget of the key between its processes with the `daily_quota` and
the `monthly_quota` configuration key of the provider.

A host that wants to spend the budget of the key once implements `Quota` and
hands the budget to the builder with `BadBotsBuilder::quota`. The budget then
lives wherever the host keeps it, and the library asks it before every request
of the provider. The instant a method of the trait takes is a
`time::OffsetDateTime`, the type the library already exposes in
`IpVerdict::assessed_at`; the crate does not re-export `time`, so the host
depends on it the way it already does for those types.

```rust
use std::sync::Arc;

use badbots::{BadBots, Config, ProviderId, Quota};
use time::OffsetDateTime;

/// The budget of an upstream key, counted in a store the processes share.
struct SharedBudget {
    spent: std::sync::Mutex<u32>,
    limit: u32,
}

impl Quota for SharedBudget {
    fn try_consume(&self, now: OffsetDateTime) -> bool {
        let mut spent = self.spent.lock().unwrap();
        if *spent >= self.limit {
            return false;
        }
        *spent += 1;
        true
    }

    fn used(&self, now: OffsetDateTime) -> u32 {
        *self.spent.lock().unwrap()
    }

    fn bounded_limit(&self) -> Option<u32> {
        Some(self.limit)
    }
}

let bots = BadBots::builder()
    .config(Config::default())
    .quota(
        ProviderId::ABUSEIPDB,
        Arc::new(SharedBudget {
            spent: std::sync::Mutex::new(0),
            limit: 500,
        }),
    )
    .build()?;
```

The budget replaces the one the configuration describes: the `daily_quota` of
AbuseIPDB and of Blocklist.de, the `monthly_quota` of CrowdSec and the default
budget of the list providers are ignored for that provider. The budget of a
provider the host registers is the one the registration carries; the budget of
the builder does not reach it.

A budget that refuses a lookup ends in `ProviderError::QuotaExhausted`: the
provider is recorded in `coverage.failed` and the verdict is computed from the
evidence of the other providers. `try_consume` has to be atomic across every
caller that shares the budget, because the library asks the budget from its
worker thread and several processes of a host may share one budget.

## Expected coverage

The library reports the sources it consults, so its coverage is the union of the
coverage of the enabled providers.

No independent measurement of the coverage of this library exists. The figures
below are publisher statements about the sources themselves:

| Statement | Kind |
|---|---|
| AbuseIPDB reports the abuse confidence score of an address together with the number of distinct reporters and the categories they chose | Publisher statement (upstream API documentation) |
| CrowdSec CTI publishes a reputation, the observed behaviors and the classifications of an address | Publisher statement (upstream API documentation) |
| Spamhaus DROP publishes the networks that professional spam and cyber-crime operations lease or steal | Publisher statement (upstream documentation) |
| Blocklist.de publishes the attack events its partner's sensors observed, per address and per service | Publisher statement (upstream documentation) |
| DShield publishes the subnets and the addresses its sensors saw scanning or attacking | Publisher statement (upstream documentation) |
| The share of observed malicious traffic that carries a `Bad` verdict is in the single-digit percentage range | Expectation derived from the design of the sources. No independent measurement exists |

The coverage is short by design. The sources report addresses that a community
has already flagged, a conviction under the strict policy needs either one
strong claim or two independent claims, and the sources do not cover every
attack category. A host that needs more coverage adds a provider; a host that
needs a lower bar uses the lenient policy.

## Staged rollout

1. **Observe only.** Enable the providers, call `verify_ip` off the request
   path, and record the verdicts. Do not enforce anything. Measure how many
   addresses are classified `Bad` and how many carry the reason
   `InsufficientEvidence`.
2. **Sample the false positives.** Take the `Bad` addresses and check them
   against the host's own traffic. A provider that produces a high share of
   false positives is either misconfigured or not suited to the host's traffic.
3. **Enforce on `Bad` only.** Apply the host's policy to `Bad` addresses.
   Leave `Unknown` alone; it carries no conviction.
4. **Add corroboration.** Enable a second provider. Two independent source
   families are what turn a claim into a conviction, so a second provider
   raises precision at the cost of quota.
5. **Tighten.** Raise the enforcement from a challenge to a block once the
   measured false-positive rate is acceptable, and keep the evidence for the
   incident record.

## Configuration

`Config` is deserializable, so a host can load it from any format it prefers.
The crate reads no file and no environment variable on its own, with one
exception: the API keys may be supplied through `BADBOTS_ABUSEIPDB_API_KEY` and
`BADBOTS_CROWDSEC_API_KEY`, and a key set through the builder takes precedence.

```rust
let config: Config = serde_json::from_str(host_config)?;
let bots = BadBots::builder().config(config).build()?;
```

| Setting | Default |
|---|---|
| `request_timeout` | 5 s |
| `positive_ttl` | 30 days |
| `negative_ttl` | 24 h |
| `failure_ttl` | 5 min |
| `network_scope_policy` | `CorroborateOnly` |
| `evidence_policy` | `Strict` |
| `max_concurrent_verifications` | 4 |
| `cache_capacity` | 10,000 |

The host bounds how long a cached result is reused. An answer that carries
evidence is reused for at most `positive_ttl`, an answer that carries no
evidence for at most `negative_ttl`, and a failed lookup is remembered for
`failure_ttl`. A provider that declares an expiry of its own is asked again at
the earlier of that expiry and the bound, so a bound can only shorten the
reuse of a result, never extend it.

`max_concurrent_verifications` bounds how many verifications run at the same
time on the worker. The bound keeps a burst of assessments from spending the
quota of a provider faster than the quota allows.

## Re-scoring stored evidence

The verdict is a pure function of the evidence set, the suppressions, the
coverage record, the configuration and the assessment instant. A host that
stores evidence can re-score it without any network access:

```rust
use badbots::{classify, Config, VerdictInput};

let verdict = classify(&stored_input, &config, now);
```

## License

MIT. See [LICENSE](LICENSE).
