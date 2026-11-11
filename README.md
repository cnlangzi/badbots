# badbots

`badbots` is a Rust library that assesses how likely an inbound request's source
IP address is to be hostile. Its users are web applications, reverse proxies,
WAFs and CDNs that need a decision plus the evidence behind it, and that then
apply their own enforcement policy.

The library is **precision-first**: an address is flagged only when a source
makes a specific, current, verifiable claim that it committed an attack. A false
positive is far more costly than a false negative, so the design accepts short
coverage rather than noisy verdicts.

The library never blocks, bans or otherwise enforces a policy, and it never
performs network I/O on the assessment path.

## Quickstart

```toml
[dependencies]
badbots = { version = "0.1", features = ["full"] }
```

```rust
use badbots::{BadBots, Config};

let bots = BadBots::builder()
    .config(Config::default())
    .enable_abuseipdb()
    .abuseipdb_api_key(std::env::var("BADBOTS_ABUSEIPDB_API_KEY").unwrap())
    .build()?;

// The request path: no network I/O, answered from local state.
let verdict = bots.assess_ip(client_ip);

// The refresh path: explicit, asynchronous, costs upstream quota.
let report = bots.enrich_ip(client_ip).await;

match verdict.classification {
    badbots::Classification::Bad => { /* the host decides what to do */ }
    badbots::Classification::Suspect => { /* observe, or apply a soft policy */ }
    badbots::Classification::Unknown => { /* no intelligence was available */ }
}
```

`assess_ip` and `assess_request` are synchronous and answer from the local cache.
`enrich_ip` and `refresh_feeds` are asynchronous and perform the upstream
requests. The library creates no thread, no background task and no runtime of
its own.

## The three verdicts

| Verdict | Meaning |
|---|---|
| `Bad` | A conviction rule was satisfied: either one `Convicting` observation about this exact address, or two observations from different source families that corroborate each other. |
| `Suspect` | Valid evidence exists but no conviction rule was satisfied. |
| `Unknown` | No usable evidence exists. The reason distinguishes the cases. |

There is no "clean" verdict and no numeric score. Absence of intelligence is
reported as `Unknown`, never as a clean bill of health.

| Reason | Meaning |
|---|---|
| `Convicted` | The verdict is `Bad`. |
| `EvidencePresent` | The verdict is `Suspect`. |
| `EvidenceExpired` | Evidence existed but had expired. |
| `NoEvidence` | Providers were consulted and reported nothing. |
| `NoCoverage` | Nothing was consulted successfully. |

Prefix-scoped observations never convict on their own: a network listing is a
statement about a range, and whole-range listings have produced real collateral
damage for hosting customers. A prefix-scoped observation may add a vote to
another family's observation. `Config::network_scope_policy` can be set to
`NetworkScopePolicy::Allow` to let prefix-scoped observations satisfy the
single-source path as well.

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

| Provider | Feature | Capability | Quota guard | Convicts alone |
|---|---|---|---|---|
| [AbuseIPDB](docs/providers/abuseipdb.md) | `abuseipdb` | Primary | 1,000 per day | Yes, with score ≥ 75, ≥ 2 distinct reporters, a report within 30 days and an inbound-attack category |
| [CrowdSec CTI](docs/providers/crowdsec.md) | `crowdsec` | Primary | 120 per month | Yes, with a malicious reputation and a malicious behavior, or a blocklist classification or reference |
| [Spamhaus DROP](docs/providers/spamhaus.md) | `spamhaus` | Corroborating | 10,000 per day | No, a listing is a statement about a range |
| [Blocklist.de](docs/providers/blocklist-de.md) | `blocklist_de` | Corroborating | 10,000 per day | No, only the attack count of the per-address query adds a vote |
| [DShield](docs/providers/dshield.md) | `dshield` | Corroborating | 10,000 per day | No, only an attack record adds a vote |

Every provider is opt-in twice over: the Cargo feature has to be compiled in
**and** the configuration has to enable the provider. A provider that is
enabled in the configuration but whose feature is absent is reported as
`ConfigError::MissingFeature` when the library is built.

The `full` feature enables every provider the crate ships.

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

A list never convicts an address on its own. Two observations of the same
source family count as one vote, so a list and a mirror of it never make a
verdict stronger.

The publisher of a list may ask for its credit and its terms to be
reproduced. The loaded list keeps them verbatim:

```rust
let attribution = bots.feed_attribution(&badbots::ProviderId::SPAMHAUS);
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

A registered provider is consulted like every other provider: its answers are
cached under its own provider id, its observations corroborate according to its
own source family, and it appears in `provider_status()` with the quota it
spends. The identifier of a registered provider has to be unique, because the
cache is keyed by it: a build with two providers of the same id fails with
`ConfigError::Invalid`.

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
| `Suspect` | Observe, rate limit or step up a challenge | Tighten the policy after measuring the false-positive rate |
| `Unknown` with reason `NoCoverage` | Treat as unclassified | Check that the providers are reachable and enabled |
| `Unknown` with reason `NoEvidence` | Treat as unclassified | Refresh the intelligence before the next decision |
| `Unknown` with reason `EvidenceExpired` | Treat as unclassified | The claim about the address is too old to act on |

The verdict carries the evidence it was derived from, including the upstream
values, so a host that needs a different granularity of trust can derive its own
policy from `verdict.evidence` without asking the library for a score. The
observations of a provider that withdrew its own claim are absent from the
verdict.

## The user-agent dimension

`assess_request` also reports whether the request looks like it came from a bot:

```rust
let request = bots.assess_request(client_ip, Some(user_agent));
request.ip;    // the address verdict
request.bot;   // is_bot, the syntactic state, the claimed family
```

The two dimensions are independent: a user agent never changes the address
verdict, and the address verdict never changes the user-agent verdict. A user
agent that claims to be a well-known crawler is never treated as verified. The
library performs no ownership verification and no reverse-DNS lookup.

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
has already flagged, a conviction needs either one strong claim or two
independent claims, and the sources do not cover every attack category. A host
that needs more coverage adds a provider rather than loosening the rules.

## Staged rollout

1. **Observe only.** Enable the providers, call `enrich_ip` off the request
   path, and record the verdicts. Do not enforce anything. Measure how many
   addresses are classified `Bad` and how many are `Suspect`.
2. **Sample the false positives.** Take the `Bad` addresses and check them
   against the host's own traffic. A provider that produces a high share of
   false positives is either misconfigured or not suited to the host's traffic.
3. **Enforce on `Bad` only.** Apply the host's policy to `Bad` addresses.
   Leave `Suspect` and `Unknown` alone; they carry no conviction.
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
| `max_concurrent_enrichments` | 4 |
| `cache_capacity` | 10,000 |

The host bounds how long a cached result is reused. An answer that carries
evidence is reused for at most `positive_ttl`, an answer that carries no
evidence for at most `negative_ttl`, and a failed lookup is remembered for
`failure_ttl`. A provider that declares an expiry of its own is asked again at
the earlier of that expiry and the bound, so a bound can only shorten the
reuse of a result, never extend it.

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
