# CrowdSec CTI

The CrowdSec CTI provider answers for one address at a time with a reputation,
the behaviors the upstream observed and the classifications it assigned.

## Setup

1. Create an account at `console.crowdsec.net` and request a CTI API key.
2. Enable the crate feature:

   ```toml
   [dependencies]
   badbots = { version = "0.1", features = ["crowdsec"] }
   ```

3. Enable the provider and supply the key:

   ```rust
   let bots = BadBots::builder()
       .enable_crowdsec()
       .crowdsec_api_key(key)
       .build()?;
   ```

   The key may also be supplied through `BADBOTS_CROWDSEC_API_KEY`. A key set
   through the builder takes precedence over the environment.

The request is:

```text
GET https://cti.api.crowdsec.net/v2/smoke/{ip}
```

The key is sent in the `x-api-key` request header. The key never appears in the
`Debug` output of the configuration.

## Quota

| Statement | Kind |
|---|---|
| The free key allows 120 lookups per month, the premium free key 1,500 | Publisher statement (upstream API documentation) |
| The local budget guard defaults to 120 lookups per month | Configuration default of this library |
| A lookup that would exceed the budget fails with `ProviderError::QuotaExhausted` and issues no upstream request | Behaviour of this library |

The quota is counted per calendar month in UTC. The budget is configurable
through `CrowdSecConfig::monthly_quota`. A host on the premium free key raises
the value to 1,500.

The monthly budget is small. A host that assesses many addresses should keep
the negative-result cache warm rather than widen the budget: a negative result
is reused for `Config::negative_ttl`, 24 hours by default.

## Data scope

The upstream reports, per address:

| Field | Use |
|---|---|
| `reputation` | Rule input, recorded as `reputation` |
| `behaviors[].name` | Rule input, recorded as `behaviors` |
| `classifications.false_positives` | Suppression |
| `classifications.classifications` | Rule input, recorded as `classifications` |
| `references` | Rule input, recorded as `references` |
| `background_noise`, `background_noise_score` | Rule input, recorded as upstream values |
| `history.last_seen` | `observed_at`, the base of the expiry |
| `history.first_seen` | Recorded as `first_seen` |
| `scores` | Recorded as `scores`, never used for the verdict |

The reputation values `malicious` and `suspicious` are rule inputs. The values
`benign` and `safe` are suppression states and produce no evidence.

The behavior names are mapped to an intent with a table that is compiled into
the crate. `http:exploit`, `bruteforce`, `flood`, `dos`, `proxy`, `sqli`,
`idor`, `rce`, `spoof` and `lateral` are malicious; `scan` is reconnaissance;
`spam` is abuse; `crawl` is scraping. The upstream taxonomy file is not
bundled, and a host that tracks a taxonomy change overrides the affected names
through `CrowdSecConfig::behavior_intents`.

The classification `community-blocklist` and the reference
`list:crowdsec_intelligence_blocklist` are conviction triggers on their own.

## Freshness

| Rule | Value |
|---|---|
| A positive result expires | The earlier of 90 days after `history.last_seen` and `Config::positive_ttl`, 30 days by default |
| A negative result is reused for | `Config::negative_ttl`, 24 hours by default |

The upstream states that an address without a report for three months is
unknown, which is the expiry the upstream declares. The library expires the
answer at the earlier of that expiry and the host bound, so a claim is never
kept for longer than `Config::positive_ttl`. The upstream `first_seen` field is
affected by progressive data degradation and is not used for the expiry.

## Terms and attribution

The upstream publishes its own terms of service and API documentation. A host
that uses this provider is bound by those terms; this library does not restate
or reinterpret them. The upstream names itself in the fields it returns, and
this library preserves those fields in the upstream values of the verdict so
that an attribution requirement can be met from the evidence the host already
stores. A suppressed address yields no observation, so the upstream values of
that address do not reach the verdict.

## Known false-positive profile

The upstream publishes a false-positive profile of its own, and this library
uses it:

| Pattern | Effect |
|---|---|
| A non-empty `classifications.false_positives` list | A `Safe` suppression |
| The reputation `benign` | A `Benign` suppression |
| The reputation `safe` | A `Safe` suppression |

A suppression speaks for the provider that published it and constrains the
evidence of that provider alone. A `Safe` suppression voids the evidence of the
publishing provider: it no longer convicts on its own and no longer adds a
corroboration vote. A `Benign` suppression keeps the evidence of the publishing
provider, which may still corroborate but no longer convicts on its own.
Neither of them constrains the evidence of another provider, so an address that
one provider suppresses may still be convicted by another.

A second pattern produces false positives without a suppression: a background
noise level of `high` means that the upstream sees many addresses of that range
behaving the same way. Such an address never convicts on its own; it produces a
`Suspect` verdict instead.

The upstream publishes the labels of the false-positive profile it assigned, and
the provider records them in the upstream values of its observation. The `Safe`
suppression it publishes alongside voids that observation, so the labels reach
neither the evidence nor the upstream values of the verdict. The verdict carries
the suppression itself.
