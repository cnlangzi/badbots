# AbuseIPDB

The AbuseIPDB check provider answers for one address at a time whether the
upstream has reports about it and how strongly the community reports it.

## Setup

1. Create an account at `abuseipdb.com` and request an API key.
2. Enable the crate feature:

   ```sh
   cargo add badbots --features abuseipdb
   ```

3. Enable the provider and supply the key:

   ```rust
   let bots = BadBots::builder()
       .enable_abuseipdb()
       .abuseipdb_api_key(key)
       .build()?;
   ```

   The key may also be supplied through `BADBOTS_ABUSEIPDB_API_KEY`. A key set
   through the builder takes precedence over the environment.

The key is sent in the `Key` request header and never in the query string,
because upstream logs query strings. The key never appears in the `Debug`
output of the configuration.

The request is:

```text
GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={n}&verbose=true
```

`verbose=true` asks for the per-report categories. `maxAgeInDays` defaults to 30
and is configurable through `AbuseIpdbConfig::max_age_days`.

## Quota

| Statement | Kind |
|---|---|
| The check endpoint is documented with a daily request quota that starts at 1,000 requests per day | Publisher statement (upstream API documentation) |
| The local budget guard defaults to 1,000 lookups per day | Configuration default of this library |
| A lookup that would exceed the budget fails with `ProviderError::QuotaExhausted` and issues no upstream request | Behaviour of this library |

The quota is counted per calendar day in UTC. The budget is configurable
through `AbuseIpdbConfig::daily_quota`. A host on a larger plan raises the
value; a host on a smaller plan lowers it.

## Data scope

The upstream reports, per address:

| Field | Use |
|---|---|
| `abuseConfidenceScore` | Rule input, recorded as `abuse_confidence_score` |
| `numDistinctUsers` | Rule input, recorded as `num_distinct_users` |
| `totalReports` | Rule input, recorded as `total_reports` |
| `reports[].categories` | Rule input, recorded as `categories` |
| `lastReportedAt` | `observed_at`, the base of the expiry |
| `usageType`, `countryCode`, `isp`, `domain`, `isTor` | Recorded as upstream values |
| `isWhitelisted` | Suppression, not recorded as an upstream value |

The categories that belong to the inbound attack set, and therefore count as an
attack on this address:

| Category | Meaning |
|---|---|
| 1 | DNS Compromise |
| 2 | DNS Poisoning |
| 4 | DDoS Attack |
| 5 | FTP Brute-Force |
| 7 | Phishing |
| 15 | Hacking |
| 16 | SQL Injection |
| 18 | Brute-Force |
| 20 | Exploited Host |
| 21 | Web App Attack |
| 22 | SSH |
| 23 | IoT Targeted |

Category 14 (Port Scan) is recorded as reconnaissance and category 10, 11 and 12
(spam) as abuse; neither belongs to the inbound attack set. The remaining
upstream categories are not emitted as evidence, because the library has no
assertion for them. The upstream category identifiers are always preserved in
`upstream_values["categories"]`.

The provider publishes two bars, and they differ:

| Bar | Conditions | Strength |
|---|---|---|
| The conviction bar | A score of at least 75, at least 2 distinct reporters, a report within 30 days and a category of the inbound attack set | `Convicting` |
| The observation bar | A score of at least 25 with at least 2 distinct reporters, or a score of at least 75 with at least 1 distinct reporter | `Indicative` |

A report set that satisfies the conviction bar produces a `Convicting`
observation. A report set that satisfies the observation bar but not the
conviction bar produces an `Indicative` observation, and the category of that
observation is the category of the reports: a report set about scanning
produces the assertion `Reconnaissance`, a report set about spam produces the
assertion `Abuse`. The category of the reports therefore decides the assertion
of the observation, and the observation bar does not require a category of the
inbound attack set.

| Situation | Strict policy | Lenient policy |
|---|---|---|
| The conviction bar is satisfied | A `Bad` verdict | A `Bad` verdict |
| Only the observation bar is satisfied | A `Unknown` verdict with the reason `InsufficientEvidence` | A `Bad` verdict |
| Neither bar is satisfied | A `Unknown` verdict with the reason `NoEvidence` | A `Unknown` verdict with the reason `NoEvidence` |

The upstream publishes a whitelist flag for the addresses it considers
legitimate. The provider consumes the flag: it withdraws its own claim about the
address, publishes a `Safe` suppression and produces no evidence. The flag is
not recorded as an upstream value. A suppression speaks for the provider that
published it, so the whitelist withdraws the AbuseIPDB claim alone; an address
that another source family convicts is still convicted.

## Freshness

| Rule | Value |
|---|---|
| A positive result expires | The earlier of 30 days after `lastReportedAt` and `Config::positive_ttl`, 30 days by default |
| A negative result is reused for | `Config::negative_ttl`, 24 hours by default |
| A report older than 30 days | Never satisfies the conviction bar, and its observation expires with it |

The upstream reports a point in time rather than a period, so no observation
window is recorded. The library expires the answer at the earlier of the expiry
the upstream declares and the host bound, so a claim is never kept for longer
than `Config::positive_ttl`.

## Terms and attribution

The upstream publishes its own terms of service and API documentation. A host
that uses this provider is bound by those terms; this library does not
restate or reinterpret them. The upstream names itself in the fields it
returns, and this library preserves those fields in the upstream values of the
verdict so that an attribution requirement can be met from the evidence the
host already stores. A whitelisted address yields no observation, so the
upstream values of that address do not reach the verdict.

## Known false-positive profile

The upstream aggregates community reports, so an address that many users
reported for a single incident carries a high confidence score. The following
patterns are known to produce a conviction that a host may disagree with:

- Hosting and VPN ranges that receive abuse reports from a shared customer
  base. The upstream reports `usageType`, `isp` and `domain` in the upstream
  values of the verdict, which is where a host recognizes such a range.
- Tor exit nodes. The upstream reports `isTor` in the upstream values.
- Scanner services that are reported because they scan. A port scan carries no
  category of the inbound attack set, so it never convicts on its own. It does
  produce an `Indicative` observation, which the strict policy does not convict
  on and the lenient policy does.
- Addresses the upstream whitelists. The provider withdraws its own claim about
  them and produces no evidence; the verdict carries the suppression.

A conviction needs a score of at least 75, at least two distinct reporters, a
report within 30 days and a category of the inbound attack set. A host that
sees false positives in a specific range can exclude that range from its own
policy: the verdict carries the upstream values that make the exclusion
decidable.
