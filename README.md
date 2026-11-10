# URL Enrichment Prototype

Ingests a messy list of URLs, works out the **smallest set of lookups** needed for three
enrichment services (domain registration, TLS certificate, URL reputation), and keeps a
complete trail from every lookup result back to every original input line.

No real WHOIS, TLS or reputation services are called. Deterministic mock providers sit
behind a small interface, so real clients can be dropped in later.

![Visual plan](docs/visual_plan.svg)

---

## Quick start

```bash
pip install -r requirements.txt
python -m pytest                                   # 70 tests

# Full walk-through: two runs of the sample file, saved into examples/
python -m urlenrich demo data/raw_urls.txt --out examples

# Or step by step against a SQLite file (default: enrichment.db)
python -m urlenrich ingest data/raw_urls.txt      # normalize + derive targets (run 1)
python -m urlenrich plan                          # what would be called, and why
python -m urlenrich enrich --rate 20 --max 1000   # call providers (rate limit + budget)
python -m urlenrich report                        # results per original input line
python -m urlenrich trace registration paypal-update.com   # one target -> all inputs
python -m urlenrich export --out results.json     # same as report, as JSON
python -m urlenrich ingest data/raw_urls.txt      # run 2: everything is reused
```

## Results on the sample file

84 lines → 73 accepted, 9 rejected, 2 skipped → **45 distinct URLs**.

| Lookup type   | Naive (1 call per accepted line) | After grouping | Calls on a re-run |
|---------------|---------------------------------:|---------------:|------------------:|
| Registration  | 67                               | **12**         | 0                 |
| TLS           | 72                               | **27**         | 0                 |
| Reputation    | 73                               | **45**         | 0                 |
| **Total**     | **212**                          | **84**         | **0**             |

The naive counts differ because not every URL needs every lookup: IP addresses have no
domain registration, and `ftp://` has no TLS lookup.

Example output is in [`examples/`](examples):

| File | Shows |
|---|---|
| `01_ingest_run1.txt` | ingest stats and rejection reasons |
| `02_plan_run1.txt` | every planned lookup and the input lines behind it |
| `03_enrich_run1.txt` | calls made per provider and status |
| `04_report_run1.txt` | every input line with its normalized URL, three targets and results |
| `05_trace_examples.txt` | from one target back to all its input lines |
| `06_rerun.txt` | the same file ingested again: 0 lookups |
| `report_run1.json` | machine-readable version of the report |

---

## Data model

SQLite, six tables. Deduplication happens at two levels (URL, then target), and links are
kept at every level, so nothing is lost when variants collapse.

```
runs ──< raw_inputs >── normalized_urls ──< url_targets >── lookup_targets ──1:1── lookup_results
          (every line,      (one per             (link +           (one per            (one per target,
           every run)        canonical URL)       derivation)        type + key)          reused forever)
```

| Table | One row per | Key columns | Purpose |
|---|---|---|---|
| `runs` | ingestion | `source`, `started_at`, `stats` | when and what was ingested |
| `raw_inputs` | input line per run | `raw_text` (verbatim), `status`, `reason`, `flags`, `normalized_url_id` | provenance: nothing is dropped silently; `flags` record every normalization step applied |
| `normalized_urls` | canonical URL | `url` UNIQUE, `host`, `port`, `host_type`, `registrable_domain`, `site`, `skipped_lookups` | dedup level 1, and why a lookup type doesn't apply |
| `lookup_targets` | (type, key) | UNIQUE(`lookup_type`, `target_key`), `attrs` | dedup level 2: what is actually sent to a provider |
| `url_targets` | URL ↔ target link | `derivation` (e.g. `explicit_https`, `inferred_from_http`) | traceability, many-to-many |
| `lookup_results` | target | `status` (`ok` / `not_found` / `error`), `payload`, `attempts`, `run_id` | the cache that makes repeated runs cheap |

Design choices:

- **Results attach to targets, never to input lines.** One registration result for
  `example.com` serves all 38 input lines under it. The link is a join, not a copy.
- **Two dedup layers.** URL-level dedup and target-level dedup are separate questions.
  Collapsing straight from raw line to target would lose the canonical URL, and the canonical
  URL is itself the reputation key.
- **The database enforces uniqueness** (`UNIQUE` + `ON CONFLICT`), not an in-memory set.
  Dedup therefore holds across runs and processes.
- **The plan is a query**, not a queue table: a target is pending when it has no result or
  only an `error` result. There is no separate queue that can drift out of sync.
- **SQLite, not JSON files or an in-memory dict.** It gives constraints, joins for tracing,
  and transactions (a run is all or nothing) with no server. The schema moves directly to
  Postgres.

---

## How lookup targets differ

Each service answers a different question, so each needs a different key from the same URL.
Example: `HTTPS://Login.PayPal-Update.com:443/verify?user=alice&session=123#top`

| Lookup | Question | Target key | Example | Shared by |
|---|---|---|---|---|
| **Registration** (WHOIS/RDAP) | Who owns the domain? | registrable domain (eTLD+1, ICANN suffixes) | `paypal-update.com` | every subdomain, scheme, port, path |
| **TLS certificate** | What cert does this endpoint serve? | `host:port` | `login.paypal-update.com:443` | every path / query / scheme on that endpoint |
| **Reputation** | Is this exact URL bad? | full normalized URL | `https://login.paypal-update.com/verify?session=123&user=alice` | only true variants of the same URL |

Specific rules:

| Case | Registration | TLS | Reputation |
|---|---|---|---|
| `https://host:8443/…` | eTLD+1 | `host:8443` (as given) | URL |
| `http://host/…` or `http://host:8080/…` | eTLD+1 | `host:443`, **inferred** | URL |
| `ftp://host/…` | eTLD+1 | n/a (`scheme_ftp_not_tls`) | URL |
| IP literal (`45.33.32.156`, `[2001:db8::1]`) | n/a (`ipv4_literal_has_no_domain`) | `ip:443` (no SNI) | URL |
| `alice.github.io`, `storage.googleapis.com` | `github.io`, `googleapis.com` | full host | URL |
| `shop.example.co.uk` | `example.co.uk` (multi-label suffix) | full host | URL |
| unknown suffix (`münchen.example`) | last two labels, flagged `psl_default_rule` | full host | URL |

Why **TLS for `http://` URLs uses port 443**: a certificate lookup connects to an endpoint
and reads its certificate. It doesn't follow the URL or its redirects. An `http://` URL only
proves the host listens on plain HTTP; asking `host:443` answers "does this host also serve
TLS, and with which cert?". It is labelled `inferred_from_http`, and it usually shares a
target with the host's `https://` URLs, so it rarely costs an extra call. A `not_found`
("no TLS listener") is itself a result.

Why **ICANN-only suffixes for registration**: the Public Suffix List also contains "private"
suffixes like `github.io`, where each user gets a subdomain. WHOIS has no record for
`alice.github.io`; the registered domain is `github.io`. The private-suffix view is still
kept as `normalized_urls.site` (`alice.github.io`), because for attribution it is a different
owner.

---

## Normalization and grouping decisions

Principle: **collapse only what is guaranteed to be the same resource**, and record every
step in `raw_inputs.flags`. A missed dedup costs one extra lookup; a wrong merge returns
another URL's result as if it were this one's.

| Rule | Example from the file | Why |
|---|---|---|
| Strip CRLF, surrounding whitespace, `"…"` and `<…>` | `"https://www.example.com/"` | copy/paste and CSV artifacts; the sample file uses CRLF line endings |
| Skip blank lines and `#` comments | line 61, line 78 | not URLs; stored as `skipped` |
| Refang `hxxp(s)`, `[.]`, `[:]` | `hxxps://login[.]paypal-update[.]com/…` | threat-intel notation for the same URL |
| Lowercase scheme and host | `HTTPS://WWW.EXAMPLE.COM/` | case-insensitive by spec |
| Remove the host's trailing dot | `https://example.com.` | same fully-qualified name |
| Unicode host → punycode (IDNA 2008) | `münchen.example` = `xn--mnchen-3ya.example` | one host, two spellings |
| Integer IP → dotted | `http://3221225994/` = `192.0.2.10` | browsers resolve it the same way |
| IPv6 compressed | `[2001:DB8:0::1]` → `[2001:db8::1]` | one address, many spellings |
| Remove default port | `:443` on https, `:80` on http | identical request |
| Keep non-default port | `cdn.example.com:8443` | different endpoint, possibly a different cert |
| Remove credentials | `https://user:secret@example.com/login` | not part of the resource; must not be sent to third parties |
| Remove fragment | `#top`, `#login` | never sent to the server |
| Empty path → `/` | `https://chase-verify.net` | same request |
| Resolve `.` and `..` | `/a/../about` → `/about` | RFC 3986 |
| Decode unreserved escapes, uppercase the rest | `%7E` → `~`, `%2f` → `%2F` | equivalent encodings |
| **Keep** `%2F` encoded | `path%2Fencoded` ≠ `path/encoded` | a different path to the server |
| Encode unsafe characters | `/<script>` → `/%3Cscript%3E` | what a browser sends |
| **Keep** path case | `DocA.html` ≠ `doca.html` | paths are case-sensitive (and are on Google Cloud Storage) |
| **Keep** trailing slash | `/about` ≠ `/about/` | can be different resources |
| Drop empty query and empty pairs | `search?` → `search` | same request |
| Drop known tracking params | `utm_*`, `fbclid`, `gclid`, … | analytics only; otherwise every campaign link is a new lookup |
| Sort query params by key (stable) | `b=2&a=1` = `a=1&b=2` | order rarely matters; repeated keys keep their relative order |
| Keep blank values | `?id=` | may be meaningful |
| Missing scheme → `http://` (flagged) | `www.example.com`, `//www.example.com/` | browser address-bar default; flagged as `scheme_inferred` |

**Grouping** then happens per lookup type, as described above:
URL → `host:port` → eTLD+1. `www.example.com` and `example.com` are different URLs and
different TLS endpoints, but one registration.

**Rejected** lines (stored with a reason, never looked up):

| Reason | Lines |
|---|---|
| `unsupported_scheme` | `mailto:` ×2, `javascript:`, `data:` |
| `missing_host` | `http://` |
| `invalid_host` | `https://exa mple.com/broken`, `not a url at all` |
| `single_label_host` | `not-a-valid-url-at-all`, `example` (no TLD) |

---

## Repeated runs and reuse

- Each `ingest` creates a new `runs` row and logs every line in `raw_inputs`. This is the
  history of what was seen, and when.
- URLs and targets are upserted. A URL or target seen in an earlier run is linked, not
  recreated (`known_normalized_urls` in the stats).
- `enrich` only calls providers for targets **with no result, or only an `error` result**.
  - `ok` and `not_found` are answers, so they are never fetched again.
  - `error` (timeout, provider failure) is retried on the next run, and `attempts` is
    incremented.
  - A new run only calls for genuinely new targets. For example, a new subdomain of a known
    domain triggers a TLS and a reputation lookup, but no registration lookup.
- Reports for any run show results that came from earlier runs, tagged
  `[reused from run N]`.
- Rate limits: each provider gets a `RateLimiter` (calls per second), and `--max` caps calls
  per type per run. Whatever is left stays pending for the next run. Lookups are committed
  every 100 calls, so a crash loses little.

---

## Libraries used, and why

| Library | Used for | Why not the standard library |
|---|---|---|
| `tldextract` | Public Suffix List → registrable domain | Can't be computed from the hostname alone (`co.uk`, `github.io`). Used with its **bundled** list snapshot (`suffix_list_urls=()`) so runs are offline and reproducible. |
| `idna` | Unicode hostnames → punycode | Python's built-in `idna` codec implements IDNA 2003. This library implements IDNA 2008 + UTS-46, which browsers use. |
| `pytest` | tests | — |
| `sqlite3`, `ipaddress`, `urllib.parse` (stdlib) | storage, IP parsing, encoding | — |

URL normalization is hand-written rather than taken from a library such as `url-normalize`.
The decisions are the point of the exercise, so each one is explicit, flagged and tested.

---

## Assumptions

- Input is one URL per line in UTF-8; blank lines and `#` lines are not URLs.
- Lookup results never expire (per the problem scope).
- Supported schemes are `http`, `https` and `ftp`; other schemes are rejected.
- Scheme-less input means `http://`.
- Query parameter order doesn't change the resource.
- The tracking-parameter list is a fixed, conservative allowlist.
- One TLS lookup per `host:port`; the TLS provider sends SNI using the host (no SNI for IPs).
- `not_found` is a final answer; only `error` is retried.
- **Reserved TLDs are treated as real sites.** The exercise data uses reserved names
  (`.test`, `.example`) in place of real domains, so the whole pipeline processes them
  normally, and the mock registration provider returns a normal result for them.
  *In a real scenario:* these TLDs have no registry (RFC 2606 / RFC 6761), so a real
  WHOIS/RDAP lookup would return "not found" for every one of them. A production version
  should not send them at all: it would record registration as not applicable
  (`reserved_tld`), the same way IP addresses are skipped today, and save the
  rate-limited calls. TLS and reputation lookups would be attempted as usual, and would
  most likely fail to connect or return no data.

## Known limitations

- **No expiry or history.** `lookup_results` keeps the latest result per target. A real
  system needs a TTL per type (for example days for registration, a certificate's
  `not_after` for TLS, and hours for reputation) and a history table.
- **`raw_inputs` grows by every line on every run.** At large scale, store a line hash plus
  a seen-count per run, or archive old runs.
- **Single process, sequential calls.** For volume: Postgres, a work queue keyed on
  `lookup_targets.id`, and parallel workers sharing a rate limiter.
- **The bundled suffix list can go stale.** Newer TLDs fall back to the default rule (and
  are flagged).
- Only decimal integer IPs are converted; hex/octal forms (`0xC0000201`) are rejected.
- Shortened URLs (`bit.example/3xYz9`) and redirects are not followed.
- Domains inside rejected `mailto:` links are not used for registration lookups, although
  they could be.
- IP literals get no ownership lookup; IP WHOIS/ASN would be a fourth lookup type.
- `http://` hosts are checked for TLS on 443 only, not on other TLS ports.
- `raw_inputs.raw_text` stores the line verbatim, including any credentials it contained
  (line 48). A production system should redact them at ingest.
- Conservative normalization (path case, trailing slash) can leave some duplicate
  reputation lookups. This is the deliberate trade-off.
- Mock providers return fake but deterministic data and ready to be swapped with real providers.

---

## Project layout

```
urlenrich/
  normalize.py   raw line -> canonical URL (or Skip / Reject with a reason)
  targets.py     canonical URL -> registration / TLS / reputation targets
  db.py          SQLite schema
  ingest.py      idempotent ingestion of a file as a run
  enrich.py      lookup plan (query) + runner (rate limit, budget, retries)
  providers.py   provider interface, rate limiter, mock providers
  report.py      plan / per-input report / trace views
  __main__.py    CLI
tests/           normalization, target derivation, pipeline (dedup, re-runs, retries, trace)
data/            raw_urls.txt
examples/        generated example output
docs/            visual plan
```
