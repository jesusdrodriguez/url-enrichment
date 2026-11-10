# URL Enrichment Prototype

The following URL-Enrichment prototype ingests a messy list of URLs, processes it, and finds the smallest set of lookups needed for the three enrichment services (domain registration, TLS certificate and URL reputation) while keeping a complete trail from every lookup result back to every original input line. This can later be used for logs and aiding investigations.

No real WHOIS, TLS or reputation services are called. Deterministic mock providers sit
behind a small interface, so real clients can be dropped in later with little to change.

Below is a visual plan for development of the prototype:

![Visual plan](docs/visual_plan.svg)

---

## Quick start

```bash
pip install -r requirements.txt
python -m pytest                                   # 81 tests
```

Expected test output:

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\...\GitHub\url-enrichment
configfile: pytest.ini
testpaths: tests
collected 81 items

tests\test_normalize.py ................................................ [ 59%]
.........                                                                [ 70%]
tests\test_pipeline.py .................                                 [ 91%]
tests\test_targets.py .......                                            [100%]

============================= 81 passed in 0.86s ==============================
```

Running the prototype:

```bash
# Full walk-through: two runs of the exercise file, saved into examples/
python -m urlenrich demo data/exercise_urls.txt --out examples

# Or step by step against a SQLite file (default: enrichment.db)
python -m urlenrich ingest data/exercise_urls.txt      # normalize + derive targets (run 1)
python -m urlenrich plan                          # what would be called, and why
python -m urlenrich enrich --rate 20 --max 1000   # call providers (rate limit + budget)
python -m urlenrich report                        # results per original input line
python -m urlenrich trace registration company-001.test   # one target -> all inputs
python -m urlenrich export --out results.json     # same as report, as JSON
python -m urlenrich ingest data/exercise_urls.txt      # run 2: everything is reused
```

## Results on the exercise file

1,000 lines → 987 accepted, 12 rejected, 1 skipped (the blank last line) → **897 distinct URLs**.

| Lookup type   | Naive (1 call per accepted line) | After grouping | Calls on a re-run |
|---------------|---------------------------------:|---------------:|------------------:|
| Registration  | 914                              | **270**        | 0                 |
| TLS           | 986                              | **743**        | 0                 |
| Reputation    | 987                              | **897**        | 0                 |
| **Total**     | **2,887**                        | **1,910**      | **0**             |

The naive counts differ because not every URL needs every lookup: the 73 IP-address lines
have no domain registration, and the one `ftp://` line has no TLS lookup. The biggest
saving is registration (914 → 270), the most rate-limited of the three services.

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

SQLite, six tables. Deduplication happens twice (first to one URL, then to one lookup
target), and every level keeps a link back, so nothing is lost when variants collapse.
The diagram shows the main columns; the full schema is in `urlenrich/db.py`.

```mermaid
erDiagram
    runs ||--o{ raw_inputs : "logs every line"
    raw_inputs }|--o| normalized_urls : "normalizes to"
    normalized_urls ||--|{ url_targets : "needs"
    lookup_targets ||--|{ url_targets : "shared by"
    lookup_targets ||--o| lookup_results : "answered by"

    runs {
        int id PK
        text source
        text started_at
        json stats
    }
    raw_inputs {
        int id PK
        int run_id FK
        int line_no
        text raw_text "as read, password masked"
        text status "accepted, rejected, skipped"
        text reason "why rejected or skipped"
        json flags "normalization steps applied"
        int normalized_url_id FK "empty unless accepted"
    }
    normalized_urls {
        int id PK
        text url UK "canonical form"
        text host
        int port
        text host_type "domain, ipv4, ipv6"
        text registrable_domain
        json skipped_lookups "lookup type: reason"
    }
    url_targets {
        int normalized_url_id PK, FK
        int target_id PK, FK
        text derivation "e.g. explicit_https"
    }
    lookup_targets {
        int id PK
        text lookup_type UK "registration, tls, reputation"
        text target_key UK
        json attrs "host, port, sni"
    }
    lookup_results {
        int target_id PK, FK
        text status "ok, not_found, error"
        json payload
        int attempts
        int run_id FK "run that fetched it"
    }
```

### What each table holds, and how many rows

| Table | One row per | After 1 run of the exercise file | After a 2nd run of the same file |
|---|---|---:|---:|
| `runs` | ingestion | 1 | 2 |
| `raw_inputs` | input line, per run | 1,000 | 2,000 |
| `normalized_urls` | distinct canonical URL | 897 | 897 |
| `url_targets` | link from a URL to one of its targets | 2,617 | 2,617 |
| `lookup_targets` | distinct (lookup type, key) | 1,910 | 1,910 |
| `lookup_results` | target with an answer | 1,910 | 1,910 |

Only the log tables grow on a re-run. Everything that costs a lookup stays the same.

### Following three lines through the tables

Lines 1, 4 and 974 of the exercise file all belong to `company-001.test`:

```
line   1  https://www.company-001.test/products/item-1
line   4  HTTPS://WWW.company-001.test/products/item-1#details
line 974  ftp://archive.company-001.test/file.zip
```

**`raw_inputs`**: one row per line, kept as read (only a password in the URL is masked).

| id | line_no | status | flags | normalized_url_id |
|---|---|---|---|---|
| 1 | 1 | accepted | — | 1 |
| 4 | 4 | accepted | `host_lowercased`, `fragment_removed` | 1 |
| 974 | 974 | accepted | — | 881 |

**`normalized_urls`**: lines 1 and 4 collapse into one URL (first dedup).

| id | url | registrable_domain | skipped_lookups |
|---|---|---|---|
| 1 | `https://www.company-001.test/products/item-1` | `company-001.test` | — |
| 881 | `ftp://archive.company-001.test/file.zip` | `company-001.test` | tls: `scheme_ftp_not_tls` |

**`url_targets` → `lookup_targets`**: both URLs point to the same registration target
(second dedup).

| url id | target id | lookup_type | target_key | derivation |
|---|---|---|---|---|
| 1 | 1 | registration | `company-001.test` | `registrable_domain` |
| 1 | 2 | tls | `www.company-001.test:443` | `explicit_https` |
| 1 | 3 | reputation | `https://www.company-001.test/products/item-1` | `normalized_url` |
| 881 | 1 | registration | `company-001.test` | `registrable_domain` |
| 881 | 1891 | reputation | `ftp://archive.company-001.test/file.zip` | `normalized_url` |

**`lookup_results`**: one answer per target, stored once (mock data).

| target id | status | provider | fetched in run |
|---|---|---|---|
| 1 | ok | mock-rdap | 1 |
| 2 | not_found | mock-tls | 1 |
| 3 | ok | mock-reputation | 1 |
| 1891 | ok | mock-reputation | 1 |

Reading it backwards is the trace: result 1 → target 1 → URLs 1 and 881 → lines 1, 4
and 974. The other company-001 URLs link to target 1 the same way, which is why
`trace registration company-001.test` shows 9 input lines for a single lookup.

### Design choices

- **Results attach to targets, never to input lines.** One registration result for
  `company-001.test` serves all 9 input lines under it. The link is a join, not a copy.
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

## How lookup targets differ

Each service answers a different question, so each needs a different key from the same URL.
Example: `HTTPS://WWW.company-001.test/products/item-1#details`

| Lookup | Question | Target key | Example | Shared by |
|---|---|---|---|---|
| **Registration** (WHOIS/RDAP) | Who owns the domain? | registrable domain (eTLD+1, ICANN suffixes) | `company-001.test` | every subdomain, scheme, port, path |
| **TLS certificate** | What cert does this endpoint serve? | `host:port` | `www.company-001.test:443` | every path / query / scheme on that endpoint |
| **Reputation** | Is this exact URL bad? | full normalized URL | `https://www.company-001.test/products/item-1` | only true variants of the same URL |

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

Second principle: **reject a line only when no host can be found.** Anything after the
host (a bad port, broken percent-encoding, a backslash) is recorded as a flag, never a
reason to drop the URL. For a security service, a skipped scan is worse than an
imperfect one.

For example, https://example.com:99999/ cannot be dropped because PORT is invalid, without enriching the domain/dns using the underlying hostname. We can potentially still probe the host in a sandboxed headless browser or crawler using port 443 and 80 to verify if a live site exists. Recommended action: store it as for log search, and enrich domain/dns on hostname.

| Rule | Example | Why |
|---|---|---|
| Strip CRLF, surrounding whitespace, `"…"` and `<…>` | `"https://www.example.com/"` | copy/paste and CSV artifacts; input files may use CRLF line endings |
| Skip blank lines and `#` comments | line 1000 (blank) | not URLs; stored as `skipped` |
| Refang `hxxp(s)`, `[.]`, `[:]` | `hxxps://login[.]paypal-update[.]com/…` | threat-intel notation for the same URL |
| Lowercase scheme and host | `HTTPS://WWW.EXAMPLE.COM/` | case-insensitive by spec |
| Remove the host's trailing dot | `https://example.com.` | same fully-qualified name |
| Unicode host → punycode (IDNA 2008) | `münchen.example` = `xn--mnchen-3ya.example` | one host, two spellings |
| Integer IP → dotted | `http://3221225994/` = `192.0.2.10` | browsers resolve it the same way |
| IPv6 compressed | `[2001:DB8:0::1]` → `[2001:db8::1]` | one address, many spellings |
| Remove default port | `:443` on https, `:80` on http | identical request |
| Keep non-default port | `cdn.example.com:8443` | different endpoint, possibly a different cert |
| Remove credentials | `https://user:secret@example.com/login` | not part of the resource; must not be sent to third parties |
| Mask the password in the stored raw line (flagged) | `user:secret@` → `user:***@` in `raw_text` | RFC 3986 §3.2.1 and OWASP logging guidance: never store a password in clear text. The username is kept, because in phishing (`https://paypal.com@evil.example/`) it is evidence |
| Remove fragment | `#top`, `#login` | never sent to the server |
| Empty path → `/` | `https://chase-verify.net` | same request |
| Resolve `.` and `..` | `/a/../about` → `/about` | RFC 3986 |
| Decode unreserved escapes, uppercase the rest | `%7E` → `~`, `%2f` → `%2F` | equivalent encodings |
| **Keep** `%2F` encoded | `path%2Fencoded` ≠ `path/encoded` | a different path to the server |
| Encode unsafe characters | `/<script>` → `/%3Cscript%3E` | what a browser sends |
| Keep malformed escapes as written | `/%ZZ`, `?q=%` | what a browser sends; never a reason to reject |
| `\` → `/` before the query (flagged) | `https://host\path` | browsers treat it as a slash |
| Unusable port → scheme's default port (flagged) | `:invalid`, `:99999` | the host is still enriched |
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
| `unsupported_scheme` | `mailto:`, `javascript:`, `file:`, `data:` (975, 976, 986, 987) |
| `missing_host` | `https://`, `http://`, `https:///missing-host` (972, 973, 988) |
| `invalid_host` | `not a url`, `https://.test/path`, `https://company 007.test/path`, `https://[2001:db8::zz]/path` (971, 982, 983, 985) |
| `single_label_host` | `https://localhost/admin` (995) |

Lines 977, 978, 979, 984, 992 and 999 look broken but have a clear host, so they are
accepted instead (see the second principle above). 977, 978, 984 and 999 are flagged
(`userinfo_removed` + `password_redacted`, `invalid_port_ignored`, `backslash_converted`); 979 (`/%ZZ`) and
992 (`?q=%`) keep their malformed escapes exactly as written, with no flag.

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
- **Exercise data is treated as real sites.** The exercise uses reserved names and
  addresses in place of real ones, and the pipeline processes them like any other host:
  - reserved TLDs: `.test`, `.example`
  - documentation IP ranges: `192.0.2.0/24`, `2001:db8::/32`
  - private, loopback and link-local IPs: `10.x`, `127.0.0.1`, `169.254.x`, `[::1]`

  The mock providers return normal results for all of them.
  *In a real scenario:* reserved TLDs have no registry (RFC 2606 / RFC 6761), so a real
  WHOIS/RDAP lookup returns "not found". Private, loopback and link-local addresses
  can't be reached by external services, and sending them would expose internal
  addresses to a third party. A production version would still keep these lines and
  their trace, but would mark the affected lookups as not applicable (`reserved_tld`,
  `non_public_ip`) instead of sending them, the same way IP addresses already skip
  registration. That saves rate-limited calls for hosts that can actually be enriched.

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
  they could be, will need further research and expansion.
- IP literals get no ownership lookup; IP WHOIS/ASN would be a fourth lookup type.
- `http://` hosts are checked for TLS on 443 only, not on other TLS ports.
- **Sensitive data in query strings is sent to the reputation service.** In email, links
  often carry password-reset tokens, magic login links, session IDs or the recipient's
  own address (`?session=123&user=alice`). The reputation key is the full URL, so these
  reach a third party. Removing them would change which URL is judged, so it isn't done
  here; options are a reputation service that accepts URL hashes (as Google Safe
  Browsing does), or stripping known token parameters. Passwords in `user:pass@` are
  already masked in storage; if analysts need to match the same credential across
  emails, store a keyed hash (HMAC) of it rather than the value.
- Conservative normalization (path case, trailing slash) can leave some duplicate
  reputation lookups. This is the deliberate trade-off.
- Mock providers return fake but deterministic data and ready to be swapped with real providers.

---

## How AI was used

I used Claude to help write code, tests and documentation. The design
decisions were mine: what to reject versus flag-and-enrich, keeping the raw input,
the per-lookup-type target keys, and masking passwords while keeping usernames
(given the email-security context).

Where I changed the AI's approach: its first version rejected any URL with a
formatting problem. I changed that to **reject only when no host can be found**,
because a partial enrichment is better than none, and a skipped URL can hide
something important:

- **Bad ports** (`:invalid`, `:99999`) are flagged and replaced with the scheme's
  default port instead of rejecting the URL.
- **Backslashes** (`https://host\path`) are accepted and treated as `/`, because
  browsers still open these URLs. The AI originally rejected them as bad format.
- **Malformed `%` escapes** (`/%ZZ`, `?q=%`) are kept exactly as written instead of
  being rejected, since that is what a browser sends.

I treated AI output as a draft to be checked, not as the answer:

- Checked every requirement in the brief against the code and its real output,
  not against a summary.
- Ran the tests against the full 1,000-line exercise file, and regenerated
  `examples/` to compare them with the committed files.
- Tested a fresh clone of the repo before submitting.

Review caught real problems:

- a committed test still pointed to a smaller sample data file I had generated
  earlier with random URLs, which had since been deleted in favour of the
  provided exercise file;
- README examples no longer matched the data;
- a first version of password masking wrongly altered `mailto:` addresses
  (now covered by a test).

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
data/            exercise_urls.txt
examples/        generated example output
docs/            visual plan
```
