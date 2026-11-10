"""Plan and run lookups.

The plan is a query, not a separate queue table: a target needs a lookup when
it has no stored result, or only a failed one. Because results never expire
in this prototype, a successful lookup is never repeated, in this run or any
later run.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter

from .ingest import now
from .providers import LookupProvider, LookupResult, RateLimiter
from .targets import LOOKUP_TYPES

DONE_STATUSES = ("ok", "not_found")   # "not_found" is an answer; "error" is not

PENDING_SQL = """
SELECT t.id, t.lookup_type, t.target_key, t.attrs,
       r.status AS last_status, r.attempts AS attempts
FROM lookup_targets t
LEFT JOIN lookup_results r ON r.target_id = t.id
WHERE (r.target_id IS NULL OR r.status NOT IN ('ok','not_found'))
  AND (? IS NULL OR t.lookup_type = ?)
ORDER BY t.lookup_type, t.target_key
"""


def pending_targets(conn: sqlite3.Connection, lookup_type: str | None = None) -> list[sqlite3.Row]:
    return conn.execute(PENDING_SQL, (lookup_type, lookup_type)).fetchall()


def inputs_for_target(conn: sqlite3.Connection, target_id: int,
                      run_id: int | None = None) -> list[sqlite3.Row]:
    """Every raw input line that leads to this target (optionally one run)."""
    return conn.execute(
        """SELECT ri.run_id, ri.line_no, ri.raw_text, nu.url, ut.derivation
           FROM url_targets ut
           JOIN normalized_urls nu ON nu.id = ut.normalized_url_id
           JOIN raw_inputs ri      ON ri.normalized_url_id = nu.id
           WHERE ut.target_id = ? AND (? IS NULL OR ri.run_id = ?)
           ORDER BY ri.run_id, ri.line_no""",
        (target_id, run_id, run_id),
    ).fetchall()


def plan_summary(conn: sqlite3.Connection, run_id: int) -> dict:
    """For one run: naive request count vs. deduplicated targets vs. still pending.

    naive   = accepted input lines that need this lookup type (one call per line)
    unique  = distinct targets those lines map to
    pending = of those, how many have no usable result yet
    """
    out = {}
    for lt in LOOKUP_TYPES:
        naive, unique, pending = conn.execute(
            """SELECT COUNT(*),
                      COUNT(DISTINCT t.id),
                      COUNT(DISTINCT CASE WHEN r.target_id IS NULL OR r.status = 'error'
                                          THEN t.id END)
               FROM raw_inputs ri
               JOIN url_targets ut    ON ut.normalized_url_id = ri.normalized_url_id
               JOIN lookup_targets t  ON t.id = ut.target_id AND t.lookup_type = ?
               LEFT JOIN lookup_results r ON r.target_id = t.id
               WHERE ri.run_id = ? AND ri.status = 'accepted'""",
            (lt, run_id),
        ).fetchone()
        out[lt] = {"naive_requests": naive, "unique_targets": unique, "pending_lookups": pending,
                   "reused_results": unique - pending}
    return out


def _store(conn, target_id: int, provider: str, result: LookupResult, run_id: int) -> None:
    conn.execute(
        """INSERT INTO lookup_results
               (target_id, status, payload, error, provider, attempts, run_id, fetched_at)
           VALUES (?,?,?,?,?,1,?,?)
           ON CONFLICT(target_id) DO UPDATE SET
               status=excluded.status, payload=excluded.payload, error=excluded.error,
               provider=excluded.provider, attempts=lookup_results.attempts + 1,
               run_id=excluded.run_id, fetched_at=excluded.fetched_at""",
        (target_id, result.status, json.dumps(result.payload, sort_keys=True), result.error,
         provider, run_id, now()),
    )


def run_lookups(conn: sqlite3.Connection, providers: dict[str, LookupProvider], run_id: int,
                limiters: dict[str, RateLimiter] | None = None,
                max_per_type: int | None = None, batch_commit: int = 100) -> dict:
    """Call each provider once per pending target. Returns counts per type/status."""
    limiters = limiters or {}
    counts: Counter = Counter()
    for lt in LOOKUP_TYPES:
        provider = providers.get(lt)
        if provider is None:
            continue
        rows = pending_targets(conn, lt)
        if max_per_type is not None:
            rows = rows[:max_per_type]    # budget; the rest stay pending for next run
        for i, row in enumerate(rows, start=1):
            if lt in limiters:
                limiters[lt].acquire()
            try:
                result = provider.lookup(row["target_key"], json.loads(row["attrs"]))
            except Exception as exc:      # provider failure -> retried next run
                result = LookupResult("error", error=f"{type(exc).__name__}: {exc}")
            _store(conn, row["id"], provider.name, result, run_id)
            counts[f"{lt}.{result.status}"] += 1
            if i % batch_commit == 0:
                conn.commit()             # don't lose finished lookups on a crash
        conn.commit()
    return dict(sorted(counts.items()))
