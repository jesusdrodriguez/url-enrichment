"""Ingest a raw URL file into the database.

Idempotent by design: running the same file twice adds a new `runs` row and
new `raw_inputs` rows (the provenance log of what was seen and when), but no
new normalized URLs, targets or lookups. Uniqueness is enforced by the
database (UNIQUE constraints + ON CONFLICT), not just by in-memory sets, so it
also holds across processes and across runs.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .normalize import Reject, Skip, normalize
from .targets import derive


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_lines(path: str | Path) -> Iterable[tuple[int, str]]:
    # newline="" keeps "\r\n" intact so we see exactly what was in the file;
    # errors="replace" means one bad byte can't abort a large ingest.
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        for line_no, line in enumerate(fh, start=1):
            yield line_no, line


def _upsert_url(conn, n, d, run_id) -> int:
    row = conn.execute(
        """INSERT INTO normalized_urls
               (url, scheme, host, port, host_type, registrable_domain, site,
                skipped_lookups, first_seen_run, last_seen_run)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(url) DO UPDATE SET last_seen_run = excluded.last_seen_run
           RETURNING id""",
        (n.url, n.scheme, n.host, n.port, n.host_type, d.registrable_domain, d.site,
         json.dumps(d.skipped, sort_keys=True), run_id, run_id),
    ).fetchone()
    return row[0]


def _upsert_target(conn, t, run_id) -> tuple[int, bool]:
    """Return (target_id, created_now)."""
    row = conn.execute(
        """INSERT INTO lookup_targets (lookup_type, target_key, attrs, first_seen_run)
           VALUES (?,?,?,?)
           ON CONFLICT(lookup_type, target_key) DO NOTHING
           RETURNING id""",
        (t.lookup_type, t.key, json.dumps(t.attrs, sort_keys=True), run_id),
    ).fetchone()
    if row:
        return row[0], True
    row = conn.execute(
        "SELECT id FROM lookup_targets WHERE lookup_type=? AND target_key=?",
        (t.lookup_type, t.key),
    ).fetchone()
    return row[0], False


def ingest_lines(conn: sqlite3.Connection, lines: Iterable[tuple[int, str]],
                 source: str) -> tuple[int, dict]:
    """Ingest (line_no, text) pairs. Returns (run_id, stats)."""
    stats: Counter = Counter()
    reasons: Counter = Counter()
    url_ids: dict[str, int] = {}     # per-run cache: avoid re-deriving repeated URLs

    with conn:  # one transaction: a run is all-or-nothing
        run_id = conn.execute("INSERT INTO runs (started_at, source) VALUES (?,?)",
                              (now(), source)).lastrowid

        for line_no, raw in lines:
            raw_text = raw.rstrip("\r\n")
            stats["lines"] += 1
            status, reason, flags, url_id = "accepted", None, [], None
            try:
                n = normalize(raw)
                flags = n.flags
                url_id = url_ids.get(n.url)
                if url_id is None:
                    stats["distinct_urls_this_run"] += 1
                    d = derive(n)
                    existed = conn.execute("SELECT 1 FROM normalized_urls WHERE url=?",
                                           (n.url,)).fetchone()
                    url_id = _upsert_url(conn, n, d, run_id)
                    stats["new_normalized_urls" if not existed else "known_normalized_urls"] += 1
                    for t in d.targets:
                        target_id, created = _upsert_target(conn, t, run_id)
                        if created:
                            stats[f"new_targets.{t.lookup_type}"] += 1
                        conn.execute(
                            """INSERT OR IGNORE INTO url_targets
                                   (normalized_url_id, target_id, derivation)
                               VALUES (?,?,?)""",
                            (url_id, target_id, t.derivation),
                        )
                    url_ids[n.url] = url_id
            except Skip as s:
                status, reason = "skipped", s.reason
            except Reject as r:
                status, reason = "rejected", r.reason + (f": {r.detail}" if r.detail else "")
                reasons[r.reason] += 1

            stats[status] += 1
            conn.execute(
                """INSERT INTO raw_inputs
                       (run_id, source, line_no, raw_text, status, reason, flags, normalized_url_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (run_id, source, line_no, raw_text, status, reason, json.dumps(flags), url_id),
            )

        summary = dict(sorted(stats.items()))
        summary["rejection_reasons"] = dict(sorted(reasons.items()))
        conn.execute("UPDATE runs SET stats=? WHERE id=?", (json.dumps(summary), run_id))
    return run_id, summary


def ingest_file(conn: sqlite3.Connection, path: str | Path, source: str | None = None):
    return ingest_lines(conn, read_lines(path), source or Path(path).name)
