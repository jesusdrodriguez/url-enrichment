"""SQLite schema and connection helpers.

Six tables, from what we were given to what we learned:

    runs              one row per ingestion
    raw_inputs        every input line, verbatim, per run      (provenance)
    normalized_urls   one row per distinct canonical URL       (dedup level 1)
    lookup_targets    one row per (lookup_type, target_key)    (dedup level 2)
    url_targets       many-to-many: URL -> its targets         (traceability)
    lookup_results    one row per target, reused across runs   (cache)

A result is attached to a *target*, never to a raw line. Walking
lookup_results -> lookup_targets -> url_targets -> normalized_urls ->
raw_inputs gives every original line a result applies to.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY,
    started_at    TEXT NOT NULL,
    source        TEXT NOT NULL,
    stats         TEXT                      -- JSON summary of the run
);

CREATE TABLE IF NOT EXISTS normalized_urls (
    id                  INTEGER PRIMARY KEY,
    url                 TEXT NOT NULL UNIQUE,
    scheme              TEXT NOT NULL,
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL,
    host_type           TEXT NOT NULL CHECK (host_type IN ('domain','ipv4','ipv6')),
    registrable_domain  TEXT,
    site                TEXT,               -- private-suffix-aware owner, e.g. alice.github.io
    skipped_lookups     TEXT NOT NULL,      -- JSON {lookup_type: reason}
    first_seen_run      INTEGER NOT NULL REFERENCES runs(id),
    last_seen_run       INTEGER NOT NULL REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS raw_inputs (
    id                  INTEGER PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES runs(id),
    source              TEXT NOT NULL,
    line_no             INTEGER NOT NULL,
    raw_text            TEXT NOT NULL,      -- exactly as read (minus the line ending)
    status              TEXT NOT NULL CHECK (status IN ('accepted','rejected','skipped')),
    reason              TEXT,               -- why rejected / skipped
    flags               TEXT NOT NULL,      -- JSON list of normalization steps applied
    normalized_url_id   INTEGER REFERENCES normalized_urls(id),
    UNIQUE (run_id, line_no)
);

CREATE TABLE IF NOT EXISTS lookup_targets (
    id              INTEGER PRIMARY KEY,
    lookup_type     TEXT NOT NULL CHECK (lookup_type IN ('registration','tls','reputation')),
    target_key      TEXT NOT NULL,
    attrs           TEXT NOT NULL,          -- JSON, what the provider needs (host, port, sni...)
    first_seen_run  INTEGER NOT NULL REFERENCES runs(id),
    UNIQUE (lookup_type, target_key)
);

CREATE TABLE IF NOT EXISTS url_targets (
    normalized_url_id   INTEGER NOT NULL REFERENCES normalized_urls(id),
    target_id           INTEGER NOT NULL REFERENCES lookup_targets(id),
    derivation          TEXT NOT NULL,      -- e.g. explicit_https / inferred_from_http
    PRIMARY KEY (normalized_url_id, target_id)
);

CREATE TABLE IF NOT EXISTS lookup_results (
    target_id       INTEGER PRIMARY KEY REFERENCES lookup_targets(id),
    status          TEXT NOT NULL CHECK (status IN ('ok','not_found','error')),
    payload         TEXT,                   -- JSON from the provider
    error           TEXT,
    provider        TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 1,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    fetched_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_raw_inputs_url    ON raw_inputs(normalized_url_id);
CREATE INDEX IF NOT EXISTS ix_url_targets_target ON url_targets(target_id);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    return conn
