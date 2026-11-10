"""End-to-end behaviour: dedup, idempotent re-runs, retries, traceability."""

from pathlib import Path

import pytest

from urlenrich.db import connect
from urlenrich.enrich import inputs_for_target, pending_targets, plan_summary, run_lookups
from urlenrich.ingest import ingest_file, ingest_lines
from urlenrich.providers import LookupResult, RateLimiter, default_providers
from urlenrich.report import input_records

DATA = Path(__file__).resolve().parent.parent / "data" / "exercise_urls.txt"


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def lines(*urls):
    return list(enumerate(urls, start=1))


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_exercise_file_counts(conn):
    run_id, stats = ingest_file(conn, DATA)
    assert stats["lines"] == 1000
    assert (stats["accepted"], stats["rejected"], stats["skipped"]) == (987, 12, 1)
    assert stats["rejection_reasons"] == {
        "invalid_host": 4, "missing_host": 3,
        "single_label_host": 1, "unsupported_scheme": 4,
    }
    plan = plan_summary(conn, run_id)
    # naive = one call per accepted line; unique = after grouping
    assert plan["registration"]["naive_requests"] == 914
    assert plan["tls"]["naive_requests"] == 986
    assert plan["reputation"]["naive_requests"] == 987
    assert plan["registration"]["unique_targets"] == 270
    assert plan["tls"]["unique_targets"] == 743
    assert plan["reputation"]["unique_targets"] == 897
    # every input line is stored, including the bad ones
    assert count(conn, "raw_inputs") == 1000


def test_duplicates_create_one_target_but_keep_every_link(conn):
    run_id, _ = ingest_lines(conn, lines(
        "https://www.example.com/", "HTTPS://WWW.EXAMPLE.COM:443/#x", "www.example.com"), "t")
    assert count(conn, "normalized_urls") == 2           # https://... and http://...
    tls = pending_targets(conn, "tls")
    assert [r["target_key"] for r in tls] == ["www.example.com:443"]
    linked = inputs_for_target(conn, tls[0]["id"], run_id)
    assert [r["line_no"] for r in linked] == [1, 2, 3]   # all three traced back


def test_rerun_reuses_results_and_makes_no_calls(conn):
    providers = default_providers()
    run1, _ = ingest_file(conn, DATA)
    first = run_lookups(conn, providers, run1)
    calls_after_first = {k: p.calls for k, p in providers.items()}
    assert calls_after_first == {"registration": 270, "tls": 743, "reputation": 897}
    assert sum(first.values()) == 1910

    targets_before = count(conn, "lookup_targets")
    run2, stats2 = ingest_file(conn, DATA)
    assert stats2.get("new_normalized_urls", 0) == 0
    assert stats2["known_normalized_urls"] == 897
    assert count(conn, "lookup_targets") == targets_before
    assert run_lookups(conn, providers, run2) == {}
    assert {k: p.calls for k, p in providers.items()} == calls_after_first

    plan = plan_summary(conn, run2)
    assert all(p["pending_lookups"] == 0 for p in plan.values())
    # run 2's inputs still get results, attributed to run 1
    rec = next(r for r in input_records(conn, run2) if r["line_no"] == 1)
    assert rec["lookups"]["reputation"]["result_from_run"] == run1


def test_new_run_only_looks_up_new_targets(conn):
    providers = default_providers()
    run1, _ = ingest_lines(conn, lines("https://a.example.com/x"), "batch1")
    run_lookups(conn, providers, run1)
    run2, _ = ingest_lines(conn, lines("https://a.example.com/x", "https://b.example.com/y"), "batch2")
    plan = plan_summary(conn, run2)
    assert plan["registration"] == {"naive_requests": 2, "unique_targets": 1,
                                    "pending_lookups": 0, "reused_results": 1}
    assert plan["tls"]["pending_lookups"] == 1            # only b.example.com:443
    assert plan["reputation"]["pending_lookups"] == 1


class FlakyProvider:
    name, lookup_type = "flaky", "reputation"

    def __init__(self):
        self.calls = 0

    def lookup(self, key, attrs):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("upstream timeout")
        return LookupResult("ok", {"verdict": "clean", "score": 1})


def test_errors_are_retried_on_next_run(conn):
    p = FlakyProvider()
    run1, _ = ingest_lines(conn, lines("https://example.com/"), "t")
    assert run_lookups(conn, {"reputation": p}, run1) == {"reputation.error": 1}
    assert len(pending_targets(conn, "reputation")) == 1  # still pending
    assert run_lookups(conn, {"reputation": p}, run1) == {"reputation.ok": 1}
    row = conn.execute("SELECT status, attempts FROM lookup_results").fetchone()
    assert (row["status"], row["attempts"]) == ("ok", 2)
    assert run_lookups(conn, {"reputation": p}, run1) == {}


def test_budget_leaves_rest_pending(conn):
    run1, _ = ingest_file(conn, DATA)
    run_lookups(conn, default_providers(), run1, max_per_type=5)
    assert len(pending_targets(conn, "reputation")) == 892


def test_rejected_and_skipped_lines_are_recorded(conn):
    run_id, _ = ingest_lines(conn, lines("", "mailto:x@y.com", "https://ok.example.com/"), "t")
    recs = {r["line_no"]: r for r in input_records(conn, run_id)}
    assert recs[1]["status"] == "skipped" and recs[1]["reason"] == "blank_line"
    assert recs[2]["status"] == "rejected" and recs[2]["reason"].startswith("unsupported_scheme")
    assert recs[3]["status"] == "accepted"


def test_rate_limiter_spaces_calls():
    t = {"now": 0.0}
    slept = []

    def sleep(s):
        slept.append(s)
        t["now"] += s

    rl = RateLimiter(per_second=2, clock=lambda: t["now"], sleep=sleep)
    for _ in range(3):
        rl.acquire()
    assert slept == [0.5, 0.5]
