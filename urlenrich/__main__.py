"""Command line interface.

    python -m urlenrich ingest data/exercise_urls.txt
    python -m urlenrich plan
    python -m urlenrich enrich
    python -m urlenrich report
    python -m urlenrich trace registration company-001.test
    python -m urlenrich export --out results.json
    python -m urlenrich demo data/exercise_urls.txt --out examples/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .db import connect
from .enrich import plan_summary, run_lookups
from .ingest import ingest_file
from .providers import RateLimiter, default_providers
from .report import input_records, render_plan, render_report, render_trace
from .targets import LOOKUP_TYPES


def latest_run(conn) -> int:
    row = conn.execute("SELECT MAX(id) FROM runs").fetchone()
    if row[0] is None:
        sys.exit("No runs yet. Run `ingest` first.")
    return row[0]


def cmd_ingest(conn, a):
    run_id, stats = ingest_file(conn, a.file, a.source)
    print(f"run {run_id}: " + json.dumps(stats, indent=2))


def cmd_plan(conn, a):
    print(render_plan(conn, a.run or latest_run(conn), show_inputs=not a.brief))


def cmd_enrich(conn, a):
    limiters = {lt: RateLimiter(a.rate) for lt in LOOKUP_TYPES}
    counts = run_lookups(conn, default_providers(), a.run or latest_run(conn), limiters,
                         max_per_type=a.max)
    print("lookups performed: " + (json.dumps(counts, indent=2) if counts else "none (all reused)"))


def cmd_report(conn, a):
    print(render_report(conn, a.run or latest_run(conn)))


def cmd_trace(conn, a):
    print(render_trace(conn, a.lookup_type, a.key))


def cmd_export(conn, a):
    run_id = a.run or latest_run(conn)
    doc = {"run_id": run_id, "plan": plan_summary(conn, run_id),
           "inputs": input_records(conn, run_id)}
    Path(a.out).write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    print(f"wrote {a.out}")

def busiest_target(conn, lookup_type: str) -> str | None:
    """The target of this type with the most input lines behind it."""
    row = conn.execute(
        """SELECT t.target_key FROM lookup_targets t
           JOIN url_targets ut ON ut.target_id = t.id
           JOIN raw_inputs ri  ON ri.normalized_url_id = ut.normalized_url_id
           WHERE t.lookup_type = ?
           GROUP BY t.id ORDER BY COUNT(*) DESC, t.target_key LIMIT 1""",
        (lookup_type,)).fetchone()
    return row[0] if row else None

def cmd_demo(conn, a):
    """Full walk-through on a fresh DB, written to example files."""
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    def save(name: str, text: str):
        (out / name).write_text(text + "\n", encoding="utf-8")
        print(f"--- {name} ---\n{text}\n")

    run1, stats1 = ingest_file(conn, a.file)
    save("01_ingest_run1.txt", f"run {run1}: " + json.dumps(stats1, indent=2))
    save("02_plan_run1.txt", render_plan(conn, run1))
    providers = default_providers()
    counts1 = run_lookups(conn, providers, run1)
    save("03_enrich_run1.txt", "lookups performed: " + json.dumps(counts1, indent=2))
    save("04_report_run1.txt", render_report(conn, run1))
    traces = [render_trace(conn, lt, key) for lt in LOOKUP_TYPES
              if (key := busiest_target(conn, lt))]
    save("05_trace_examples.txt", "\n\n".join(traces))
    Path(out / "report_run1.json").write_text(json.dumps(
        {"run_id": run1, "plan": plan_summary(conn, run1), "inputs": input_records(conn, run1)},
        indent=2, ensure_ascii=False), encoding="utf-8")

    # Second run of the same file: nothing new should be looked up.
    run2, stats2 = ingest_file(conn, a.file)
    counts2 = run_lookups(conn, providers, run2)
    save("06_rerun.txt", "\n".join([
        f"run {run2} (same file again): " + json.dumps(stats2, indent=2),
        "",
        render_plan(conn, run2, show_inputs=False),
        "",
        "lookups performed: " + (json.dumps(counts2) if counts2 else "none - every result reused"),
        f"provider call totals across both runs: "
        + json.dumps({lt: p.calls for lt, p in providers.items()}),
    ]))


def main(argv=None):
    p = argparse.ArgumentParser(prog="urlenrich", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="enrichment.db", help="SQLite file (default: enrichment.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ingest", help="ingest a URL file as a new run")
    s.add_argument("file")
    s.add_argument("--source", help="label for where the file came from")
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("plan", help="show deduplicated lookups still to do")
    s.add_argument("--run", type=int)
    s.add_argument("--brief", action="store_true", help="hide the input lines per target")
    s.set_defaults(fn=cmd_plan)

    s = sub.add_parser("enrich", help="run pending lookups with the mock providers")
    s.add_argument("--run", type=int)
    s.add_argument("--rate", type=float, default=20.0, help="max calls/second per provider")
    s.add_argument("--max", type=int, help="max lookups per type this run (budget)")
    s.set_defaults(fn=cmd_enrich)

    s = sub.add_parser("report", help="show results linked back to each input line")
    s.add_argument("--run", type=int)
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("trace", help="show every input line behind one lookup target")
    s.add_argument("lookup_type", choices=LOOKUP_TYPES)
    s.add_argument("key")
    s.set_defaults(fn=cmd_trace)

    s = sub.add_parser("export", help="write per-input results for a run as JSON")
    s.add_argument("--run", type=int)
    s.add_argument("--out", default="results.json")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("demo", help="fresh end-to-end run, twice, saved to example files")
    s.add_argument("file")
    s.add_argument("--out", default="examples")
    s.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    if a.cmd == "demo":
        a.db = ":memory:"      # demo never touches a real database
    conn = connect(a.db)
    try:
        a.fn(conn, a)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
