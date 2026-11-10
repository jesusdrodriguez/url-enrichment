"""Read-side views: the lookup plan, per-input results, and target traces."""

from __future__ import annotations

import json
import sqlite3

from .enrich import inputs_for_target, pending_targets, plan_summary
from .targets import LOOKUP_TYPES


def summarize_result(lookup_type: str, status: str | None, payload: str | None,
                     error: str | None) -> str:
    if status is None:
        return "PENDING (no result yet)"
    if status == "error":
        return f"ERROR ({error}) - will retry"
    p = json.loads(payload or "{}")
    if status == "not_found":
        return f"not_found ({p.get('note', '')})"
    if lookup_type == "registration":
        return f"registrar={p['registrar']}, created={p['created']}"
    if lookup_type == "tls":
        return f"issuer={p['issuer']}, expires={p['not_after']}"
    return f"verdict={p['verdict']} (score {p['score']})"


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

def render_plan(conn: sqlite3.Connection, run_id: int, show_inputs: bool = True) -> str:
    out = [f"LOOKUP PLAN (run {run_id})", ""]
    out.append(f"{'lookup type':<14}{'naive':>8}{'unique':>9}{'reused':>9}{'to call':>10}")
    for lt, s in plan_summary(conn, run_id).items():
        out.append(f"{lt:<14}{s['naive_requests']:>8}{s['unique_targets']:>9}"
                   f"{s['reused_results']:>9}{s['pending_lookups']:>10}")
    out.append("  naive   = one call per accepted input line")
    out.append("  unique  = distinct targets after normalization + grouping")
    out.append("  reused  = targets that already have a result from an earlier run")
    out.append("  to call = requests that will actually be sent")
    for lt in LOOKUP_TYPES:
        rows = pending_targets(conn, lt)
        out += ["", f"== {lt.upper()}: {len(rows)} pending lookups =="]
        for row in rows:
            inputs = inputs_for_target(conn, row["id"], run_id)
            out.append(f"  {row['target_key']}   <- {len(inputs)} input line(s)")
            if show_inputs:
                for inp in inputs:
                    out.append(f"      line {inp['line_no']:>3} [{inp['derivation']}]  "
                               f"{inp['raw_text'].strip()}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Per-input report
# --------------------------------------------------------------------------- #

def input_records(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    """One record per raw input line, with every lookup target and result."""
    records = []
    for ri in conn.execute(
        """SELECT ri.*, nu.url, nu.skipped_lookups FROM raw_inputs ri
           LEFT JOIN normalized_urls nu ON nu.id = ri.normalized_url_id
           WHERE ri.run_id = ? ORDER BY ri.line_no""", (run_id,)):
        rec = {"line_no": ri["line_no"], "raw": ri["raw_text"], "status": ri["status"],
               "reason": ri["reason"], "flags": json.loads(ri["flags"]),
               "normalized_url": ri["url"], "lookups": {}}
        if ri["status"] == "accepted":
            for lt, reason in json.loads(ri["skipped_lookups"]).items():
                rec["lookups"][lt] = {"target": None, "not_applicable": reason}
            for t in conn.execute(
                """SELECT t.lookup_type, t.target_key, ut.derivation,
                          r.status, r.payload, r.error, r.run_id AS result_run
                   FROM url_targets ut
                   JOIN lookup_targets t ON t.id = ut.target_id
                   LEFT JOIN lookup_results r ON r.target_id = t.id
                   WHERE ut.normalized_url_id = ?""", (ri["normalized_url_id"],)):
                rec["lookups"][t["lookup_type"]] = {
                    "target": t["target_key"], "derivation": t["derivation"],
                    "status": t["status"] or "pending",
                    "result": json.loads(t["payload"]) if t["payload"] else None,
                    "error": t["error"], "result_from_run": t["result_run"],
                    "summary": summarize_result(t["lookup_type"], t["status"], t["payload"],
                                                t["error"]),
                }
        records.append(rec)
    return records


def render_report(conn: sqlite3.Connection, run_id: int) -> str:
    out = [f"RESULTS BY INPUT LINE (run {run_id})"]
    for rec in input_records(conn, run_id):
        out.append("")
        out.append(f"line {rec['line_no']:>3}: {rec['raw']!r}")
        if rec["status"] != "accepted":
            out.append(f"    {rec['status'].upper()}: {rec['reason']}")
            continue
        out.append(f"    normalized: {rec['normalized_url']}")
        if rec["flags"]:
            out.append(f"    steps:      {', '.join(rec['flags'])}")
        for lt in LOOKUP_TYPES:
            lk = rec["lookups"].get(lt)
            if lk is None:
                continue
            if lk["target"] is None:
                out.append(f"    {lt:<12} n/a ({lk['not_applicable']})")
                continue
            reused = (lk["result_from_run"] is not None and lk["result_from_run"] != run_id)
            tag = f" [reused from run {lk['result_from_run']}]" if reused else ""
            out.append(f"    {lt:<12} {lk['target']}  ->  {lk['summary']}{tag}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Trace: from one target back to every input that produced it
# --------------------------------------------------------------------------- #

def render_trace(conn: sqlite3.Connection, lookup_type: str, key: str) -> str:
    t = conn.execute(
        """SELECT t.id, t.target_key, t.first_seen_run, r.status, r.payload, r.error,
                  r.run_id, r.attempts
           FROM lookup_targets t LEFT JOIN lookup_results r ON r.target_id = t.id
           WHERE t.lookup_type = ? AND t.target_key = ?""", (lookup_type, key)).fetchone()
    if t is None:
        return f"No {lookup_type} target {key!r}."
    out = [f"TRACE {lookup_type}: {key}",
           f"  result: {summarize_result(lookup_type, t['status'], t['payload'], t['error'])}"
           + (f"  (fetched in run {t['run_id']}, attempts {t['attempts']})" if t["status"] else "")]
    urls = conn.execute(
        """SELECT nu.id, nu.url, ut.derivation FROM url_targets ut
           JOIN normalized_urls nu ON nu.id = ut.normalized_url_id
           WHERE ut.target_id = ? ORDER BY nu.url""", (t["id"],)).fetchall()
    out.append(f"  {len(urls)} normalized URL(s):")
    for u in urls:
        out.append(f"    {u['url']}   [{u['derivation']}]")
        for ri in conn.execute(
            "SELECT run_id, line_no, raw_text FROM raw_inputs WHERE normalized_url_id=? "
            "ORDER BY run_id, line_no", (u["id"],)):
            out.append(f"        run {ri['run_id']} line {ri['line_no']:>3}: {ri['raw_text'].strip()}")
    return "\n".join(out)
