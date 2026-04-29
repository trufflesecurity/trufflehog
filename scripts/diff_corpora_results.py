#!/usr/bin/env python3
"""
Diffs two trufflehog JSONL outputs (main vs PR build) and emits a Markdown
report to stdout.

Identity per finding: (DetectorName, Raw or RawV2 fallback). Set semantics —
duplicates within a single scan collapse into one identity, so a regex change
either adds a new (detector, secret) identity or removes one.

Verification is disabled at scan time (see scripts/detector_corpora_test.sh),
so verified/unverified deltas are intentionally not surfaced — the diff
measures regex match changes only.

Usage: diff_corpora_results.py <main.jsonl> <pr.jsonl>
"""
import json
import sys
from collections import defaultdict


PREAMBLE = (
    "This bench measures regex match regressions only. It runs with "
    "`--no-verification --allow-verification-overlap` so each detector's "
    "regex behavior is measured independently — verifier behavior is tested "
    "separately by detector unit tests."
)


def load_findings(path):
    """Returns dict: detector_name -> {"identities": set[str], "total": int}."""
    by_detector = defaultdict(lambda: {"identities": set(), "total": 0})
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = obj.get("DetectorName") or ""
            if not detector:
                continue
            raw = obj.get("Raw") or obj.get("RawV2") or ""
            by_detector[detector]["identities"].add(raw)
            by_detector[detector]["total"] += 1
    return by_detector


def render(main, pr):
    detectors = sorted(set(main) | set(pr))
    rows = []
    has_diff = False
    for d in detectors:
        m = main.get(d, {"identities": set(), "total": 0})
        p = pr.get(d, {"identities": set(), "total": 0})
        new = p["identities"] - m["identities"]
        removed = m["identities"] - p["identities"]
        # A row is "diff-clean" only when NEW, REMOVED, AND raw totals all match.
        # Total-count differences without identity changes are still real (e.g.,
        # a regex change in one detector can shift duplicate-match counts via
        # cross-detector dedup), so they must not be reported as ✅.
        if new or removed or m["total"] != p["total"]:
            has_diff = True
        rows.append({
            "detector": d,
            "total_main": m["total"],
            "total_pr": p["total"],
            "unique_main": len(m["identities"]),
            "unique_pr": len(p["identities"]),
            "new": len(new),
            "removed": len(removed),
        })

    title = "## Corpora Test Results — Diff (PR vs main)"
    parts = [title, "", PREAMBLE, ""]

    if not rows:
        parts += ["_(No findings on either side.)_", ""]
        return "\n".join(parts)

    if has_diff:
        rows.sort(key=lambda r: (r["new"] + r["removed"], r["detector"]), reverse=True)
    else:
        parts += ["✅ No diff vs main — regex matches are identical across both builds.", ""]
        rows.sort(key=lambda r: r["detector"])

    parts += [
        "| Detector | total main | total PR | unique main | unique PR | NEW | REMOVED |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        parts.append(
            f"| {r['detector']} | {r['total_main']} | {r['total_pr']} | "
            f"{r['unique_main']} | {r['unique_pr']} | {r['new']} | {r['removed']} |"
        )
    parts.append("")
    return "\n".join(parts)


def main():
    if len(sys.argv) != 3:
        print("Usage: diff_corpora_results.py <main.jsonl> <pr.jsonl>", file=sys.stderr)
        sys.exit(2)
    main_findings = load_findings(sys.argv[1])
    pr_findings = load_findings(sys.argv[2])
    sys.stdout.write(render(main_findings, pr_findings))


if __name__ == "__main__":
    main()
