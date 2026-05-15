#!/usr/bin/env python3
"""
Diffs two trufflehog JSONL outputs (main vs PR build) and emits a Markdown
report to stdout.

Identity per finding: (DetectorName, Raw or RawV2 fallback). Set semantics —
duplicates within a single scan collapse into one identity, so a regex change
either adds a new (detector, secret) identity or removes one.

Verification is disabled at scan time (--no-verification) to avoid network
calls against a large corpus where thousands of matches could dominate runtime.
The diff measures regex match changes only.

When --changed-detectors is provided, the report focuses on the detectors
changed by the PR. Detectors flagged via --new-detectors are rendered with 🆕
status and absolute density (no main baseline). When --corpus-bytes is
provided, a blast-radius column projects matches per 10 GB of scanned content.

Usage:
    diff_corpora_results.py <main.jsonl> <pr.jsonl>
        [--changed-detectors=<csv>]
        [--new-detectors=<csv>]
        [--corpus-bytes=<n>]
"""
import argparse
import json
import sys
from collections import defaultdict


PREAMBLE = (
    "Scans a corpus of real-world public code against only the detectors "
    "changed in this PR, then compares unique match counts between the PR "
    "build and the main baseline to catch regex regressions. Verification "
    "is disabled — each detector's regex is measured independently."
)

STATUS_KEY = (
    "- 🔴 regression: >5 new, >20% increase over main, or any removed\n"
    "- ⚠️ warning: 1–5 new and ≤20% increase over main\n"
    "- ✅ clean\n"
    "- 🆕 new detector (no baseline)"
)

# Marker on the very first line of the body so peter-evans/find-comment can
# locate the sticky comment via substring match. Workflow file references the
# same literal — keep the two in sync.
STICKY_COMMENT_MARKER = "<!-- detector-bench -->"


def parse_csv(s):
    """Parse a comma-separated detector list into normalized name set.

    Strips ``.v<n>`` version suffixes and lowercases. JSONL DetectorName is the
    proto enum name (e.g., ``JDBC``); we match case-insensitively by name only,
    since version doesn't appear in the output. Versioned scoping happens at
    the trufflehog --include-detectors level.
    """
    if not s:
        return set()
    out = set()
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        if "." in item:
            item = item.split(".", 1)[0]
        out.add(item.lower())
    return out


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


def status_emoji(new_count, removed_count, unique_main):
    """Hybrid threshold: 🔴 on absolute (>5) OR relative (>20% of main) NEW, OR any REMOVED."""
    if removed_count > 0:
        return "🔴"
    if new_count > 5 or new_count > 0.20 * max(unique_main, 1):
        return "🔴"
    if new_count > 0:
        return "⚠️"
    return "✅"


def build_top_line_summary(rows, changed):
    regressed = sum(1 for r in rows if not r["is_new"] and r["emoji"] == "🔴")
    warned = sum(1 for r in rows if not r["is_new"] and r["emoji"] == "⚠️")
    new_count = sum(1 for r in rows if r["is_new"])
    clean = sum(1 for r in rows if r["emoji"] == "✅")
    scoped = ", ".join(f"`{d}`" for d in sorted(changed)) if changed else ""
    parts = []
    if regressed:
        parts.append(f"{regressed} regressed")
    if warned:
        parts.append(f"{warned} warned")
    parts += [f"{new_count} new", f"{clean} clean"]
    summary = f"**{' · '.join(parts)}**"
    if scoped:
        summary += f" \u00a0|\u00a0 Scoped to: {scoped}"
    return summary


def render(main, pr, changed=None, new_detectors=None):
    new_detectors = new_detectors or set()

    if changed:
        all_names = {d for d in (set(main) | set(pr))
                     if d.lower() in changed}
        # Detectors that the PR claims to have changed (or added) but that
        # produced zero matches on either side. These don't appear in JSONL,
        # so we surface them as a warning row.
        seen_lower = {d.lower() for d in (set(main) | set(pr))}
        missing = sorted(d for d in changed if d not in seen_lower)
    else:
        all_names = set(main) | set(pr)
        missing = []

    _empty = {"identities": set(), "total": 0}
    rows = []
    has_diff = False
    for d in sorted(all_names):
        # A detector is only treated as fully new if the new_detectors set
        # says so AND main produced no findings for it. When a PR modifies an
        # existing version and adds a new version of the same detector (e.g.
        # jdbc.v1 + jdbc.v2), both collapse to "jdbc" in new_detectors but
        # main still ran against the existing version — its results must not
        # be discarded.
        is_new = d.lower() in new_detectors and d not in main
        m = main.get(d, _empty)
        p = pr.get(d, _empty)
        new_ids = p["identities"] - m["identities"]
        removed_ids = m["identities"] - p["identities"]

        if is_new:
            emoji = "🆕"
        else:
            emoji = status_emoji(len(new_ids), len(removed_ids), len(m["identities"]))

        if new_ids or removed_ids or m["total"] != p["total"]:
            has_diff = True

        rows.append({
            "detector": d,
            "is_new": is_new,
            "emoji": emoji,
            "total_main": m["total"],
            "total_pr": p["total"],
            "unique_main": len(m["identities"]),
            "unique_pr": len(p["identities"]),
            "new_count": len(new_ids),
            "removed_count": len(removed_ids),
        })

    parts = [
        STICKY_COMMENT_MARKER,
        "## Corpora Test Results",
        "",
        PREAMBLE,
        "",
    ]
    if rows:
        parts += [build_top_line_summary(rows, changed), ""]

    if not rows and not missing:
        parts += ["_(No findings on either side for the changed detectors.)_", ""]
        return "\n".join(parts)

    if rows:
        if has_diff or any(r["is_new"] for r in rows):
            rows.sort(
                key=lambda r: (
                    0 if r["is_new"] else 1,
                    -(r["new_count"] + r["removed_count"]),
                    r["detector"],
                )
            )
        else:
            rows.sort(key=lambda r: r["detector"])

        cols = ["Status", "Detector", "Unique matches (main)", "Unique matches (PR)",
                "New", "Removed"]
        aligns = ["", "", "---:", "---:", "---:", "---:"]
        parts += [
            "| " + " | ".join(cols) + " |",
            "|" + "|".join(a if a else "---" for a in aligns) + "|",
        ]

        for r in rows:
            if r["is_new"]:
                cells = [
                    r["emoji"],
                    r["detector"],
                    "—",
                    str(r["unique_pr"]),
                    "—",
                    "—",
                ]
            else:
                cells = [
                    r["emoji"],
                    r["detector"],
                    str(r["unique_main"]),
                    str(r["unique_pr"]),
                    str(r["new_count"]),
                    str(r["removed_count"]),
                ]
            parts.append("| " + " | ".join(cells) + " |")
        parts.append("")
        parts.append(STATUS_KEY)
        parts.append("")

    if missing:
        parts += [
            "### ⚠️ Changed detectors with zero matches in both builds",
            "",
            "These detectors were modified by the PR but produced no matches "
            "against the corpus on either side. Could be a deliberate scope "
            "narrowing, or — more concerning — a regex so loose the engine "
            "silently filtered the flood (issue #3578). Worth a manual look.",
            "",
        ]
        for d in missing:
            parts.append(f"- `{d}`")
        parts.append("")

    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("main_jsonl")
    parser.add_argument("pr_jsonl")
    parser.add_argument("--changed-detectors", default="",
                        help="CSV of detectors changed in PR; filters report.")
    parser.add_argument("--new-detectors", default="",
                        help="CSV of detectors present in PR but not main; rendered with 🆕.")
    args = parser.parse_args()

    main_findings = load_findings(args.main_jsonl)
    pr_findings = load_findings(args.pr_jsonl)
    changed = parse_csv(args.changed_detectors)
    new_detectors = parse_csv(args.new_detectors)

    sys.stdout.write(render(
        main_findings,
        pr_findings,
        changed=changed if changed else None,
        new_detectors=new_detectors,
    ))


if __name__ == "__main__":
    main()
