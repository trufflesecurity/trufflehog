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

Phase 2: when --changed-detectors is provided, the report focuses on the
detectors changed by the PR. Detectors flagged via --new-detectors are
rendered with 🆕 status and absolute density (no main baseline). When
--corpus-bytes is provided, a blast-radius column projects matches per
10 GB of scanned content.

Phase 3a: --keyword-corpus-meta points at the sidecar JSON written by
scripts/build_keyword_corpus.py. When present, detectors whose Layer 1
(GitHub Code Search) fetch returned zero results get a concise warning
rendered above the per-detector details — they're flagged so reviewers
know the bench's verdict for those detectors leans entirely on the S3
corpus and may be under-sampled.

Phase 4: --heatmap-png and --heatmap-artifact-url embed the heatmap
rendered by scripts/render_heatmap.py at the top of the report. We try
inline base64 first (no auth, renders everywhere GitHub Markdown does);
if the encoded image would push the comment near GitHub's 65 KB body
limit, we fall back to a clickable artifact link instead. Missing PNG
or zero-length file → no heatmap section, no error.

Usage:
    diff_corpora_results.py <main.jsonl> <pr.jsonl>
        [--changed-detectors=<csv>]
        [--new-detectors=<csv>]
        [--corpus-bytes=<n>]
        [--keyword-corpus-meta=<path>]
        [--heatmap-png=<path>]
        [--heatmap-artifact-url=<url>]
"""
import argparse
import base64
import json
import os
import sys
from collections import defaultdict


PREAMBLE = (
    "This bench measures regex match regressions only. It runs with "
    "`--no-verification --allow-verification-overlap` so each detector's "
    "regex behavior is measured independently — verifier behavior is tested "
    "separately by detector unit tests."
)

# 10 GB notional monorepo for blast-radius projection.
BLAST_RADIUS_BYTES = 10 * 1024 * 1024 * 1024

# Cap how many sample Raw values we render in the per-detector details.
SAMPLE_LIMIT = 10
SAMPLE_TRUNCATE = 120

# GitHub issue/PR comment bodies are capped at 65536 chars. The summary table
# plus per-detector details routinely consume 5-15 KB; budgeting ~50 KB for the
# inline PNG keeps comfortable headroom while still permitting most heatmaps
# to embed directly. Larger images fall back to the artifact-URL link.
HEATMAP_INLINE_LIMIT_BYTES = 50 * 1024


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
    """Returns dict: detector_name -> {"identities": set[str], "total": int, "samples": list[str]}."""
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


def truncate(s, n=SAMPLE_TRUNCATE):
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def render_blast_radius(matches, corpus_bytes, signed=False):
    if corpus_bytes is None or corpus_bytes <= 0:
        return ""
    density = matches / corpus_bytes  # matches per byte
    projected = density * BLAST_RADIUS_BYTES
    if signed:
        sign = "+" if projected > 0 else ("−" if projected < 0 else "")
        return f"{sign}{abs(projected):,.0f}"
    return f"{projected:,.0f}"


def load_keyword_corpus_meta(path):
    """Read the sidecar emitted by build_keyword_corpus.py.

    Returns a dict with `thin_l1` (set of detector names, lowercase, dotted
    suffix stripped to match identity normalization elsewhere in this
    file) and `reports` (kept as-is for future use). Missing/unreadable
    file → empty result, surfaced silently — Phase 3a coverage is a
    nice-to-have, not load-bearing.
    """
    if not path:
        return {"thin_l1": set(), "reports": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"thin_l1": set(), "reports": []}
    thin = set()
    for name in raw.get("thin_l1") or []:
        if not isinstance(name, str):
            continue
        norm = name.split(".", 1)[0].strip().lower()
        if norm:
            thin.add(norm)
    return {"thin_l1": thin, "reports": raw.get("reports") or []}


def build_heatmap_section(png_path, artifact_url):
    """Return the Markdown lines that embed the heatmap, or [] if there's
    nothing to embed.

    Strategy:
      1. If the PNG file is missing/empty, nothing to do.
      2. Try inline base64 if the encoded body fits the inline budget.
         Inline survives comment pruning of artifacts and renders without
         GitHub auth on mobile/desktop alike.
      3. Otherwise fall back to a plain Markdown link to the workflow
         artifact URL with a one-line explainer. Artifact URLs require
         GitHub login, so no embedded ``![](...)`` — that would render as
         a broken image.
    """
    if not png_path or not os.path.isfile(png_path):
        return []
    try:
        size = os.path.getsize(png_path)
    except OSError:
        return []
    if size <= 0:
        return []

    if size <= HEATMAP_INLINE_LIMIT_BYTES:
        try:
            with open(png_path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("ascii")
        except OSError:
            return []
        return [
            "### Δ heatmap (changed detectors × decoder)",
            "",
            f"![PR vs main — Δ unique findings per (detector, decoder)]"
            f"(data:image/png;base64,{encoded})",
            "",
        ]

    if artifact_url:
        return [
            "### Δ heatmap (changed detectors × decoder)",
            "",
            f"_Heatmap PNG too large to inline ({size // 1024} KB); "
            f"[download from workflow artifacts]({artifact_url})._",
            "",
        ]
    return []


def render(main, pr, changed=None, new_detectors=None, corpus_bytes=None,
           keyword_meta=None, heatmap_png=None, heatmap_artifact_url=None):
    new_detectors = new_detectors or set()
    keyword_meta = keyword_meta or {"thin_l1": set(), "reports": []}

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

    rows = []
    has_diff = False
    for d in sorted(all_names):
        is_new = d.lower() in new_detectors
        m = main.get(d, {"identities": set(), "total": 0})
        p = pr.get(d, {"identities": set(), "total": 0})
        new_ids = p["identities"] - m["identities"]
        removed_ids = m["identities"] - p["identities"]

        if is_new:
            emoji = "🆕"
        else:
            emoji = status_emoji(len(new_ids), len(removed_ids), len(m["identities"]))

        if new_ids or removed_ids or m["total"] != p["total"]:
            has_diff = True

        if is_new:
            blast = render_blast_radius(p["total"], corpus_bytes, signed=False)
        else:
            blast = render_blast_radius(p["total"] - m["total"], corpus_bytes, signed=True)

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
            "new_samples": sorted(new_ids)[:SAMPLE_LIMIT],
            "removed_samples": sorted(removed_ids)[:SAMPLE_LIMIT],
            "blast": blast,
        })

    parts = ["## Corpora Test Results — Diff (PR vs main)", "", PREAMBLE, ""]
    if changed:
        parts.append(
            f"_Scoped to {len(changed)} detector(s) changed in this PR; "
            f"unchanged detectors are not measured._"
        )
        parts.append("")

    parts += build_heatmap_section(heatmap_png, heatmap_artifact_url)

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
            parts += [
                "✅ No diff vs main — regex matches are identical across both builds.",
                "",
            ]
            rows.sort(key=lambda r: r["detector"])

        show_blast = corpus_bytes is not None and corpus_bytes > 0
        cols = ["Status", "Detector", "total main", "total PR",
                "unique main", "unique PR", "NEW", "REMOVED"]
        aligns = ["", "", "---:", "---:", "---:", "---:", "---:", "---:"]
        if show_blast:
            cols.append("Blast radius (Δ per 10 GB)")
            aligns.append("---:")
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
                    str(r["total_pr"]),
                    "—",
                    str(r["unique_pr"]),
                    "—",
                    "—",
                ]
            else:
                cells = [
                    r["emoji"],
                    r["detector"],
                    str(r["total_main"]),
                    str(r["total_pr"]),
                    str(r["unique_main"]),
                    str(r["unique_pr"]),
                    str(r["new_count"]),
                    str(r["removed_count"]),
                ]
            if show_blast:
                cells.append(r["blast"] or "—")
            parts.append("| " + " | ".join(cells) + " |")
        parts.append("")

        if show_blast:
            parts += [
                "_Blast radius projects PR-vs-main match-count delta to a 10 GB "
                "monorepo (positive = added matches, negative = removed). For 🆕 "
                "rows it shows absolute projected matches with no baseline._",
                "",
            ]

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

    thin_l1 = sorted(keyword_meta.get("thin_l1") or set())
    if changed:
        thin_l1 = [d for d in thin_l1 if d in changed]
    if thin_l1:
        # Single contiguous blockquote: `>` on the spacer line keeps GitHub
        # Markdown from splitting the bullet list into a second quote.
        parts.append(
            "> ⚠️ **Thin Layer 1 coverage:** GitHub Code Search returned no "
            "snippets for the detectors below. The bench's verdict for them "
            "leans entirely on the S3 corpus and may be under-sampled."
        )
        parts.append(">")
        for d in thin_l1:
            parts.append(f"> - `{d}`")
        parts.append("")

    detail_rows = [r for r in rows if r["new_samples"] or r["removed_samples"]]
    if detail_rows:
        parts += ["### Per-detector details", ""]
        for r in detail_rows:
            parts.append(f"<details><summary>{r['emoji']} <code>{r['detector']}</code></summary>")
            parts.append("")
            if r["new_samples"]:
                label = (
                    f"NEW findings (showing {len(r['new_samples'])} of {r['new_count']})"
                    if r["new_count"] > len(r["new_samples"])
                    else f"NEW findings ({r['new_count']})"
                )
                parts.append(f"**{label}:**")
                parts.append("")
                for s in r["new_samples"]:
                    parts.append(f"- `{truncate(s)}`")
                parts.append("")
            if r["removed_samples"]:
                label = (
                    f"REMOVED findings (showing {len(r['removed_samples'])} of {r['removed_count']})"
                    if r["removed_count"] > len(r["removed_samples"])
                    else f"REMOVED findings ({r['removed_count']})"
                )
                parts.append(f"**{label}:**")
                parts.append("")
                for s in r["removed_samples"]:
                    parts.append(f"- `{truncate(s)}`")
                parts.append("")
            parts.append("</details>")
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
    parser.add_argument("--corpus-bytes", type=int, default=0,
                        help="Total uncompressed bytes scanned; enables blast-radius column.")
    parser.add_argument("--keyword-corpus-meta", default="",
                        help="Path to build_keyword_corpus.py sidecar; surfaces thin-L1 warnings.")
    parser.add_argument("--heatmap-png", default="",
                        help="Path to heatmap PNG produced by render_heatmap.py.")
    parser.add_argument("--heatmap-artifact-url", default="",
                        help="Workflow artifact URL for the heatmap; used as fallback link "
                             "when the PNG exceeds the inline budget.")
    args = parser.parse_args()

    main_findings = load_findings(args.main_jsonl)
    pr_findings = load_findings(args.pr_jsonl)
    changed = parse_csv(args.changed_detectors)
    new_detectors = parse_csv(args.new_detectors)
    corpus_bytes = args.corpus_bytes if args.corpus_bytes > 0 else None
    keyword_meta = load_keyword_corpus_meta(args.keyword_corpus_meta)

    sys.stdout.write(render(
        main_findings,
        pr_findings,
        changed=changed if changed else None,
        new_detectors=new_detectors,
        corpus_bytes=corpus_bytes,
        keyword_meta=keyword_meta,
        heatmap_png=args.heatmap_png or None,
        heatmap_artifact_url=args.heatmap_artifact_url or None,
    ))


if __name__ == "__main__":
    main()
