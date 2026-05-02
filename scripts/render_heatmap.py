#!/usr/bin/env python3
"""Render a per-(detector, decoder) Δ heatmap of detector findings.

Inputs are the same JSONL files produced by trufflehog stdin scans that
``diff_corpora_results.py`` consumes (main vs PR). The diff script identifies
findings by ``(DetectorName, Raw or RawV2)`` with set semantics; the heatmap
keeps that identity but adds ``DecoderName`` to the bucketing key, so each
cell answers "how many unique secrets did this (detector, decoder) cell gain
or lose?"

Bucketing rationale (Phase 4 design decision):

  Stdin scans drop file metadata — both Layer 0 (S3 corpus) and Layer 1
  (keyword corpus) findings come back with empty ``SourceMetadata.Data.Stdin``,
  so we can't bucket by file extension. ``DecoderName`` is the only stable
  per-finding signal that always exists, and it carries real diagnostic
  meaning: "the regression came in via the BASE64 decode path" or "the
  ESCAPED_UNICODE path lit up new false positives" tells reviewers which
  lane to investigate. Robust-by-construction beats heuristic-on-Raw or
  reverse-correlation-on-L1.

Visual choices:

  - Diverging RdBu_r colormap: red = increase (regression-likely), blue =
    decrease (lost recall), white = 0.
  - SymLogNorm: cells with Δ=1 in a rare decoder remain visible even when a
    sibling cell has Δ=200 in PLAIN. Linear band around 0 keeps the white
    "no change" reading; log-ish outside it preserves the rare-decoder
    diagnostic. Without this, common-decoder outliers wash out small but
    important signals.
  - Every cell is annotated with its integer Δ. Belt-and-suspenders against
    color-only readings.
  - Empty decoder columns (no findings on either side for any changed
    detector) are dropped — no need to render dead space.

Identity bucketing:

  identity := (DecoderName, Raw or RawV2)
  per-cell Δ := |pr_only| - |main_only|

  Note this is a stricter identity than the summary table's
  ``(DetectorName, Raw or RawV2)``: a single secret found via both PLAIN
  and BASE64 contributes one identity to the table but two to the heatmap.
  That's the desired behavior — the heatmap diagnoses *which decoder path
  changed*, not *how many distinct secrets changed overall*.

Outputs:

  - PNG (``--output``, default /tmp/heatmap.png): the matplotlib render.
    Archived as a workflow artifact for reviewers who want the colored
    version; not embedded inline in the comment because GitHub's
    Markdown sanitizer strips ``data:`` URLs and artifact-zip URLs are
    auth-gated, neither of which renders as ``<img>`` in PR comments.

  - Grid JSON (``--grid-output``, default /tmp/heatmap-grid.json): same
    Δ matrix as the PNG. The diff script reads this and renders an
    emoji-bucketed Markdown table — that's what actually shows up in the
    PR comment. Always emitted when a non-empty grid exists, even if
    matplotlib isn't available, so the comment renders without the PNG
    if needed.

Skips both outputs (no files written) when the grid would be all-zero or
empty. The diff script handles missing files gracefully.

Usage:
    render_heatmap.py <main.jsonl> <pr.jsonl> --changed-detectors=<csv>
        [--output=/tmp/heatmap.png]
        [--grid-output=/tmp/heatmap-grid.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict


# Standard decoders emitted by trufflehog. Ordered by expected frequency so
# the heatmap reads left-to-right common→rare. Any decoder not in this list
# falls through to alphabetical ordering after the canonical ones.
DECODER_ORDER = ["PLAIN", "BASE64", "UTF8", "UTF16", "ESCAPED_UNICODE"]


def parse_csv(s):
    """Lowercase + strip ``.v<n>`` suffix, mirrors diff_corpora_results.parse_csv."""
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
    """Returns dict: detector -> dict[decoder] -> set(raw identities)."""
    by_dd = defaultdict(lambda: defaultdict(set))
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return by_dd
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = obj.get("DetectorName") or ""
            decoder = obj.get("DecoderName") or "UNKNOWN"
            raw = obj.get("Raw") or obj.get("RawV2") or ""
            if not detector or not raw:
                continue
            by_dd[detector][decoder].add(raw)
    return by_dd


def order_decoders(present):
    """PLAIN/BASE64/... first when present, then any extras alphabetically."""
    canonical = [d for d in DECODER_ORDER if d in present]
    extras = sorted(d for d in present if d not in DECODER_ORDER)
    return canonical + extras


def build_grid(main, pr, changed):
    """Returns (rows, cols, deltas) where deltas[i][j] is the signed Δ count
    for row detector i and column decoder j. Detectors and decoders that
    never appear on either side are dropped."""
    detectors = sorted(
        d for d in (set(main) | set(pr))
        if d.lower() in changed
    )

    decoders_present = set()
    for d in detectors:
        decoders_present.update(main.get(d, {}).keys())
        decoders_present.update(pr.get(d, {}).keys())
    decoders = order_decoders(decoders_present)

    deltas = []
    row_abs_totals = []
    for d in detectors:
        row = []
        row_abs = 0
        for dec in decoders:
            m_set = main.get(d, {}).get(dec, set())
            p_set = pr.get(d, {}).get(dec, set())
            delta = len(p_set - m_set) - len(m_set - p_set)
            row.append(delta)
            row_abs += abs(delta)
        deltas.append(row)
        row_abs_totals.append(row_abs)

    # Drop columns that are zero across every detector — they add no signal.
    keep_cols = [j for j in range(len(decoders))
                 if any(deltas[i][j] != 0 for i in range(len(detectors)))]
    if not keep_cols:
        return detectors, [], []
    decoders = [decoders[j] for j in keep_cols]
    deltas = [[row[j] for j in keep_cols] for row in deltas]

    # Sort rows by total |Δ| desc, ties broken alphabetically. Detectors with
    # no Δ in any kept column drop off the bottom of the figure.
    order = sorted(
        range(len(detectors)),
        key=lambda i: (-row_abs_totals[i], detectors[i]),
    )
    detectors = [detectors[i] for i in order if row_abs_totals[i] > 0]
    deltas = [deltas[i] for i in order if row_abs_totals[i] > 0]

    return detectors, decoders, deltas


def render(detectors, decoders, deltas, output_path):
    """Write the heatmap PNG. Caller has already verified the grid is non-empty."""
    # Lazy import: this script is only invoked from the workflow when
    # matplotlib has been pip-installed in CI; importing at module top would
    # break unit-test-style invocations that just want to assert grid shape.
    import matplotlib

    matplotlib.use("Agg")  # No display in CI.
    import matplotlib.pyplot as plt
    from matplotlib.colors import SymLogNorm

    n_rows = len(detectors)
    n_cols = len(decoders)

    # Figure size: aim for a tight PNG well under the 50 KB inline budget.
    # Width scales with column count; height scales with row count, with
    # generous lower bounds so labels don't clip on tiny grids.
    width = max(5.5, 1.4 * n_cols + 2.5)
    height = max(2.5, 0.55 * n_rows + 1.6)
    fig, ax = plt.subplots(figsize=(width, height), dpi=100)

    max_abs = max((abs(v) for row in deltas for v in row), default=1)
    if max_abs < 1:
        max_abs = 1
    # SymLogNorm linthresh=1 keeps integer Δ in [-1,1] in the linear band so
    # zero stays white; outside that we go log-ish so a Δ=200 cell doesn't
    # saturate everything else to faint pastel.
    norm = SymLogNorm(linthresh=1.0, vmin=-max_abs, vmax=max_abs, base=10)

    im = ax.imshow(deltas, aspect="auto", cmap="RdBu_r", norm=norm)

    ax.set_xticks(range(n_cols))
    ax.set_xticklabels(decoders, rotation=30, ha="right", fontsize=9)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(detectors, fontsize=9)
    ax.set_xlabel("Decoder", fontsize=10)
    ax.set_ylabel("Detector", fontsize=10)
    ax.set_title("PR vs main — Δ unique findings per (detector, decoder)", fontsize=11)

    # Annotate every cell with its integer Δ. Text color flips to white
    # on saturated cells so the number stays readable.
    for i in range(n_rows):
        for j in range(n_cols):
            v = deltas[i][j]
            if v == 0:
                label = "0"
                color = "#888888"
            else:
                label = f"{v:+d}"
                rgba = im.cmap(im.norm(v))
                # Perceived luminance — flip text color on dark cells.
                lum = 0.299 * rgba[0] + 0.587 * rgba[1] + 0.114 * rgba[2]
                color = "white" if lum < 0.45 else "black"
            ax.text(j, i, label, ha="center", va="center",
                    color=color, fontsize=9)

    cbar = fig.colorbar(im, ax=ax, shrink=0.85, pad=0.02)
    cbar.set_label("Δ unique findings (PR − main)", fontsize=9)
    cbar.ax.tick_params(labelsize=8)

    fig.tight_layout()
    fig.savefig(output_path, dpi=100, format="png",
                bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def write_grid_json(path, detectors, decoders, deltas):
    """Persist the grid the diff script renders the emoji table from.

    The ``_layout`` field is a human-readable note for future readers — it
    has no behavioral effect. We emit it inline rather than relying solely
    on this docstring because the JSON is the long-lived contract between
    the renderer and the diff script.
    """
    payload = {
        "detectors": detectors,
        "decoders": decoders,
        "deltas": deltas,
        "_layout": "deltas[i][j] = (PR - main) unique-finding count for detectors[i] / decoders[j]",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def try_render_png(detectors, decoders, deltas, output_path):
    """Attempt to render the PNG; on matplotlib import failure, log and
    move on. The PNG is artifact-only — the comment doesn't need it — so a
    missing matplotlib should not fail the workflow."""
    try:
        render(detectors, decoders, deltas, output_path)
    except ImportError as exc:
        print(f"[render_heatmap] matplotlib unavailable, skipping PNG: {exc}",
              file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("main_jsonl")
    parser.add_argument("pr_jsonl")
    parser.add_argument("--changed-detectors", default="",
                        help="CSV of detectors changed in PR; restricts heatmap rows.")
    parser.add_argument("--output", default="/tmp/heatmap.png",
                        help="PNG output path (default /tmp/heatmap.png).")
    parser.add_argument("--grid-output", default="/tmp/heatmap-grid.json",
                        help="Grid JSON output path; consumed by diff_corpora_results.py.")
    args = parser.parse_args()

    changed = parse_csv(args.changed_detectors)
    if not changed:
        print("[render_heatmap] no changed detectors supplied; nothing to render",
              file=sys.stderr)
        return 0

    main_findings = load_findings(args.main_jsonl)
    pr_findings = load_findings(args.pr_jsonl)
    detectors, decoders, deltas = build_grid(main_findings, pr_findings, changed)

    if not detectors or not decoders:
        print("[render_heatmap] grid is empty or all-zero; skipping render",
              file=sys.stderr)
        return 0

    write_grid_json(args.grid_output, detectors, decoders, deltas)
    png_ok = try_render_png(detectors, decoders, deltas, args.output)
    suffix = f" + {args.output}" if png_ok else " (PNG skipped)"
    print(f"[render_heatmap] wrote {args.grid_output}{suffix} "
          f"({len(detectors)} rows × {len(decoders)} cols)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
