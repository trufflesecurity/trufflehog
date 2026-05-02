#!/usr/bin/env python3
"""Build the Layer 1 keyword corpus by querying GitHub Code Search for the
keywords each changed detector pre-filters on.

Output is a zstd-compressed JSONL whose shape matches the S3 corpus:
each line is `{"provenance": {...}, "content": "<raw file content>"}`.
The corpora script extracts `.content` and pipes it to trufflehog via
stdin, so provenance fields are descriptive only — they aid postmortem
debugging of where a finding came from but don't reach trufflehog itself.

A sidecar meta JSON is written next to the corpus. It reports per-detector
result counts plus a `thin_l1` list of detectors whose total returned
results was zero. The diff script reads it to render a thin-coverage
callout.

Rate-limit policy:
  - Search bucket is 30 requests/minute on the authenticated search API.
  - We track X-RateLimit-Remaining and X-RateLimit-Reset on every search
    response and pre-emptively sleep when remaining < safety threshold.
  - Floor of 2.1s between consecutive search calls as belt-and-suspenders.
  - 403/429 responses: honor Retry-After / X-RateLimit-Reset, sleep, retry
    once. Two failures in a row → give up the keyword and move on.

Cap:
  - At most --max-results-per-detector unique results across all keywords
    for that detector (default 100).
  - Per-keyword sub-cap of ceil(cap / len(keywords)) so one popular
    keyword can't starve the others.
  - Identity for dedup: (repo_full_name, path, sha).

Dependencies:
  - Python stdlib only at runtime.
  - `zstd` CLI (already installed in the corpora workflow) for the final
    compression step.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


GITHUB_API = "https://api.github.com"
USER_AGENT = "trufflehog-detector-bench/0.1"
SEARCH_PER_PAGE = 100  # API max — fewer round-trips means less rate budget eaten.
SEARCH_FLOOR_SLEEP = 2.1  # seconds — 30 req/min => 2s; 0.1 of cushion.
RAW_FETCH_TIMEOUT = 20.0
SEARCH_TIMEOUT = 30.0
MAX_RAW_BYTES = 384 * 1024  # GH Code Search index ceiling; defensive cap.


@dataclass
class RateState:
    """Rate-limit state for the search bucket. Updated from every search
    response and consulted before the next call."""

    remaining: int = 30  # Optimistic; real value comes back in the first response.
    reset_epoch: float = 0.0
    last_call: float = 0.0

    def wait_before_call(self, safety: int = 2) -> None:
        """Sleep just enough to respect both the 30/min header budget and
        the per-call floor."""
        now = time.time()
        # Floor pacing.
        gap = SEARCH_FLOOR_SLEEP - (now - self.last_call)
        if gap > 0:
            time.sleep(gap)
        # Header-driven pacing.
        if self.remaining is not None and self.remaining < safety:
            now = time.time()
            wait = max(0.0, self.reset_epoch - now) + 1.0
            if wait > 0:
                print(
                    f"[rate-limit] remaining={self.remaining}, sleeping {wait:.1f}s for reset",
                    file=sys.stderr,
                )
                time.sleep(wait)
            # After the reset window expires, the bucket is full again.
            self.remaining = 30


@dataclass
class DetectorReport:
    detector: str
    keywords: list[str] = field(default_factory=list)
    fetched: int = 0
    keyword_failures: list[str] = field(default_factory=list)
    thin_l1: bool = False


def main() -> int:
    args = parse_args()

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print(
            "[build_keyword_corpus] GITHUB_TOKEN is empty; writing an empty corpus "
            "and marking all detectors thin_l1.",
            file=sys.stderr,
        )

    detectors = [d.strip() for d in args.detectors.split(",") if d.strip()]
    if not detectors:
        # Nothing changed — write empty outputs and exit cleanly so the
        # workflow can still append the path to DATASETS without a special
        # case.
        write_outputs(args.output_corpus, args.output_meta, [], {"reports": [], "thin_l1": []})
        return 0

    rate = RateState()
    reports: list[DetectorReport] = []
    corpus_lines: list[dict[str, Any]] = []
    seen_global: set[tuple[str, str, str]] = set()

    # Anything below can take time and touch the network. We want a written
    # corpus + meta sidecar regardless of whether we got partway through, so
    # downstream workflow steps stay deterministic even on fetch failures.
    try:
        run_main_loop(args, detectors, token, rate, reports, corpus_lines, seen_global)
    finally:
        summary = build_summary(reports)
        write_outputs(args.output_corpus, args.output_meta, corpus_lines, summary)
        print(
            f"[build_keyword_corpus] wrote {len(corpus_lines)} corpus lines, "
            f"{len(summary['thin_l1'])} detector(s) marked thin_l1",
            file=sys.stderr,
        )
    return 0


def build_summary(reports: list[DetectorReport]) -> dict[str, Any]:
    return {
        "reports": [
            {
                "detector": r.detector,
                "keywords": r.keywords,
                "fetched": r.fetched,
                "keyword_failures": r.keyword_failures,
                "thin_l1": r.thin_l1,
            }
            for r in reports
        ],
        "thin_l1": [r.detector for r in reports if r.thin_l1],
    }


def run_main_loop(
    args: argparse.Namespace,
    detectors: list[str],
    token: str,
    rate: RateState,
    reports: list[DetectorReport],
    corpus_lines: list[dict[str, Any]],
    seen_global: set[tuple[str, str, str]],
) -> None:
    for raw_name in detectors:
        # detect_changed_detectors.sh emits names like "github.v2"; the
        # source dir is pkg/detectors/github/v2. Strip the .v<n> suffix
        # and translate it into a /v<n> path component.
        detector_name, version_suffix = split_version(raw_name)
        package_dir = resolve_package_dir(detector_name, version_suffix, args.detectors_root)

        report = DetectorReport(detector=raw_name)
        reports.append(report)

        if package_dir is None:
            print(
                f"[build_keyword_corpus] {raw_name}: cannot resolve package dir; "
                "marking thin_l1",
                file=sys.stderr,
            )
            report.thin_l1 = True
            continue

        keywords = run_extract_keywords(args.extract_keywords_bin, package_dir)
        report.keywords = keywords
        if not keywords:
            print(
                f"[build_keyword_corpus] {raw_name}: no keywords extracted from "
                f"{package_dir}; marking thin_l1",
                file=sys.stderr,
            )
            report.thin_l1 = True
            continue

        if not token:
            report.thin_l1 = True
            continue

        per_kw_cap = max(1, math.ceil(args.max_results_per_detector / len(keywords)))
        cap_remaining = args.max_results_per_detector

        print(
            f"[build_keyword_corpus] {raw_name}: keywords={keywords} "
            f"cap={args.max_results_per_detector} per_kw_cap={per_kw_cap}",
            file=sys.stderr,
        )

        for kw in keywords:
            if cap_remaining <= 0:
                break
            try:
                added = fetch_keyword_results(
                    keyword=kw,
                    detector_label=raw_name,
                    cap_remaining=cap_remaining,
                    per_kw_cap=per_kw_cap,
                    rate=rate,
                    token=token,
                    seen_global=seen_global,
                    corpus_lines=corpus_lines,
                )
            except KeywordFetchError as exc:
                print(
                    f"[build_keyword_corpus] {raw_name}: keyword '{kw}' failed: {exc}",
                    file=sys.stderr,
                )
                report.keyword_failures.append(kw)
                continue
            except Exception as exc:  # noqa: BLE001 — last-resort, see below
                # We want partial outputs on the way out even if a fetch
                # step blows up unexpectedly. Log, mark, continue — the
                # finally block in main() still writes corpus/meta.
                print(
                    f"[build_keyword_corpus] {raw_name}: keyword '{kw}' raised "
                    f"{type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                report.keyword_failures.append(kw)
                continue
            report.fetched += added
            cap_remaining -= added

        if report.fetched == 0:
            report.thin_l1 = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--detectors",
        default=os.environ.get("DETECTORS", ""),
        help="Comma-separated detector list (matches detect_changed_detectors.sh format).",
    )
    p.add_argument(
        "--detectors-root",
        default="pkg/detectors",
        help="Path to the detectors source tree (default pkg/detectors).",
    )
    p.add_argument(
        "--extract-keywords-bin",
        default=os.environ.get("EXTRACT_KEYWORDS_BIN", "/tmp/extract-keywords"),
        help="Pre-built extract-keywords binary.",
    )
    p.add_argument(
        "--output-corpus",
        default="/tmp/keyword-corpus.jsonl.zstd",
        help="Path for the zstd-compressed JSONL corpus output.",
    )
    p.add_argument(
        "--output-meta",
        default="/tmp/keyword-corpus-meta.json",
        help="Path for the per-detector meta sidecar JSON.",
    )
    p.add_argument(
        "--max-results-per-detector",
        type=int,
        default=int(os.environ.get("KEYWORD_CORPUS_CAP", "100")),
        help="Cap on unique results fetched per detector across all keywords.",
    )
    return p.parse_args()


def split_version(name: str) -> tuple[str, str]:
    """`jdbc` → ('jdbc', ''); `github.v2` → ('github', 'v2')."""
    if "." in name:
        base, _, ver = name.partition(".")
        return base, ver
    return name, ""


def resolve_package_dir(name: str, version: str, root: str) -> str | None:
    """Map a detector identifier back to its package directory.

    detect_changed_detectors.sh emits the proto-enum name (lowercase), but
    package directory names sometimes diverge (e.g. proto NpmToken lives in
    pkg/detectors/npmtoken). When the simple lowercase mapping doesn't
    exist we fall through with None and let the caller mark thin_l1 — this
    is correct semantics: we couldn't find data for this detector, surface
    it as thin coverage rather than failing the workflow.
    """
    candidates = [name]
    if version:
        candidates = [os.path.join(c, version) for c in candidates]
    for c in candidates:
        path = os.path.join(root, c)
        if os.path.isdir(path):
            return path
    return None


def run_extract_keywords(binary: str, package_dir: str) -> list[str]:
    if not os.path.isfile(binary):
        print(
            f"[build_keyword_corpus] extract-keywords binary not found at {binary}",
            file=sys.stderr,
        )
        return []
    try:
        out = subprocess.run(
            [binary, package_dir],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[build_keyword_corpus] extract-keywords timed out on {package_dir}", file=sys.stderr)
        return []
    if out.returncode != 0:
        if out.stderr.strip():
            print(out.stderr.strip(), file=sys.stderr)
        return []
    try:
        loaded = json.loads(out.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [k for k in loaded if isinstance(k, str) and k]


class KeywordFetchError(Exception):
    """Wraps a fatal failure for a single keyword lookup."""


def fetch_keyword_results(
    *,
    keyword: str,
    detector_label: str,
    cap_remaining: int,
    per_kw_cap: int,
    rate: RateState,
    token: str,
    seen_global: set[tuple[str, str, str]],
    corpus_lines: list[dict[str, Any]],
) -> int:
    """Returns the number of new corpus lines added for this keyword."""
    added = 0
    page = 1
    while added < per_kw_cap and (cap_remaining - added) > 0:
        items, has_more = search_code(keyword, page, rate, token)
        if not items:
            break
        for item in items:
            if added >= per_kw_cap or (cap_remaining - added) <= 0:
                break
            repo = (item.get("repository") or {}).get("full_name") or ""
            path = item.get("path") or ""
            sha = item.get("sha") or ""
            key = (repo, path, sha)
            if not repo or not path or key in seen_global:
                continue
            download_url = item.get("html_url")
            # `git_url` (blob API) is the canonical content source; fall
            # back to constructing a raw URL from the html_url when blob is
            # absent. Keep both candidates for robustness.
            raw_candidates = build_raw_candidates(item)
            content = fetch_first_ok(raw_candidates, token=token)
            if content is None:
                continue
            seen_global.add(key)
            corpus_lines.append(
                {
                    "provenance": {
                        "layer": "L1",
                        "detector": detector_label,
                        "keyword": keyword,
                        "repo": repo,
                        "path": path,
                        "sha": sha,
                        "url": download_url or "",
                    },
                    "content": content,
                }
            )
            added += 1
        if not has_more:
            break
        page += 1
    return added


def search_code(
    keyword: str,
    page: int,
    rate: RateState,
    token: str,
) -> tuple[list[dict[str, Any]], bool]:
    """Single page of GitHub Code Search. Returns (items, has_more).

    `has_more` is True iff the response yielded a full page of results,
    indicating the next page may have content. Using the size of the
    returned items list (vs. parsing the total_count field) avoids
    overshooting the 1000-result hard cap that the search API enforces.
    """
    qs = urllib.parse.urlencode(
        {"q": keyword, "per_page": SEARCH_PER_PAGE, "page": page}
    )
    url = f"{GITHUB_API}/search/code?{qs}"
    body, headers = github_request(
        url,
        token=token,
        accept="application/vnd.github.v3+json",
        rate=rate,
        is_search=True,
    )
    update_rate(rate, headers)
    if body is None:
        return [], False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], False
    items = data.get("items") or []
    has_more = len(items) >= SEARCH_PER_PAGE
    return items, has_more


def build_raw_candidates(item: dict[str, Any]) -> list[str]:
    """Build candidate raw-content URLs from a code-search hit.

    The search API doesn't return a direct raw URL — `html_url` points at
    the GitHub web UI. Translate it to raw.githubusercontent.com by
    replacing `/blob/` with the raw host. Also include the `git_url` blob
    API URL as a backup; that path is on the core 5000/hr token bucket
    rather than the 30/min search bucket, so it's a safer fallback when
    raw.githubusercontent.com gives us trouble.
    """
    out: list[str] = []
    html_url = item.get("html_url") or ""
    if html_url and "/blob/" in html_url:
        raw = (
            html_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1)
            .replace("/blob/", "/", 1)
        )
        out.append(raw)
    git_url = item.get("git_url") or ""
    if git_url:
        out.append(git_url)  # GET on this returns a JSON envelope with base64 content.
    return out


def fetch_first_ok(urls: list[str], *, token: str) -> str | None:
    """Try each candidate URL in order and return the first successful
    body, or None if all fail. The blob-API form returns a JSON envelope
    that we decode separately."""
    for url in urls:
        try:
            if url.startswith("https://raw.githubusercontent.com/"):
                req = urllib.request.Request(url, headers=raw_headers(token))
                with urllib.request.urlopen(req, timeout=RAW_FETCH_TIMEOUT) as resp:
                    data = resp.read(MAX_RAW_BYTES + 1)
                    if len(data) > MAX_RAW_BYTES:
                        return None
                    return decode_text(data)
            # Blob API path: fetch JSON, base64-decode `content`.
            body, _headers = github_request(
                url,
                token=token,
                accept="application/vnd.github.v3+json",
                rate=None,
                is_search=False,
            )
            if not body:
                continue
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                continue
            if (payload.get("encoding") or "").lower() == "base64":
                import base64

                raw = base64.b64decode(payload.get("content") or "")
                if len(raw) > MAX_RAW_BYTES:
                    return None
                return decode_text(raw)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            continue
    return None


def github_request(
    url: str,
    *,
    token: str,
    accept: str,
    rate: RateState | None,
    is_search: bool,
    max_retries: int = 1,
) -> tuple[str | None, dict[str, str]]:
    """Issue a GitHub API request, honoring rate-limit pacing for searches
    and retrying once on 403/429 if the headers indicate a wait window.
    Returns (body, headers) — body is None on hard failure."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    attempt = 0
    while True:
        if is_search and rate is not None:
            rate.wait_before_call()
            rate.last_call = time.time()
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=SEARCH_TIMEOUT) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read().decode("utf-8", errors="replace")
                return body, response_headers
        except urllib.error.HTTPError as exc:
            response_headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            if exc.code in (403, 429) and attempt < max_retries:
                wait = compute_retry_wait(response_headers)
                print(
                    f"[rate-limit] {exc.code} on {url}; sleeping {wait:.1f}s",
                    file=sys.stderr,
                )
                time.sleep(wait)
                attempt += 1
                continue
            print(f"[github_request] {exc.code} on {url}: giving up", file=sys.stderr)
            return None, response_headers
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < max_retries:
                time.sleep(2.0)
                attempt += 1
                continue
            print(f"[github_request] transport error on {url}: {exc}", file=sys.stderr)
            return None, {}
        except ValueError as exc:
            # Malformed header (typically a corrupt token) — no point retrying.
            print(f"[github_request] invalid request for {url}: {exc}", file=sys.stderr)
            return None, {}


def compute_retry_wait(headers: dict[str, str]) -> float:
    """Honor Retry-After (seconds) when present, else fall back to
    X-RateLimit-Reset; floor at 1 second so we always make forward
    progress even if the headers are wrong/missing."""
    if "retry-after" in headers:
        try:
            return max(1.0, float(headers["retry-after"]))
        except ValueError:
            pass
    reset = headers.get("x-ratelimit-reset")
    if reset:
        try:
            wait = float(reset) - time.time() + 1.0
            return max(1.0, wait)
        except ValueError:
            pass
    return 60.0


def update_rate(rate: RateState, headers: dict[str, str]) -> None:
    rem = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if rem is not None:
        try:
            rate.remaining = int(rem)
        except ValueError:
            pass
    if reset is not None:
        try:
            rate.reset_epoch = float(reset)
        except ValueError:
            pass


def raw_headers(token: str) -> dict[str, str]:
    h = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3.raw"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def decode_text(data: bytes) -> str:
    """UTF-8 with replacement; raw blobs may contain odd bytes but trufflehog
    consumes the JSON-extracted .content as text via stdin so we want a
    valid string regardless."""
    return data.decode("utf-8", errors="replace")


def write_outputs(
    output_corpus: str,
    output_meta: str,
    corpus_lines: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    """Write the JSONL corpus, compress it with zstd, and write the meta
    sidecar. zstd is invoked as a subprocess so we don't depend on a Python
    extension module — the `zstd` CLI is already installed in the corpora
    workflow."""
    # 1. Plain JSONL → temp file.
    if output_corpus.endswith(".zstd"):
        tmp_jsonl = output_corpus[: -len(".zstd")]
    elif output_corpus.endswith(".zst"):
        tmp_jsonl = output_corpus[: -len(".zst")]
    else:
        tmp_jsonl = output_corpus + ".jsonl"
    with open(tmp_jsonl, "w", encoding="utf-8") as f:
        for line in corpus_lines:
            f.write(json.dumps(line, ensure_ascii=False))
            f.write("\n")

    # 2. zstd compress in place.
    if output_corpus.endswith(".zstd") or output_corpus.endswith(".zst"):
        try:
            subprocess.run(
                ["zstd", "-q", "-f", "-o", output_corpus, tmp_jsonl],
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[build_keyword_corpus] zstd compression failed: {exc}", file=sys.stderr)
            raise
        os.unlink(tmp_jsonl)
    else:
        # Caller asked for an uncompressed output; leave it alone.
        os.replace(tmp_jsonl, output_corpus)

    # 3. Sidecar meta.
    with open(output_meta, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    sys.exit(main())
