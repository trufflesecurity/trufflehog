#!/usr/bin/env python3
"""Verify the two golangci-lint version pins agree, and that Renovate can see both.

golangci-lint is pinned twice: as the `version` input to golangci-lint-action in
.github/workflows/lint.yml, and as GOLANGCI_LINT_VERSION in scripts/lint.sh. Both
files carry a NOTE comment saying the two must match, but until this check existed
nothing enforced it, and the pins drifted twice -- once leaving the workflow on
v2.12.2 while the script stayed on v2.11.4, and again leaving the script on v2.12.2
after the workflow moved to v2.13.1. The second drift was more than cosmetic: go1.27
support arrived in golangci-lint v2.13.0, so `make lint` on the stale pin failed
outright for anyone on that toolchain.

Renovate's github-actions manager reads the workflow pin. Nothing built in reads a
shell variable, so .github/renovate.json carries a regex custom manager for
scripts/lint.sh. That closes the bumping gap but introduces a quieter one: a regex
that stops matching *fails open*. Renovate reports no dependency rather than an
error, so reshaping that assignment -- switching to single quotes, wrapping it in
`readonly`, interpolating it -- would silently return us to bumping the workflow
alone, with nothing to notice.

This check therefore does two things:

  1. Asserts the two pins are equal and concrete, which catches drift however it
     arrives -- including a hand edit Renovate was never involved in.
  2. Applies the regex configured in .github/renovate.json to scripts/lint.sh and
     requires it to match, so the custom manager cannot quietly stop tracking the
     file it exists to track.

Exits non-zero with an explanation on the first problem found.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path

DEP_NAME = "golangci/golangci-lint"
SCRIPT_PATH = "scripts/lint.sh"
WORKFLOW_PATH = ".github/workflows/lint.yml"
RENOVATE_PATH = ".github/renovate.json"

# A pin must be a full major.minor.patch. Rejecting only "latest" is not enough:
# a partial tag such as "v2" floats just as much while reading like a pin.
SEMVER = re.compile(r"^v?\d+\.\d+\.\d+$")

REPO_ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def read(relative_path: str) -> str:
    path = REPO_ROOT / relative_path
    if not path.is_file():
        fail(f"{relative_path} not found.")
    return path.read_text()


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Apply one Renovate managerFilePatterns entry to a repository-relative path.

    Renovate treats a pattern wrapped in slashes as a regex and anything else as a
    glob, so both spellings are honored here rather than assuming the current one.
    """
    if len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/"):
        try:
            return re.search(pattern[1:-1], path) is not None
        except re.error as error:
            fail(
                f"the '{DEP_NAME}' customManager in {RENOVATE_PATH} has a "
                f"managerFilePatterns entry that is not a valid regex: {pattern} ({error})"
            )
    return fnmatch.fnmatch(path, pattern)


def extract_sole_match(pattern: re.Pattern[str], text: str, description: str) -> re.Match[str]:
    """Require exactly one match. A second means the pattern now covers something else."""
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(
            f"expected exactly one {description}, found {len(matches)} — "
            "make this check's pattern more specific, or remove the duplicate pin."
        )
    return matches[0]


def load_custom_manager(renovate_config: dict) -> dict:
    managers = [
        manager
        for manager in renovate_config.get("customManagers", [])
        if manager.get("customType") == "regex"
        and manager.get("depNameTemplate") == DEP_NAME
    ]
    if len(managers) != 1:
        fail(
            f"{RENOVATE_PATH} must define exactly one regex customManager with "
            f"depNameTemplate '{DEP_NAME}', found {len(managers)}. That manager is what "
            f"lets Renovate see the pin in {SCRIPT_PATH}; without it the bot bumps "
            f"{WORKFLOW_PATH} alone and the two pins drift."
        )
    return managers[0]


def script_pin_from_renovate_regex(manager: dict) -> str:
    """Apply the manager's own regex to scripts/lint.sh and return what it captures."""
    datasource = manager.get("datasourceTemplate", "")
    if datasource != "github-releases":
        fail(
            f"the '{DEP_NAME}' customManager in {RENOVATE_PATH} must use the "
            f"'github-releases' datasource, found '{datasource or '<unset>'}'. The workflow "
            "pin resolves against GitHub release tags, so the script pin has to resolve the "
            "same way or the two can be offered different versions."
        )

    file_patterns = manager.get("managerFilePatterns", [])
    if not any(path_matches_pattern(SCRIPT_PATH, pattern) for pattern in file_patterns):
        fail(
            f"the '{DEP_NAME}' customManager in {RENOVATE_PATH} must target {SCRIPT_PATH} "
            f"through managerFilePatterns. It currently targets: {file_patterns}."
        )

    match_strings = manager.get("matchStrings", [])
    if len(match_strings) != 1:
        fail(
            f"the '{DEP_NAME}' customManager in {RENOVATE_PATH} must declare exactly one "
            f"matchStrings entry, found {len(match_strings)}. This check applies that single "
            "pattern to the script; with several it cannot tell which one is meant to match."
        )
    match_string = match_strings[0]

    if "(?<currentValue>" not in match_string:
        fail(
            f"the '{DEP_NAME}' matchStrings pattern in {RENOVATE_PATH} must capture the "
            "version in a named group '(?<currentValue>...)'. Renovate uses that group to "
            f"decide which substring to rewrite. Pattern: {match_string}"
        )

    # Renovate matches with RE2, which accepts both (?<name>) and (?P<name>);
    # Python's re accepts only the latter. Renaming the group is the whole
    # translation -- it does not change what the pattern matches.
    try:
        compiled = re.compile(match_string.replace("(?<currentValue>", "(?P<currentValue>"))
    except re.error as error:
        fail(
            f"the '{DEP_NAME}' matchStrings pattern in {RENOVATE_PATH} does not compile: "
            f"{error}. Pattern: {match_string}"
        )

    script_text = read(SCRIPT_PATH)
    matches = list(compiled.finditer(script_text))
    if len(matches) != 1:
        fail(
            f"the '{DEP_NAME}' matchStrings pattern from {RENOVATE_PATH} matched "
            f"{len(matches)} times in {SCRIPT_PATH}, expected exactly 1. Renovate reports no "
            "dependency when its regex stops matching, so it would quietly resume bumping "
            f"{WORKFLOW_PATH} alone. Re-sync the pattern with the GOLANGCI_LINT_VERSION "
            f"assignment. Pattern: {match_string}"
        )
    return matches[0].group("currentValue")


def require_group_rule(renovate_config: dict) -> None:
    for rule in renovate_config.get("packageRules", []):
        if DEP_NAME in rule.get("matchDepNames", []) and rule.get("groupName"):
            return
    fail(
        f"{RENOVATE_PATH} must contain a packageRule matching depName '{DEP_NAME}' and "
        "setting a groupName. The shared preset groups all github-actions updates into one "
        "PR, so without this rule the workflow pin and the script pin land in separate PRs "
        "and whichever merges first leaves the pins drifted."
    )


def main() -> None:
    try:
        renovate_config = json.loads(read(RENOVATE_PATH))
    except json.JSONDecodeError as error:
        fail(f"{RENOVATE_PATH} is not valid JSON: {error}")

    manager = load_custom_manager(renovate_config)
    script_version = script_pin_from_renovate_regex(manager)
    require_group_rule(renovate_config)

    # The workflow pin is read straight out of the YAML text rather than parsed,
    # to keep this check dependency-free on a bare runner.
    workflow_match = extract_sole_match(
        re.compile(r"^[ \t]*version:[ \t]*(?P<version>\S+)", re.MULTILINE),
        read(WORKFLOW_PATH),
        f"golangci-lint 'version:' key in {WORKFLOW_PATH}",
    )
    workflow_version = workflow_match.group("version")

    for label, path, version in (
        ("workflow", WORKFLOW_PATH, workflow_version),
        ("script", SCRIPT_PATH, script_version),
    ):
        if not SEMVER.match(version):
            fail(
                f"{path} must pin golangci-lint to a concrete vX.Y.Z release, found "
                f"'{version}'. A floating value such as 'latest' or 'v2' lets the linter "
                f"change under a branch that did not change ({label} pin)."
            )

    if workflow_version != script_version:
        fail(
            f"golangci-lint is pinned to '{workflow_version}' in {WORKFLOW_PATH} but "
            f"'{script_version}' in {SCRIPT_PATH}. Bump both together, or local `make lint` "
            "and the CI lint job will disagree about what counts as a finding. Renovate is "
            "configured to move them in one PR; if only one moved, check the customManager "
            f"in {RENOVATE_PATH}."
        )

    print(f"golangci-lint pins agree ({workflow_version}), and Renovate tracks both.")


if __name__ == "__main__":
    main()
