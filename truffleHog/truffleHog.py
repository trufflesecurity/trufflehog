#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import datetime
import argparse
import uuid
import hashlib
import os
import re
import json
import tempfile
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes
from truffleHog.utils import BColors, str2bool, get_rules, get_path_inclusions
from truffleHog.utils import shannon_entropy, clone_git_repo, del_rw


def path_included(blob, include_patterns=None, exclude_patterns=None):
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True


def is_line_disabled(line):
    """find a comment like # pylint: disable=no-member
    not-a-secret
    and send true if exist."""
    return re.search(r"\s*not-a-secret", line)


def regex_check(
    printableDiff,
    commit_time,
    branch_name,
    prev_commit,
    blob,
    commit_hash,
    custom_regexes={},
):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(
                printableDiff, BColors.WARNING + found_string + BColors.ENDC
            )
        if found_strings:
            foundRegex = {}
            foundRegex["date"] = commit_time
            foundRegex["path"] = blob.b_path if blob.b_path else blob.a_path
            foundRegex["branch"] = branch_name
            foundRegex["commit"] = prev_commit.message
            foundRegex["diff"] = blob.diff.decode("utf-8", errors="replace")
            foundRegex["stringsFound"] = found_strings
            foundRegex["printDiff"] = found_diff
            foundRegex["reason"] = key
            foundRegex["commit_hash"] = commit_hash
            regex_matches.append(foundRegex)
    return regex_matches
