#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re


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
