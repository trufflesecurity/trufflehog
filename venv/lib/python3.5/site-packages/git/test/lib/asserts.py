# asserts.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import stat

from nose.tools import (
    assert_equal,       # @UnusedImport
    assert_not_equal,   # @UnusedImport
    assert_raises,      # @UnusedImport
    raises,             # @UnusedImport
    assert_true,        # @UnusedImport
    assert_false        # @UnusedImport
)

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch  # @NoMove @UnusedImport

__all__ = ['assert_instance_of', 'assert_not_instance_of',
           'assert_none', 'assert_not_none',
           'assert_match', 'assert_not_match', 'assert_mode_644',
           'assert_mode_755',
           'assert_equal', 'assert_not_equal', 'assert_raises', 'patch', 'raises',
           'assert_true', 'assert_false']


def assert_instance_of(expected, actual, msg=None):
    """Verify that object is an instance of expected """
    assert isinstance(actual, expected), msg


def assert_not_instance_of(expected, actual, msg=None):
    """Verify that object is not an instance of expected """
    assert not isinstance(actual, expected, msg)


def assert_none(actual, msg=None):
    """verify that item is None"""
    assert actual is None, msg


def assert_not_none(actual, msg=None):
    """verify that item is None"""
    assert actual is not None, msg


def assert_match(pattern, string, msg=None):
    """verify that the pattern matches the string"""
    assert_not_none(re.search(pattern, string), msg)


def assert_not_match(pattern, string, msg=None):
    """verify that the pattern does not match the string"""
    assert_none(re.search(pattern, string), msg)


def assert_mode_644(mode):
    """Verify given mode is 644"""
    assert (mode & stat.S_IROTH) and (mode & stat.S_IRGRP)
    assert (mode & stat.S_IWUSR) and (mode & stat.S_IRUSR) and not (mode & stat.S_IXUSR)


def assert_mode_755(mode):
    """Verify given mode is 755"""
    assert (mode & stat.S_IROTH) and (mode & stat.S_IRGRP) and (mode & stat.S_IXOTH) and (mode & stat.S_IXGRP)
    assert (mode & stat.S_IWUSR) and (mode & stat.S_IRUSR) and (mode & stat.S_IXUSR)
