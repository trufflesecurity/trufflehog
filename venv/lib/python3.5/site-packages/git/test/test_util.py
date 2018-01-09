# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import tempfile
import time
try:
    from unittest import skipIf
except ImportError:
    from unittest2 import skipIf


import ddt

from git.cmd import dashify
from git.compat import string_types, is_win
from git.objects.util import (
    altz_to_utctz_str,
    utctz_to_altz,
    verify_utctz,
    parse_date,
)
from git.test.lib import (
    TestBase,
    assert_equal
)
from git.util import (
    LockFile,
    BlockingLockFile,
    get_user_id,
    Actor,
    IterableList,
    cygpath,
    decygpath
)


_norm_cygpath_pairs = (
    (r'foo\bar', 'foo/bar'),
    (r'foo/bar', 'foo/bar'),

    (r'C:\Users', '/cygdrive/c/Users'),
    (r'C:\d/e', '/cygdrive/c/d/e'),

    ('C:\\', '/cygdrive/c/'),

    (r'\\server\C$\Users', '//server/C$/Users'),
    (r'\\server\C$', '//server/C$'),
    ('\\\\server\\c$\\', '//server/c$/'),
    (r'\\server\BAR/', '//server/BAR/'),

    (r'D:/Apps', '/cygdrive/d/Apps'),
    (r'D:/Apps\fOO', '/cygdrive/d/Apps/fOO'),
    (r'D:\Apps/123', '/cygdrive/d/Apps/123'),
)

_unc_cygpath_pairs = (
    (r'\\?\a:\com', '/cygdrive/a/com'),
    (r'\\?\a:/com', '/cygdrive/a/com'),

    (r'\\?\UNC\server\D$\Apps', '//server/D$/Apps'),
)


class TestIterableMember(object):

    """A member of an iterable list"""
    __slots__ = "name"

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "TestIterableMember(%r)" % self.name


@ddt.ddt
class TestUtils(TestBase):

    def setup(self):
        self.testdict = {
            "string": "42",
            "int": 42,
            "array": [42],
        }

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.idata(_norm_cygpath_pairs + _unc_cygpath_pairs)
    def test_cygpath_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath, wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.data(
        (r'./bar', 'bar'),
        (r'.\bar', 'bar'),
        (r'../bar', '../bar'),
        (r'..\bar', '../bar'),
        (r'../bar/.\foo/../chu', '../bar/chu'),
    )
    def test_cygpath_norm_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath or wpath, wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.data(
        r'C:',
        r'C:Relative',
        r'D:Apps\123',
        r'D:Apps/123',
        r'\\?\a:rel',
        r'\\share\a:rel',
    )
    def test_cygpath_invalids(self, wpath):
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, wpath.replace('\\', '/'), wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.idata(_norm_cygpath_pairs)
    def test_decygpath(self, case):
        wpath, cpath = case
        wcpath = decygpath(cpath)
        self.assertEqual(wcpath, wpath.replace('/', '\\'), cpath)

    def test_it_should_dashify(self):
        assert_equal('this-is-my-argument', dashify('this_is_my_argument'))
        assert_equal('foo', dashify('foo'))

    def test_lock_file(self):
        my_file = tempfile.mktemp()
        lock_file = LockFile(my_file)
        assert not lock_file._has_lock()
        # release lock we don't have  - fine
        lock_file._release_lock()

        # get lock
        lock_file._obtain_lock_or_raise()
        assert lock_file._has_lock()

        # concurrent access
        other_lock_file = LockFile(my_file)
        assert not other_lock_file._has_lock()
        self.failUnlessRaises(IOError, other_lock_file._obtain_lock_or_raise)

        lock_file._release_lock()
        assert not lock_file._has_lock()

        other_lock_file._obtain_lock_or_raise()
        self.failUnlessRaises(IOError, lock_file._obtain_lock_or_raise)

        # auto-release on destruction
        del(other_lock_file)
        lock_file._obtain_lock_or_raise()
        lock_file._release_lock()

    def test_blocking_lock_file(self):
        my_file = tempfile.mktemp()
        lock_file = BlockingLockFile(my_file)
        lock_file._obtain_lock()

        # next one waits for the lock
        start = time.time()
        wait_time = 0.1
        wait_lock = BlockingLockFile(my_file, 0.05, wait_time)
        self.failUnlessRaises(IOError, wait_lock._obtain_lock)
        elapsed = time.time() - start
        extra_time = 0.02
        if is_win:
            # for Appveyor
            extra_time *= 6  # NOTE: Indeterministic failures here...
        self.assertLess(elapsed, wait_time + extra_time)

    def test_user_id(self):
        self.assertIn('@', get_user_id())

    def test_parse_date(self):
        # test all supported formats
        def assert_rval(rval, veri_time, offset=0):
            self.assertEqual(len(rval), 2)
            self.assertIsInstance(rval[0], int)
            self.assertIsInstance(rval[1], int)
            self.assertEqual(rval[0], veri_time)
            self.assertEqual(rval[1], offset)

            # now that we are here, test our conversion functions as well
            utctz = altz_to_utctz_str(offset)
            self.assertIsInstance(utctz, string_types)
            self.assertEqual(utctz_to_altz(verify_utctz(utctz)), offset)
        # END assert rval utility

        rfc = ("Thu, 07 Apr 2005 22:13:11 +0000", 0)
        iso = ("2005-04-07T22:13:11 -0200", 7200)
        iso2 = ("2005-04-07 22:13:11 +0400", -14400)
        iso3 = ("2005.04.07 22:13:11 -0000", 0)
        alt = ("04/07/2005 22:13:11", 0)
        alt2 = ("07.04.2005 22:13:11", 0)
        veri_time_utc = 1112911991      # the time this represents, in time since epoch, UTC
        for date, offset in (rfc, iso, iso2, iso3, alt, alt2):
            assert_rval(parse_date(date), veri_time_utc, offset)
        # END for each date type

        # and failure
        self.failUnlessRaises(ValueError, parse_date, 'invalid format')
        self.failUnlessRaises(ValueError, parse_date, '123456789 -02000')
        self.failUnlessRaises(ValueError, parse_date, ' 123456789 -0200')

    def test_actor(self):
        for cr in (None, self.rorepo.config_reader()):
            self.assertIsInstance(Actor.committer(cr), Actor)
            self.assertIsInstance(Actor.author(cr), Actor)
        # END assure config reader is handled

    @ddt.data(('name', ''), ('name', 'prefix_'))
    def test_iterable_list(self, case):
        name, prefix = case
        ilist = IterableList(name, prefix)

        name1 = "one"
        name2 = "two"
        m1 = TestIterableMember(prefix + name1)
        m2 = TestIterableMember(prefix + name2)

        ilist.extend((m1, m2))

        self.assertEqual(len(ilist), 2)

        # contains works with name and identity
        self.assertIn(name1, ilist)
        self.assertIn(name2, ilist)
        self.assertIn(m2, ilist)
        self.assertIn(m2, ilist)
        self.assertNotIn('invalid', ilist)

        # with string index
        self.assertIs(ilist[name1], m1)
        self.assertIs(ilist[name2], m2)

        # with int index
        self.assertIs(ilist[0], m1)
        self.assertIs(ilist[1], m2)

        # with getattr
        self.assertIs(ilist.one, m1)
        self.assertIs(ilist.two, m2)

        # test exceptions
        self.failUnlessRaises(AttributeError, getattr, ilist, 'something')
        self.failUnlessRaises(IndexError, ilist.__getitem__, 'something')

        # delete by name and index
        self.failUnlessRaises(IndexError, ilist.__delitem__, 'something')
        del(ilist[name2])
        self.assertEqual(len(ilist), 1)
        self.assertNotIn(name2, ilist)
        self.assertIn(name1, ilist)
        del(ilist[0])
        self.assertNotIn(name1, ilist)
        self.assertEqual(len(ilist), 0)

        self.failUnlessRaises(IndexError, ilist.__delitem__, 0)
        self.failUnlessRaises(IndexError, ilist.__delitem__, 'something')
