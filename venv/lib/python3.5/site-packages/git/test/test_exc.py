# -*- coding: utf-8 -*-
# test_exc.py
# Copyright (C) 2008, 2009, 2016 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php


import re

import ddt
from git.exc import (
    InvalidGitRepositoryError,
    WorkTreeRepositoryUnsupported,
    NoSuchPathError,
    CommandError,
    GitCommandNotFound,
    GitCommandError,
    CheckoutError,
    CacheError,
    UnmergedEntriesError,
    HookExecutionError,
    RepositoryDirtyError,
)
from git.test.lib import TestBase

import itertools as itt


_cmd_argvs = (
    ('cmd', ),
    ('θνιψοδε', ),
    ('θνιψοδε', 'normal', 'argvs'),
    ('cmd', 'ελληνικα', 'args'),
    ('θνιψοδε', 'κι', 'αλλα', 'strange', 'args'),
    ('θνιψοδε', 'κι', 'αλλα', 'non-unicode', 'args'),
)
_causes_n_substrings = (
    (None,                      None),                          # noqa: E241 @IgnorePep8
    (7,                         "exit code(7)"),                # noqa: E241 @IgnorePep8
    ('Some string',             "'Some string'"),               # noqa: E241 @IgnorePep8
    ('παλιο string',            "'παλιο string'"),              # noqa: E241 @IgnorePep8
    (Exception("An exc."),      "Exception('An exc.')"),        # noqa: E241 @IgnorePep8
    (Exception("Κακια exc."),   "Exception('Κακια exc.')"),     # noqa: E241 @IgnorePep8
    (object(),                  "<object object at "),          # noqa: E241 @IgnorePep8
)

_streams_n_substrings = (None, 'steram', 'ομορφο stream', )


@ddt.ddt
class TExc(TestBase):

    def test_ExceptionsHaveBaseClass(self):
        from git.exc import GitError
        self.assertIsInstance(GitError(), Exception)
        
        exception_classes = [
            InvalidGitRepositoryError,
            WorkTreeRepositoryUnsupported,
            NoSuchPathError,
            CommandError,
            GitCommandNotFound,
            GitCommandError,
            CheckoutError,
            CacheError,
            UnmergedEntriesError,
            HookExecutionError,
            RepositoryDirtyError,
        ]
        for ex_class in exception_classes:
            self.assertTrue(issubclass(ex_class, GitError))

    @ddt.data(*list(itt.product(_cmd_argvs, _causes_n_substrings, _streams_n_substrings)))
    def test_CommandError_unicode(self, case):
        argv, (cause, subs), stream = case
        cls = CommandError
        c = cls(argv, cause)
        s = str(c)

        self.assertIsNotNone(c._msg)
        self.assertIn('  cmdline: ', s)

        for a in argv:
            self.assertIn(a, s)

        if not cause:
            self.assertIn("failed!", s)
        else:
            self.assertIn(" failed due to:", s)

            if subs is not None:
                # Substrings (must) already contain opening `'`.
                subs = "(?<!')%s(?!')" % re.escape(subs)
                self.assertRegexpMatches(s, subs)

        if not stream:
            c = cls(argv, cause)
            s = str(c)
            self.assertNotIn("  stdout:", s)
            self.assertNotIn("  stderr:", s)
        else:
            c = cls(argv, cause, stream)
            s = str(c)
            self.assertIn("  stderr:", s)
            self.assertIn(stream, s)

            c = cls(argv, cause, None, stream)
            s = str(c)
            self.assertIn("  stdout:", s)
            self.assertIn(stream, s)

            c = cls(argv, cause, stream, stream + 'no2')
            s = str(c)
            self.assertIn("  stderr:", s)
            self.assertIn(stream, s)
            self.assertIn("  stdout:", s)
            self.assertIn(stream + 'no2', s)

    @ddt.data(
        (['cmd1'], None),
        (['cmd1'], "some cause"),
        (['cmd1'], Exception()),
    )
    def test_GitCommandNotFound(self, init_args):
        argv, cause = init_args
        c = GitCommandNotFound(argv, cause)
        s = str(c)

        self.assertIn(argv[0], s)
        if cause:
            self.assertIn(' not found due to: ', s)
            self.assertIn(str(cause), s)
        else:
            self.assertIn(' not found!', s)

    @ddt.data(
        (['cmd1'], None),
        (['cmd1'], "some cause"),
        (['cmd1'], Exception()),
    )
    def test_GitCommandError(self, init_args):
        argv, cause = init_args
        c = GitCommandError(argv, cause)
        s = str(c)

        self.assertIn(argv[0], s)
        if cause:
            self.assertIn(' failed due to: ', s)
            self.assertIn(str(cause), s)
        else:
            self.assertIn(' failed!', s)

    @ddt.data(
        (['cmd1'], None),
        (['cmd1'], "some cause"),
        (['cmd1'], Exception()),
    )
    def test_HookExecutionError(self, init_args):
        argv, cause = init_args
        c = HookExecutionError(argv, cause)
        s = str(c)

        self.assertIn(argv[0], s)
        if cause:
            self.assertTrue(s.startswith('Hook('), s)
            self.assertIn(str(cause), s)
        else:
            self.assertIn(' failed!', s)
