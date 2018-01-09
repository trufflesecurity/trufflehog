# -*- coding: utf-8 -*-
# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
import subprocess
import sys

from git import (
    Git,
    refresh,
    GitCommandError,
    GitCommandNotFound,
    Repo,
    cmd
)
from git.compat import PY3, is_darwin
from git.test.lib import (
    TestBase,
    patch,
    raises,
    assert_equal,
    assert_true,
    assert_match,
    fixture_path
)
from git.test.lib import with_rw_directory
from git.util import finalize_process

import os.path as osp


try:
    from unittest import mock
except ImportError:
    import mock

from git.compat import is_win


class TestGit(TestBase):

    @classmethod
    def setUpClass(cls):
        super(TestGit, cls).setUpClass()
        cls.git = Git(cls.rorepo.working_dir)

    def tearDown(self):
        import gc
        gc.collect()

    @patch.object(Git, 'execute')
    def test_call_process_calls_execute(self, git):
        git.return_value = ''
        self.git.version()
        assert_true(git.called)
        assert_equal(git.call_args, ((['git', 'version'],), {}))

    def test_call_unpack_args_unicode(self):
        args = Git._Git__unpack_args(u'Unicode€™')
        if PY3:
            mangled_value = 'Unicode\u20ac\u2122'
        else:
            mangled_value = 'Unicode\xe2\x82\xac\xe2\x84\xa2'
        assert_equal(args, [mangled_value])

    def test_call_unpack_args(self):
        args = Git._Git__unpack_args(['git', 'log', '--', u'Unicode€™'])
        if PY3:
            mangled_value = 'Unicode\u20ac\u2122'
        else:
            mangled_value = 'Unicode\xe2\x82\xac\xe2\x84\xa2'
        assert_equal(args, ['git', 'log', '--', mangled_value])

    @raises(GitCommandError)
    def test_it_raises_errors(self):
        self.git.this_does_not_exist()

    def test_it_transforms_kwargs_into_git_command_arguments(self):
        assert_equal(["-s"], self.git.transform_kwargs(**{'s': True}))
        assert_equal(["-s", "5"], self.git.transform_kwargs(**{'s': 5}))

        assert_equal(["--max-count"], self.git.transform_kwargs(**{'max_count': True}))
        assert_equal(["--max-count=5"], self.git.transform_kwargs(**{'max_count': 5}))

        # Multiple args are supported by using lists/tuples
        assert_equal(["-L", "1-3", "-L", "12-18"], self.git.transform_kwargs(**{'L': ('1-3', '12-18')}))
        assert_equal(["-C", "-C"], self.git.transform_kwargs(**{'C': [True, True]}))

        # order is undefined
        res = self.git.transform_kwargs(**{'s': True, 't': True})
        self.assertEqual(set(['-s', '-t']), set(res))

    def test_it_executes_git_to_shell_and_returns_result(self):
        assert_match(r'^git version [\d\.]{2}.*$', self.git.execute(["git", "version"]))

    def test_it_accepts_stdin(self):
        filename = fixture_path("cat_file_blob")
        with open(filename, 'r') as fh:
            assert_equal("70c379b63ffa0795fdbfbc128e5a2818397b7ef8",
                         self.git.hash_object(istream=fh, stdin=True))

    @patch.object(Git, 'execute')
    def test_it_ignores_false_kwargs(self, git):
        # this_should_not_be_ignored=False implies it *should* be ignored
        self.git.version(pass_this_kwarg=False)
        assert_true("pass_this_kwarg" not in git.call_args[1])

    def test_it_accepts_environment_variables(self):
        filename = fixture_path("ls_tree_empty")
        with open(filename, 'r') as fh:
            tree = self.git.mktree(istream=fh)
            env = {
                'GIT_AUTHOR_NAME': 'Author Name',
                'GIT_AUTHOR_EMAIL': 'author@example.com',
                'GIT_AUTHOR_DATE': '1400000000+0000',
                'GIT_COMMITTER_NAME': 'Committer Name',
                'GIT_COMMITTER_EMAIL': 'committer@example.com',
                'GIT_COMMITTER_DATE': '1500000000+0000',
            }
            commit = self.git.commit_tree(tree, m='message', env=env)
            assert_equal(commit, '4cfd6b0314682d5a58f80be39850bad1640e9241')

    def test_persistent_cat_file_command(self):
        # read header only
        import subprocess as sp
        hexsha = "b2339455342180c7cc1e9bba3e9f181f7baa5167"
        g = self.git.cat_file(batch_check=True, istream=sp.PIPE, as_process=True)
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        obj_info = g.stdout.readline()

        # read header + data
        g = self.git.cat_file(batch=True, istream=sp.PIPE, as_process=True)
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        obj_info_two = g.stdout.readline()
        self.assertEqual(obj_info, obj_info_two)

        # read data - have to read it in one large chunk
        size = int(obj_info.split()[2])
        g.stdout.read(size)
        g.stdout.read(1)

        # now we should be able to read a new object
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        self.assertEqual(g.stdout.readline(), obj_info)

        # same can be achieved using the respective command functions
        hexsha, typename, size = self.git.get_object_header(hexsha)
        hexsha, typename_two, size_two, data = self.git.get_object_data(hexsha)  # @UnusedVariable
        self.assertEqual(typename, typename_two)
        self.assertEqual(size, size_two)

    def test_version(self):
        v = self.git.version_info
        self.assertIsInstance(v, tuple)
        for n in v:
            self.assertIsInstance(n, int)
        # END verify number types

    def test_cmd_override(self):
        prev_cmd = self.git.GIT_PYTHON_GIT_EXECUTABLE
        exc = GitCommandNotFound
        try:
            # set it to something that doens't exist, assure it raises
            type(self.git).GIT_PYTHON_GIT_EXECUTABLE = osp.join(
                "some", "path", "which", "doesn't", "exist", "gitbinary")
            self.failUnlessRaises(exc, self.git.version)
        finally:
            type(self.git).GIT_PYTHON_GIT_EXECUTABLE = prev_cmd
        # END undo adjustment

    def test_refresh(self):
        # test a bad git path refresh
        self.assertRaises(GitCommandNotFound, refresh, "yada")

        # test a good path refresh
        which_cmd = "where" if is_win else "which"
        path = os.popen("{0} git".format(which_cmd)).read().strip().split('\n')[0]
        refresh(path)

    def test_options_are_passed_to_git(self):
        # This work because any command after git --version is ignored
        git_version = self.git(version=True).NoOp()
        git_command_version = self.git.version()
        self.assertEquals(git_version, git_command_version)

    def test_persistent_options(self):
        git_command_version = self.git.version()
        # analog to test_options_are_passed_to_git
        self.git.set_persistent_git_options(version=True)
        git_version = self.git.NoOp()
        self.assertEquals(git_version, git_command_version)
        # subsequent calls keep this option:
        git_version_2 = self.git.NoOp()
        self.assertEquals(git_version_2, git_command_version)

        # reset to empty:
        self.git.set_persistent_git_options()
        self.assertRaises(GitCommandError, self.git.NoOp)

    def test_single_char_git_options_are_passed_to_git(self):
        input_value = 'TestValue'
        output_value = self.git(c='user.name=%s' % input_value).config('--get', 'user.name')
        self.assertEquals(input_value, output_value)

    def test_change_to_transform_kwargs_does_not_break_command_options(self):
        self.git.log(n=1)

    def test_insert_after_kwarg_raises(self):
        # This isn't a complete add command, which doesn't matter here
        self.failUnlessRaises(ValueError, self.git.remote, 'add', insert_kwargs_after='foo')

    def test_env_vars_passed_to_git(self):
        editor = 'non_existent_editor'
        with mock.patch.dict('os.environ', {'GIT_EDITOR': editor}):  # @UndefinedVariable
            self.assertEqual(self.git.var("GIT_EDITOR"), editor)

    @with_rw_directory
    def test_environment(self, rw_dir):
        # sanity check
        self.assertEqual(self.git.environment(), {})

        # make sure the context manager works and cleans up after itself
        with self.git.custom_environment(PWD='/tmp'):
            self.assertEqual(self.git.environment(), {'PWD': '/tmp'})

        self.assertEqual(self.git.environment(), {})

        old_env = self.git.update_environment(VARKEY='VARVALUE')
        # The returned dict can be used to revert the change, hence why it has
        # an entry with value 'None'.
        self.assertEqual(old_env, {'VARKEY': None})
        self.assertEqual(self.git.environment(), {'VARKEY': 'VARVALUE'})

        new_env = self.git.update_environment(**old_env)
        self.assertEqual(new_env, {'VARKEY': 'VARVALUE'})
        self.assertEqual(self.git.environment(), {})

        path = osp.join(rw_dir, 'failing-script.sh')
        with open(path, 'wt') as stream:
            stream.write("#!/usr/bin/env sh\n"
                         "echo FOO\n")
        os.chmod(path, 0o777)

        rw_repo = Repo.init(osp.join(rw_dir, 'repo'))
        remote = rw_repo.create_remote('ssh-origin', "ssh://git@server/foo")

        with rw_repo.git.custom_environment(GIT_SSH=path):
            try:
                remote.fetch()
            except GitCommandError as err:
                if sys.version_info[0] < 3 and is_darwin:
                    self.assertIn('ssh-orig, ' in str(err))
                    self.assertEqual(err.status, 128)
                else:
                    self.assertIn('FOO', str(err))

    def test_handle_process_output(self):
        from git.cmd import handle_process_output

        line_count = 5002
        count = [None, 0, 0]

        def counter_stdout(line):
            count[1] += 1

        def counter_stderr(line):
            count[2] += 1

        cmdline = [sys.executable, fixture_path('cat_file.py'), str(fixture_path('issue-301_stderr'))]
        proc = subprocess.Popen(cmdline,
                                stdin=None,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=False,
                                creationflags=cmd.PROC_CREATIONFLAGS,
                                )

        handle_process_output(proc, counter_stdout, counter_stderr, finalize_process)

        self.assertEqual(count[1], line_count)
        self.assertEqual(count[2], line_count)
