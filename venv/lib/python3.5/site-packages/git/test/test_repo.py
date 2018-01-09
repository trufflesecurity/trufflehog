# -*- coding: utf-8 -*-
# test_repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import glob
from io import BytesIO
import itertools
import os
import pickle
import sys
import tempfile
try:
    from unittest import skipIf, SkipTest
except ImportError:
    from unittest2 import skipIf, SkipTest

try:
    import pathlib
except ImportError:
    pathlib = None

from git import (
    InvalidGitRepositoryError,
    Repo,
    NoSuchPathError,
    Head,
    Commit,
    Object,
    Tree,
    IndexFile,
    Git,
    Reference,
    GitDB,
    Submodule,
    GitCmdObjectDB,
    Remote,
    BadName,
    GitCommandError
)
from git.compat import (
    PY3,
    is_win,
    string_types,
    win_encode,
)
from git.exc import (
    BadObject,
)
from git.repo.fun import touch
from git.test.lib import (
    patch,
    TestBase,
    with_rw_repo,
    fixture,
    assert_false,
    assert_equal,
    assert_true,
    raises
)
from git.util import HIDE_WINDOWS_KNOWN_ERRORS, cygpath
from git.test.lib import with_rw_directory
from git.util import join_path_native, rmtree, rmfile, bin_to_hex

import functools as fnt
import os.path as osp


def iter_flatten(lol):
    for items in lol:
        for item in items:
            yield item


def flatten(lol):
    return list(iter_flatten(lol))


_tc_lock_fpaths = osp.join(osp.dirname(__file__), '../../.git/*.lock')


def _rm_lock_files():
    for lfp in glob.glob(_tc_lock_fpaths):
        rmfile(lfp)


class TestRepo(TestBase):

    def setUp(self):
        _rm_lock_files()

    def tearDown(self):
        for lfp in glob.glob(_tc_lock_fpaths):
            if osp.isfile(lfp):
                raise AssertionError('Previous TC left hanging git-lock file: %s', lfp)
        import gc
        gc.collect()

    @raises(InvalidGitRepositoryError)
    def test_new_should_raise_on_invalid_repo_location(self):
        Repo(tempfile.gettempdir())

    @raises(NoSuchPathError)
    def test_new_should_raise_on_non_existent_path(self):
        Repo("repos/foobar")

    @with_rw_repo('0.3.2.1')
    def test_repo_creation_from_different_paths(self, rw_repo):
        r_from_gitdir = Repo(rw_repo.git_dir)
        self.assertEqual(r_from_gitdir.git_dir, rw_repo.git_dir)
        assert r_from_gitdir.git_dir.endswith('.git')
        assert not rw_repo.git.working_dir.endswith('.git')
        self.assertEqual(r_from_gitdir.git.working_dir, rw_repo.git.working_dir)

    def test_description(self):
        txt = "Test repository"
        self.rorepo.description = txt
        assert_equal(self.rorepo.description, txt)

    def test_heads_should_return_array_of_head_objects(self):
        for head in self.rorepo.heads:
            assert_equal(Head, head.__class__)

    def test_heads_should_populate_head_data(self):
        for head in self.rorepo.heads:
            assert head.name
            self.assertIsInstance(head.commit, Commit)
        # END for each head

        self.assertIsInstance(self.rorepo.heads.master, Head)
        self.assertIsInstance(self.rorepo.heads['master'], Head)

    def test_tree_from_revision(self):
        tree = self.rorepo.tree('0.1.6')
        self.assertEqual(len(tree.hexsha), 40)
        self.assertEqual(tree.type, "tree")
        self.assertEqual(self.rorepo.tree(tree), tree)

        # try from invalid revision that does not exist
        self.failUnlessRaises(BadName, self.rorepo.tree, 'hello world')

    def test_pickleable(self):
        pickle.loads(pickle.dumps(self.rorepo))

    def test_commit_from_revision(self):
        commit = self.rorepo.commit('0.1.4')
        self.assertEqual(commit.type, 'commit')
        self.assertEqual(self.rorepo.commit(commit), commit)

    def test_commits(self):
        mc = 10
        commits = list(self.rorepo.iter_commits('0.1.6', max_count=mc))
        self.assertEqual(len(commits), mc)

        c = commits[0]
        assert_equal('9a4b1d4d11eee3c5362a4152216376e634bd14cf', c.hexsha)
        assert_equal(["c76852d0bff115720af3f27acdb084c59361e5f6"], [p.hexsha for p in c.parents])
        assert_equal("ce41fc29549042f1aa09cc03174896cf23f112e3", c.tree.hexsha)
        assert_equal("Michael Trier", c.author.name)
        assert_equal("mtrier@gmail.com", c.author.email)
        assert_equal(1232829715, c.authored_date)
        assert_equal(5 * 3600, c.author_tz_offset)
        assert_equal("Michael Trier", c.committer.name)
        assert_equal("mtrier@gmail.com", c.committer.email)
        assert_equal(1232829715, c.committed_date)
        assert_equal(5 * 3600, c.committer_tz_offset)
        assert_equal("Bumped version 0.1.6\n", c.message)

        c = commits[1]
        self.assertIsInstance(c.parents, tuple)

    def test_trees(self):
        mc = 30
        num_trees = 0
        for tree in self.rorepo.iter_trees('0.1.5', max_count=mc):
            num_trees += 1
            self.assertIsInstance(tree, Tree)
        # END for each tree
        self.assertEqual(num_trees, mc)

    def _assert_empty_repo(self, repo):
        # test all kinds of things with an empty, freshly initialized repo.
        # It should throw good errors

        # entries should be empty
        self.assertEqual(len(repo.index.entries), 0)

        # head is accessible
        assert repo.head
        assert repo.head.ref
        assert not repo.head.is_valid()

        # we can change the head to some other ref
        head_ref = Head.from_path(repo, Head.to_full_path('some_head'))
        assert not head_ref.is_valid()
        repo.head.ref = head_ref

        # is_dirty can handle all kwargs
        for args in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
            assert not repo.is_dirty(*args)
        # END for each arg

        # we can add a file to the index ( if we are not bare )
        if not repo.bare:
            pass
        # END test repos with working tree

    @with_rw_directory
    def test_clone_from_keeps_env(self, rw_dir):
        original_repo = Repo.init(osp.join(rw_dir, "repo"))
        environment = {"entry1": "value", "another_entry": "10"}

        cloned = Repo.clone_from(original_repo.git_dir, osp.join(rw_dir, "clone"), env=environment)

        assert_equal(environment, cloned.git.environment())

    @with_rw_directory
    def test_clone_from_pathlib(self, rw_dir):
        if pathlib is None:  # pythons bellow 3.4 don't have pathlib
            raise SkipTest("pathlib was introduced in 3.4")

        original_repo = Repo.init(osp.join(rw_dir, "repo"))

        Repo.clone_from(original_repo.git_dir, pathlib.Path(rw_dir) / "clone_pathlib")

    def test_init(self):
        prev_cwd = os.getcwd()
        os.chdir(tempfile.gettempdir())
        git_dir_rela = "repos/foo/bar.git"
        del_dir_abs = osp.abspath("repos")
        git_dir_abs = osp.abspath(git_dir_rela)
        try:
            # with specific path
            for path in (git_dir_rela, git_dir_abs):
                r = Repo.init(path=path, bare=True)
                self.assertIsInstance(r, Repo)
                assert r.bare is True
                assert not r.has_separate_working_tree()
                assert osp.isdir(r.git_dir)

                self._assert_empty_repo(r)

                # test clone
                clone_path = path + "_clone"
                rc = r.clone(clone_path)
                self._assert_empty_repo(rc)

                try:
                    rmtree(clone_path)
                except OSError:
                    # when relative paths are used, the clone may actually be inside
                    # of the parent directory
                    pass
                # END exception handling

                # try again, this time with the absolute version
                rc = Repo.clone_from(r.git_dir, clone_path)
                self._assert_empty_repo(rc)

                rmtree(git_dir_abs)
                try:
                    rmtree(clone_path)
                except OSError:
                    # when relative paths are used, the clone may actually be inside
                    # of the parent directory
                    pass
                # END exception handling

            # END for each path

            os.makedirs(git_dir_rela)
            os.chdir(git_dir_rela)
            r = Repo.init(bare=False)
            assert r.bare is False
            assert not r.has_separate_working_tree()

            self._assert_empty_repo(r)
        finally:
            try:
                rmtree(del_dir_abs)
            except OSError:
                pass
            os.chdir(prev_cwd)
        # END restore previous state

    def test_bare_property(self):
        self.rorepo.bare

    def test_daemon_export(self):
        orig_val = self.rorepo.daemon_export
        self.rorepo.daemon_export = not orig_val
        self.assertEqual(self.rorepo.daemon_export, (not orig_val))
        self.rorepo.daemon_export = orig_val
        self.assertEqual(self.rorepo.daemon_export, orig_val)

    def test_alternates(self):
        cur_alternates = self.rorepo.alternates
        # empty alternates
        self.rorepo.alternates = []
        self.assertEqual(self.rorepo.alternates, [])
        alts = ["other/location", "this/location"]
        self.rorepo.alternates = alts
        self.assertEqual(alts, self.rorepo.alternates)
        self.rorepo.alternates = cur_alternates

    def test_repr(self):
        assert repr(self.rorepo).startswith('<git.Repo ')

    def test_is_dirty_with_bare_repository(self):
        orig_value = self.rorepo._bare
        self.rorepo._bare = True
        assert_false(self.rorepo.is_dirty())
        self.rorepo._bare = orig_value

    def test_is_dirty(self):
        self.rorepo._bare = False
        for index in (0, 1):
            for working_tree in (0, 1):
                for untracked_files in (0, 1):
                    assert self.rorepo.is_dirty(index, working_tree, untracked_files) in (True, False)
                # END untracked files
            # END working tree
        # END index
        orig_val = self.rorepo._bare
        self.rorepo._bare = True
        assert self.rorepo.is_dirty() is False
        self.rorepo._bare = orig_val

    @with_rw_repo('HEAD')
    def test_is_dirty_with_path(self, rwrepo):
        assert rwrepo.is_dirty(path="git") is False

        with open(osp.join(rwrepo.working_dir, "git", "util.py"), "at") as f:
            f.write("junk")
        assert rwrepo.is_dirty(path="git") is True
        assert rwrepo.is_dirty(path="doc") is False

        rwrepo.git.add(Git.polish_url(osp.join("git", "util.py")))
        assert rwrepo.is_dirty(index=False, path="git") is False
        assert rwrepo.is_dirty(path="git") is True

        with open(osp.join(rwrepo.working_dir, "doc", "no-such-file.txt"), "wt") as f:
            f.write("junk")
        assert rwrepo.is_dirty(path="doc") is False
        assert rwrepo.is_dirty(untracked_files=True, path="doc") is True

    def test_head(self):
        self.assertEqual(self.rorepo.head.reference.object, self.rorepo.active_branch.object)

    def test_index(self):
        index = self.rorepo.index
        self.assertIsInstance(index, IndexFile)

    def test_tag(self):
        assert self.rorepo.tag('refs/tags/0.1.5').commit

    def test_archive(self):
        tmpfile = tempfile.mktemp(suffix='archive-test')
        with open(tmpfile, 'wb') as stream:
            self.rorepo.archive(stream, '0.1.6', path='doc')
            assert stream.tell()
        os.remove(tmpfile)

    @patch.object(Git, '_call_process')
    def test_should_display_blame_information(self, git):
        if sys.version_info < (2, 7):
            ## Skipped, not `assertRaisesRegexp` in py2.6
            return
        git.return_value = fixture('blame')
        b = self.rorepo.blame('master', 'lib/git.py')
        assert_equal(13, len(b))
        assert_equal(2, len(b[0]))
        # assert_equal(25, reduce(lambda acc, x: acc + len(x[-1]), b))
        assert_equal(hash(b[0][0]), hash(b[9][0]))
        c = b[0][0]
        assert_true(git.called)

        assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', c.hexsha)
        assert_equal('Tom Preston-Werner', c.author.name)
        assert_equal('tom@mojombo.com', c.author.email)
        assert_equal(1191997100, c.authored_date)
        assert_equal('Tom Preston-Werner', c.committer.name)
        assert_equal('tom@mojombo.com', c.committer.email)
        assert_equal(1191997100, c.committed_date)
        self.assertRaisesRegexp(ValueError, "634396b2f541a9f2d58b00be1a07f0c358b999b3 missing", lambda: c.message)

        # test the 'lines per commit' entries
        tlist = b[0][1]
        assert_true(tlist)
        assert_true(isinstance(tlist[0], string_types))
        assert_true(len(tlist) < sum(len(t) for t in tlist))               # test for single-char bug

        # BINARY BLAME
        git.return_value = fixture('blame_binary')
        blames = self.rorepo.blame('master', 'rps')
        self.assertEqual(len(blames), 2)

    def test_blame_real(self):
        c = 0
        nml = 0   # amount of multi-lines per blame
        for item in self.rorepo.head.commit.tree.traverse(
                predicate=lambda i, d: i.type == 'blob' and i.path.endswith('.py')):
            c += 1

            for b in self.rorepo.blame(self.rorepo.head, item.path):
                nml += int(len(b[1]) > 1)
        # END for each item to traverse
        assert c, "Should have executed at least one blame command"
        assert nml, "There should at least be one blame commit that contains multiple lines"

    @patch.object(Git, '_call_process')
    def test_blame_incremental(self, git):
        # loop over two fixtures, create a test fixture for 2.11.1+ syntax
        for git_fixture in ('blame_incremental', 'blame_incremental_2.11.1_plus'):
            git.return_value = fixture(git_fixture)
            blame_output = self.rorepo.blame_incremental('9debf6b0aafb6f7781ea9d1383c86939a1aacde3', 'AUTHORS')
            blame_output = list(blame_output)
            self.assertEqual(len(blame_output), 5)

            # Check all outputted line numbers
            ranges = flatten([entry.linenos for entry in blame_output])
            self.assertEqual(ranges, flatten([range(2, 3), range(14, 15), range(1, 2), range(3, 14), range(15, 17)]))

            commits = [entry.commit.hexsha[:7] for entry in blame_output]
            self.assertEqual(commits, ['82b8902', '82b8902', 'c76852d', 'c76852d', 'c76852d'])

            # Original filenames
            self.assertSequenceEqual([entry.orig_path for entry in blame_output], [u'AUTHORS'] * len(blame_output))

            # Original line numbers
            orig_ranges = flatten([entry.orig_linenos for entry in blame_output])
            self.assertEqual(orig_ranges, flatten([range(2, 3), range(14, 15), range(1, 2), range(2, 13), range(13, 15)]))   # noqa E501

    @patch.object(Git, '_call_process')
    def test_blame_complex_revision(self, git):
        git.return_value = fixture('blame_complex_revision')
        res = self.rorepo.blame("HEAD~10..HEAD", "README.md")
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[0][1]), 83, "Unexpected amount of parsed blame lines")

    @skipIf(HIDE_WINDOWS_KNOWN_ERRORS and Git.is_cygwin(),
            """FIXME: File "C:\\projects\\gitpython\\git\\cmd.py", line 671, in execute
                    raise GitCommandError(command, status, stderr_value, stdout_value)
                GitCommandError: Cmd('git') failed due to: exit code(128)
                  cmdline: git add 1__��ava verb��ten 1_test _myfile 1_test_other_file
                          1_��ava-----verb��ten
                  stderr: 'fatal: pathspec '"1__çava verböten"' did not match any files'
                """)
    @with_rw_repo('HEAD', bare=False)
    def test_untracked_files(self, rwrepo):
        for run, (repo_add, is_invoking_git) in enumerate((
                (rwrepo.index.add, False),
                (rwrepo.git.add, True),
        )):
            base = rwrepo.working_tree_dir
            files = (join_path_native(base, u"%i_test _myfile" % run),
                     join_path_native(base, "%i_test_other_file" % run),
                     join_path_native(base, u"%i__çava verböten" % run),
                     join_path_native(base, u"%i_çava-----verböten" % run))

            num_recently_untracked = 0
            for fpath in files:
                with open(fpath, "wb"):
                    pass
            untracked_files = rwrepo.untracked_files
            num_recently_untracked = len(untracked_files)

            # assure we have all names - they are relative to the git-dir
            num_test_untracked = 0
            for utfile in untracked_files:
                num_test_untracked += join_path_native(base, utfile) in files
            self.assertEqual(len(files), num_test_untracked)

            if is_win and not PY3 and is_invoking_git:
                ## On Windows, shell needed when passing unicode cmd-args.
                #
                repo_add = fnt.partial(repo_add, shell=True)
                untracked_files = [win_encode(f) for f in untracked_files]
            repo_add(untracked_files)
            self.assertEqual(len(rwrepo.untracked_files), (num_recently_untracked - len(files)))
        # end for each run

    def test_config_reader(self):
        reader = self.rorepo.config_reader()                # all config files
        assert reader.read_only
        reader = self.rorepo.config_reader("repository")    # single config file
        assert reader.read_only

    def test_config_writer(self):
        for config_level in self.rorepo.config_level:
            try:
                with self.rorepo.config_writer(config_level) as writer:
                    self.assertFalse(writer.read_only)
            except IOError:
                # its okay not to get a writer for some configuration files if we
                # have no permissions
                pass

    def test_config_level_paths(self):
        for config_level in self.rorepo.config_level:
            assert self.rorepo._get_config_path(config_level)

    def test_creation_deletion(self):
        # just a very quick test to assure it generally works. There are
        # specialized cases in the test_refs module
        head = self.rorepo.create_head("new_head", "HEAD~1")
        self.rorepo.delete_head(head)

        try:
            tag = self.rorepo.create_tag("new_tag", "HEAD~2")
        finally:
            self.rorepo.delete_tag(tag)
        with self.rorepo.config_writer():
            pass
        try:
            remote = self.rorepo.create_remote("new_remote", "git@server:repo.git")
        finally:
            self.rorepo.delete_remote(remote)

    def test_comparison_and_hash(self):
        # this is only a preliminary test, more testing done in test_index
        self.assertEqual(self.rorepo, self.rorepo)
        self.assertFalse(self.rorepo != self.rorepo)
        self.assertEqual(len(set((self.rorepo, self.rorepo))), 1)

    @with_rw_directory
    def test_tilde_and_env_vars_in_repo_path(self, rw_dir):
        ph = os.environ.get('HOME')
        try:
            os.environ['HOME'] = rw_dir
            Repo.init(osp.join('~', 'test.git'), bare=True)

            os.environ['FOO'] = rw_dir
            Repo.init(osp.join('$FOO', 'test.git'), bare=True)
        finally:
            if ph:
                os.environ['HOME'] = ph
                del os.environ['FOO']
        # end assure HOME gets reset to what it was

    def test_git_cmd(self):
        # test CatFileContentStream, just to be very sure we have no fencepost errors
        # last \n is the terminating newline that it expects
        l1 = b"0123456789\n"
        l2 = b"abcdefghijklmnopqrstxy\n"
        l3 = b"z\n"
        d = l1 + l2 + l3 + b"\n"

        l1p = l1[:5]

        # full size
        # size is without terminating newline
        def mkfull():
            return Git.CatFileContentStream(len(d) - 1, BytesIO(d))

        ts = 5

        def mktiny():
            return Git.CatFileContentStream(ts, BytesIO(d))

        # readlines no limit
        s = mkfull()
        lines = s.readlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[-1].endswith(b'\n'), lines[-1])
        self.assertEqual(s._stream.tell(), len(d))  # must have scrubbed to the end

        # realines line limit
        s = mkfull()
        lines = s.readlines(5)
        self.assertEqual(len(lines), 1)

        # readlines on tiny sections
        s = mktiny()
        lines = s.readlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], l1p)
        self.assertEqual(s._stream.tell(), ts + 1)

        # readline no limit
        s = mkfull()
        self.assertEqual(s.readline(), l1)
        self.assertEqual(s.readline(), l2)
        self.assertEqual(s.readline(), l3)
        self.assertEqual(s.readline(), b'')
        self.assertEqual(s._stream.tell(), len(d))

        # readline limit
        s = mkfull()
        self.assertEqual(s.readline(5), l1p)
        self.assertEqual(s.readline(), l1[5:])

        # readline on tiny section
        s = mktiny()
        self.assertEqual(s.readline(), l1p)
        self.assertEqual(s.readline(), b'')
        self.assertEqual(s._stream.tell(), ts + 1)

        # read no limit
        s = mkfull()
        self.assertEqual(s.read(), d[:-1])
        self.assertEqual(s.read(), b'')
        self.assertEqual(s._stream.tell(), len(d))

        # read limit
        s = mkfull()
        self.assertEqual(s.read(5), l1p)
        self.assertEqual(s.read(6), l1[5:])
        self.assertEqual(s._stream.tell(), 5 + 6)  # its not yet done

        # read tiny
        s = mktiny()
        self.assertEqual(s.read(2), l1[:2])
        self.assertEqual(s._stream.tell(), 2)
        self.assertEqual(s.read(), l1[2:ts])
        self.assertEqual(s._stream.tell(), ts + 1)

    def _assert_rev_parse_types(self, name, rev_obj):
        rev_parse = self.rorepo.rev_parse

        if rev_obj.type == 'tag':
            rev_obj = rev_obj.object

        # tree and blob type
        obj = rev_parse(name + '^{tree}')
        self.assertEqual(obj, rev_obj.tree)

        obj = rev_parse(name + ':CHANGES')
        self.assertEqual(obj.type, 'blob')
        self.assertEqual(obj.path, 'CHANGES')
        self.assertEqual(rev_obj.tree['CHANGES'], obj)

    def _assert_rev_parse(self, name):
        """tries multiple different rev-parse syntaxes with the given name
        :return: parsed object"""
        rev_parse = self.rorepo.rev_parse
        orig_obj = rev_parse(name)
        if orig_obj.type == 'tag':
            obj = orig_obj.object
        else:
            obj = orig_obj
        # END deref tags by default

        # try history
        rev = name + "~"
        obj2 = rev_parse(rev)
        self.assertEqual(obj2, obj.parents[0])
        self._assert_rev_parse_types(rev, obj2)

        # history with number
        ni = 11
        history = [obj.parents[0]]
        for pn in range(ni):
            history.append(history[-1].parents[0])
        # END get given amount of commits

        for pn in range(11):
            rev = name + "~%i" % (pn + 1)
            obj2 = rev_parse(rev)
            self.assertEqual(obj2, history[pn])
            self._assert_rev_parse_types(rev, obj2)
        # END history check

        # parent ( default )
        rev = name + "^"
        obj2 = rev_parse(rev)
        self.assertEqual(obj2, obj.parents[0])
        self._assert_rev_parse_types(rev, obj2)

        # parent with number
        for pn, parent in enumerate(obj.parents):
            rev = name + "^%i" % (pn + 1)
            self.assertEqual(rev_parse(rev), parent)
            self._assert_rev_parse_types(rev, parent)
        # END for each parent

        return orig_obj

    @with_rw_repo('HEAD', bare=False)
    def test_rw_rev_parse(self, rwrepo):
        # verify it does not confuse branches with hexsha ids
        ahead = rwrepo.create_head('aaaaaaaa')
        assert(rwrepo.rev_parse(str(ahead)) == ahead.commit)

    def test_rev_parse(self):
        rev_parse = self.rorepo.rev_parse

        # try special case: This one failed at some point, make sure its fixed
        self.assertEqual(rev_parse("33ebe").hexsha, "33ebe7acec14b25c5f84f35a664803fcab2f7781")

        # start from reference
        num_resolved = 0

        for ref_no, ref in enumerate(Reference.iter_items(self.rorepo)):
            path_tokens = ref.path.split("/")
            for pt in range(len(path_tokens)):
                path_section = '/'.join(path_tokens[-(pt + 1):])
                try:
                    obj = self._assert_rev_parse(path_section)
                    self.assertEqual(obj.type, ref.object.type)
                    num_resolved += 1
                except (BadName, BadObject):
                    print("failed on %s" % path_section)
                    # is fine, in case we have something like 112, which belongs to remotes/rname/merge-requests/112
                    pass
                # END exception handling
            # END for each token
            if ref_no == 3 - 1:
                break
        # END for each reference
        assert num_resolved

        # it works with tags !
        tag = self._assert_rev_parse('0.1.4')
        self.assertEqual(tag.type, 'tag')

        # try full sha directly ( including type conversion )
        self.assertEqual(tag.object, rev_parse(tag.object.hexsha))
        self._assert_rev_parse_types(tag.object.hexsha, tag.object)

        # multiple tree types result in the same tree: HEAD^{tree}^{tree}:CHANGES
        rev = '0.1.4^{tree}^{tree}'
        self.assertEqual(rev_parse(rev), tag.object.tree)
        self.assertEqual(rev_parse(rev + ':CHANGES'), tag.object.tree['CHANGES'])

        # try to get parents from first revision - it should fail as no such revision
        # exists
        first_rev = "33ebe7acec14b25c5f84f35a664803fcab2f7781"
        commit = rev_parse(first_rev)
        self.assertEqual(len(commit.parents), 0)
        self.assertEqual(commit.hexsha, first_rev)
        self.failUnlessRaises(BadName, rev_parse, first_rev + "~")
        self.failUnlessRaises(BadName, rev_parse, first_rev + "^")

        # short SHA1
        commit2 = rev_parse(first_rev[:20])
        self.assertEqual(commit2, commit)
        commit2 = rev_parse(first_rev[:5])
        self.assertEqual(commit2, commit)

        # todo: dereference tag into a blob 0.1.7^{blob} - quite a special one
        # needs a tag which points to a blob

        # ref^0 returns commit being pointed to, same with ref~0, and ^{}
        tag = rev_parse('0.1.4')
        for token in (('~0', '^0', '^{}')):
            self.assertEqual(tag.object, rev_parse('0.1.4%s' % token))
        # END handle multiple tokens

        # try partial parsing
        max_items = 40
        for i, binsha in enumerate(self.rorepo.odb.sha_iter()):
            self.assertEqual(rev_parse(bin_to_hex(binsha)[:8 - (i % 2)].decode('ascii')).binsha, binsha)
            if i > max_items:
                # this is rather slow currently, as rev_parse returns an object
                # which requires accessing packs, it has some additional overhead
                break
        # END for each binsha in repo

        # missing closing brace commit^{tree
        self.failUnlessRaises(ValueError, rev_parse, '0.1.4^{tree')

        # missing starting brace
        self.failUnlessRaises(ValueError, rev_parse, '0.1.4^tree}')

        # REVLOG
        #######
        head = self.rorepo.head

        # need to specify a ref when using the @ syntax
        self.failUnlessRaises(BadObject, rev_parse, "%s@{0}" % head.commit.hexsha)

        # uses HEAD.ref by default
        self.assertEqual(rev_parse('@{0}'), head.commit)
        if not head.is_detached:
            refspec = '%s@{0}' % head.ref.name
            self.assertEqual(rev_parse(refspec), head.ref.commit)
            # all additional specs work as well
            self.assertEqual(rev_parse(refspec + "^{tree}"), head.commit.tree)
            self.assertEqual(rev_parse(refspec + ":CHANGES").type, 'blob')
        # END operate on non-detached head

        # position doesn't exist
        self.failUnlessRaises(IndexError, rev_parse, '@{10000}')

        # currently, nothing more is supported
        self.failUnlessRaises(NotImplementedError, rev_parse, "@{1 week ago}")

        # the last position
        assert rev_parse('@{1}') != head.commit

    def test_repo_odbtype(self):
        target_type = GitCmdObjectDB
        if sys.version_info[:2] < (2, 5):
            target_type = GitCmdObjectDB
        self.assertIsInstance(self.rorepo.odb, target_type)

    def test_submodules(self):
        self.assertEqual(len(self.rorepo.submodules), 1)  # non-recursive
        self.assertGreaterEqual(len(list(self.rorepo.iter_submodules())), 2)

        self.assertIsInstance(self.rorepo.submodule("gitdb"), Submodule)
        self.failUnlessRaises(ValueError, self.rorepo.submodule, "doesn't exist")

    @with_rw_repo('HEAD', bare=False)
    def test_submodule_update(self, rwrepo):
        # fails in bare mode
        rwrepo._bare = True
        self.failUnlessRaises(InvalidGitRepositoryError, rwrepo.submodule_update)
        rwrepo._bare = False

        # test create submodule
        sm = rwrepo.submodules[0]
        sm = rwrepo.create_submodule("my_new_sub", "some_path", join_path_native(self.rorepo.working_tree_dir, sm.path))
        self.assertIsInstance(sm, Submodule)

        # note: the rest of this functionality is tested in test_submodule

    @with_rw_repo('HEAD')
    def test_git_file(self, rwrepo):
        # Move the .git directory to another location and create the .git file.
        real_path_abs = osp.abspath(join_path_native(rwrepo.working_tree_dir, '.real'))
        os.rename(rwrepo.git_dir, real_path_abs)
        git_file_path = join_path_native(rwrepo.working_tree_dir, '.git')
        with open(git_file_path, 'wb') as fp:
            fp.write(fixture('git_file'))

        # Create a repo and make sure it's pointing to the relocated .git directory.
        git_file_repo = Repo(rwrepo.working_tree_dir)
        self.assertEqual(osp.abspath(git_file_repo.git_dir), real_path_abs)

        # Test using an absolute gitdir path in the .git file.
        with open(git_file_path, 'wb') as fp:
            fp.write(('gitdir: %s\n' % real_path_abs).encode('ascii'))
        git_file_repo = Repo(rwrepo.working_tree_dir)
        self.assertEqual(osp.abspath(git_file_repo.git_dir), real_path_abs)

    def test_file_handle_leaks(self):
        def last_commit(repo, rev, path):
            commit = next(repo.iter_commits(rev, path, max_count=1))
            commit.tree[path]

        # This is based on this comment
        # https://github.com/gitpython-developers/GitPython/issues/60#issuecomment-23558741
        # And we expect to set max handles to a low value, like 64
        # You should set ulimit -n X, see .travis.yml
        # The loops below would easily create 500 handles if these would leak (4 pipes + multiple mapped files)
        for _ in range(64):
            for repo_type in (GitCmdObjectDB, GitDB):
                repo = Repo(self.rorepo.working_tree_dir, odbt=repo_type)
                last_commit(repo, 'master', 'git/test/test_base.py')
            # end for each repository type
        # end for each iteration

    def test_remote_method(self):
        self.failUnlessRaises(ValueError, self.rorepo.remote, 'foo-blue')
        self.assertIsInstance(self.rorepo.remote(name='origin'), Remote)

    @with_rw_directory
    def test_empty_repo(self, rw_dir):
        """Assure we can handle empty repositories"""
        r = Repo.init(rw_dir, mkdir=False)
        # It's ok not to be able to iterate a commit, as there is none
        self.failUnlessRaises(ValueError, r.iter_commits)
        self.assertEqual(r.active_branch.name, 'master')
        assert not r.active_branch.is_valid(), "Branch is yet to be born"

        # actually, when trying to create a new branch without a commit, git itself fails
        # We should, however, not fail ungracefully
        self.failUnlessRaises(BadName, r.create_head, 'foo')
        self.failUnlessRaises(BadName, r.create_head, 'master')
        # It's expected to not be able to access a tree
        self.failUnlessRaises(ValueError, r.tree)

        new_file_path = osp.join(rw_dir, "new_file.ext")
        touch(new_file_path)
        r.index.add([new_file_path])
        r.index.commit("initial commit\nBAD MESSAGE 1\n")

        # Now a branch should be creatable
        nb = r.create_head('foo')
        assert nb.is_valid()

        with open(new_file_path, 'w') as f:
            f.write('Line 1\n')

        r.index.add([new_file_path])
        r.index.commit("add line 1\nBAD MESSAGE 2\n")

        with open('%s/.git/logs/refs/heads/master' % (rw_dir,), 'r') as f:
            contents = f.read()

        assert 'BAD MESSAGE' not in contents, 'log is corrupt'

    def test_merge_base(self):
        repo = self.rorepo
        c1 = 'f6aa8d1'
        c2 = repo.commit('d46e3fe')
        c3 = '763ef75'
        self.failUnlessRaises(ValueError, repo.merge_base)
        self.failUnlessRaises(ValueError, repo.merge_base, 'foo')

        # two commit merge-base
        res = repo.merge_base(c1, c2)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 1)
        self.assertIsInstance(res[0], Commit)
        self.assertTrue(res[0].hexsha.startswith('3936084'))

        for kw in ('a', 'all'):
            res = repo.merge_base(c1, c2, c3, **{kw: True})
            self.assertIsInstance(res, list)
            self.assertEqual(len(res), 1)
        # end for each keyword signalling all merge-bases to be returned

        # Test for no merge base - can't do as we have
        self.failUnlessRaises(GitCommandError, repo.merge_base, c1, 'ffffff')

    def test_is_ancestor(self):
        git = self.rorepo.git
        if git.version_info[:3] < (1, 8, 0):
            raise SkipTest("git merge-base --is-ancestor feature unsupported")

        repo = self.rorepo
        c1 = 'f6aa8d1'
        c2 = '763ef75'
        self.assertTrue(repo.is_ancestor(c1, c1))
        self.assertTrue(repo.is_ancestor("master", "master"))
        self.assertTrue(repo.is_ancestor(c1, c2))
        self.assertTrue(repo.is_ancestor(c1, "master"))
        self.assertFalse(repo.is_ancestor(c2, c1))
        self.assertFalse(repo.is_ancestor("master", c1))
        for i, j in itertools.permutations([c1, 'ffffff', ''], r=2):
            self.assertRaises(GitCommandError, repo.is_ancestor, i, j)

    @with_rw_directory
    def test_git_work_tree_dotgit(self, rw_dir):
        """Check that we find .git as a worktree file and find the worktree
        based on it."""
        git = Git(rw_dir)
        if git.version_info[:3] < (2, 5, 1):
            raise SkipTest("worktree feature unsupported")

        rw_master = self.rorepo.clone(join_path_native(rw_dir, 'master_repo'))
        branch = rw_master.create_head('aaaaaaaa')
        worktree_path = join_path_native(rw_dir, 'worktree_repo')
        if Git.is_cygwin():
            worktree_path = cygpath(worktree_path)
        rw_master.git.worktree('add', worktree_path, branch.name)

        # this ensures that we can read the repo's gitdir correctly
        repo = Repo(worktree_path)
        self.assertIsInstance(repo, Repo)

        # this ensures we're able to actually read the refs in the tree, which
        # means we can read commondir correctly.
        commit = repo.head.commit
        self.assertIsInstance(commit, Object)

        self.assertIsInstance(repo.heads['aaaaaaaa'], Head)

    @with_rw_directory
    def test_git_work_tree_env(self, rw_dir):
        """Check that we yield to GIT_WORK_TREE"""
        # clone a repo
        # move .git directory to a subdirectory
        # set GIT_DIR and GIT_WORK_TREE appropriately
        # check that repo.working_tree_dir == rw_dir
        self.rorepo.clone(join_path_native(rw_dir, 'master_repo'))

        repo_dir = join_path_native(rw_dir, 'master_repo')
        old_git_dir = join_path_native(repo_dir, '.git')
        new_subdir = join_path_native(repo_dir, 'gitdir')
        new_git_dir = join_path_native(new_subdir, 'git')
        os.mkdir(new_subdir)
        os.rename(old_git_dir, new_git_dir)

        oldenv = os.environ.copy()
        os.environ['GIT_DIR'] = new_git_dir
        os.environ['GIT_WORK_TREE'] = repo_dir

        try:
            r = Repo()
            self.assertEqual(r.working_tree_dir, repo_dir)
            self.assertEqual(r.working_dir, repo_dir)
        finally:
            os.environ = oldenv
