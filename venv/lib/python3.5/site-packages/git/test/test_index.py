# -*- coding: utf-8 -*-
# test_index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from io import BytesIO
import os
from stat import (
    S_ISLNK,
    ST_MODE
)
import sys
import tempfile
try:
    from unittest import skipIf
except ImportError:
    from unittest2 import skipIf

from git import (
    IndexFile,
    Repo,
    BlobFilter,
    UnmergedEntriesError,
    Tree,
    Object,
    Diff,
    GitCommandError,
    CheckoutError,
)
from git.compat import string_types, is_win, PY3
from git.exc import (
    HookExecutionError,
    InvalidGitRepositoryError
)
from git.index.fun import hook_path
from git.index.typ import (
    BaseIndexEntry,
    IndexEntry
)
from git.objects import Blob
from git.test.lib import (
    TestBase,
    fixture_path,
    fixture,
    with_rw_repo
)
from git.test.lib import with_rw_directory
from git.util import Actor, rmtree
from git.util import HIDE_WINDOWS_KNOWN_ERRORS, hex_to_bin
from gitdb.base import IStream

import os.path as osp
from git.cmd import Git

HOOKS_SHEBANG = "#!/usr/bin/env sh\n"


@skipIf(HIDE_WINDOWS_KNOWN_ERRORS, "TODO: fix hooks execution on Windows: #703")
def _make_hook(git_dir, name, content, make_exec=True):
    """A helper to create a hook"""
    hp = hook_path(name, git_dir)
    hpd = osp.dirname(hp)
    if not osp.isdir(hpd):
        os.mkdir(hpd)
    with open(hp, "wt") as fp:
        fp.write(HOOKS_SHEBANG + content)
    if make_exec:
        os.chmod(hp, 0o744)
    return hp


class TestIndex(TestBase):

    def __init__(self, *args):
        super(TestIndex, self).__init__(*args)
        self._reset_progress()

    def _assert_fprogress(self, entries):
        self.assertEqual(len(entries), len(self._fprogress_map))
        for path, call_count in self._fprogress_map.items():  # @UnusedVariable
            self.assertEqual(call_count, 2)
        # END for each item in progress map
        self._reset_progress()

    def _fprogress(self, path, done, item):
        self._fprogress_map.setdefault(path, 0)
        curval = self._fprogress_map[path]
        if curval == 0:
            assert not done
        if curval == 1:
            assert done
        self._fprogress_map[path] = curval + 1

    def _fprogress_add(self, path, done, item):
        """Called as progress func - we keep track of the proper
        call order"""
        assert item is not None
        self._fprogress(path, done, item)

    def _reset_progress(self):
        # maps paths to the count of calls
        self._fprogress_map = dict()

    def _assert_entries(self, entries):
        for entry in entries:
            assert isinstance(entry, BaseIndexEntry)
            assert not osp.isabs(entry.path)
            assert "\\" not in entry.path
        # END for each entry

    def test_index_file_base(self):
        # read from file
        index = IndexFile(self.rorepo, fixture_path("index"))
        assert index.entries
        assert index.version > 0

        # test entry
        entry = next(iter(index.entries.values()))
        for attr in ("path", "ctime", "mtime", "dev", "inode", "mode", "uid",
                     "gid", "size", "binsha", "hexsha", "stage"):
            getattr(entry, attr)
        # END for each method

        # test update
        entries = index.entries
        assert isinstance(index.update(), IndexFile)
        assert entries is not index.entries

        # test stage
        index_merge = IndexFile(self.rorepo, fixture_path("index_merge"))
        self.assertEqual(len(index_merge.entries), 106)
        assert len(list(e for e in index_merge.entries.values() if e.stage != 0))

        # write the data - it must match the original
        tmpfile = tempfile.mktemp()
        index_merge.write(tmpfile)
        with open(tmpfile, 'rb') as fp:
            self.assertEqual(fp.read(), fixture("index_merge"))
        os.remove(tmpfile)

    def _cmp_tree_index(self, tree, index):
        # fail unless both objects contain the same paths and blobs
        if isinstance(tree, str):
            tree = self.rorepo.commit(tree).tree

        blist = list()
        for blob in tree.traverse(predicate=lambda e, d: e.type == "blob", branch_first=False):
            assert (blob.path, 0) in index.entries
            blist.append(blob)
        # END for each blob in tree
        if len(blist) != len(index.entries):
            iset = set(k[0] for k in index.entries.keys())
            bset = set(b.path for b in blist)
            raise AssertionError("CMP Failed: Missing entries in index: %s, missing in tree: %s" %
                                 (bset - iset, iset - bset))
        # END assertion message

    @with_rw_repo('0.1.6')
    def test_index_lock_handling(self, rw_repo):
        def add_bad_blob():
            rw_repo.index.add([Blob(rw_repo, b'f' * 20, 'bad-permissions', 'foo')])

        try:
            ## 1st fail on purpose adding into index.
            add_bad_blob()
        except Exception as ex:
            msg_py3 = "required argument is not an integer"
            msg_py2 = "cannot convert argument to integer"
            msg_py26 = "unsupported operand type(s) for &: 'str' and 'long'"
            assert msg_py2 in str(ex) or msg_py3 in str(ex) or \
                msg_py26 in str(ex), str(ex)

        ## 2nd time should not fail due to stray lock file
        try:
            add_bad_blob()
        except Exception as ex:
            assert "index.lock' could not be obtained" not in str(ex)

    @with_rw_repo('0.1.6')
    def test_index_file_from_tree(self, rw_repo):
        if sys.version_info < (2, 7):
            ## Skipped, not `assertRaisesRegexp` in py2.6
            return
        common_ancestor_sha = "5117c9c8a4d3af19a9958677e45cda9269de1541"
        cur_sha = "4b43ca7ff72d5f535134241e7c797ddc9c7a3573"
        other_sha = "39f85c4358b7346fee22169da9cad93901ea9eb9"

        # simple index from tree
        base_index = IndexFile.from_tree(rw_repo, common_ancestor_sha)
        assert base_index.entries
        self._cmp_tree_index(common_ancestor_sha, base_index)

        # merge two trees - its like a fast-forward
        two_way_index = IndexFile.from_tree(rw_repo, common_ancestor_sha, cur_sha)
        assert two_way_index.entries
        self._cmp_tree_index(cur_sha, two_way_index)

        # merge three trees - here we have a merge conflict
        three_way_index = IndexFile.from_tree(rw_repo, common_ancestor_sha, cur_sha, other_sha)
        assert len(list(e for e in three_way_index.entries.values() if e.stage != 0))

        # ITERATE BLOBS
        merge_required = lambda t: t[0] != 0
        merge_blobs = list(three_way_index.iter_blobs(merge_required))
        assert merge_blobs
        assert merge_blobs[0][0] in (1, 2, 3)
        assert isinstance(merge_blobs[0][1], Blob)

        # test BlobFilter
        prefix = 'lib/git'
        for stage, blob in base_index.iter_blobs(BlobFilter([prefix])):  # @UnusedVariable
            assert blob.path.startswith(prefix)

        # writing a tree should fail with an unmerged index
        self.failUnlessRaises(UnmergedEntriesError, three_way_index.write_tree)

        # removed unmerged entries
        unmerged_blob_map = three_way_index.unmerged_blobs()
        assert unmerged_blob_map

        # pick the first blob at the first stage we find and use it as resolved version
        three_way_index.resolve_blobs(l[0][1] for l in unmerged_blob_map.values())
        tree = three_way_index.write_tree()
        assert isinstance(tree, Tree)
        num_blobs = 0
        for blob in tree.traverse(predicate=lambda item, d: item.type == "blob"):
            assert (blob.path, 0) in three_way_index.entries
            num_blobs += 1
        # END for each blob
        self.assertEqual(num_blobs, len(three_way_index.entries))

    @with_rw_repo('0.1.6')
    def test_index_merge_tree(self, rw_repo):
        # A bit out of place, but we need a different repo for this:
        self.assertNotEqual(self.rorepo, rw_repo)
        self.assertEqual(len(set((self.rorepo, self.rorepo, rw_repo, rw_repo))), 2)

        # SINGLE TREE MERGE
        # current index is at the (virtual) cur_commit
        next_commit = "4c39f9da792792d4e73fc3a5effde66576ae128c"
        parent_commit = rw_repo.head.commit.parents[0]
        manifest_key = IndexFile.entry_key('MANIFEST.in', 0)
        manifest_entry = rw_repo.index.entries[manifest_key]
        rw_repo.index.merge_tree(next_commit)
        # only one change should be recorded
        assert manifest_entry.binsha != rw_repo.index.entries[manifest_key].binsha

        rw_repo.index.reset(rw_repo.head)
        self.assertEqual(rw_repo.index.entries[manifest_key].binsha, manifest_entry.binsha)

        # FAKE MERGE
        #############
        # Add a change with a NULL sha that should conflict with next_commit. We
        # pretend there was a change, but we do not even bother adding a proper
        # sha for it ( which makes things faster of course )
        manifest_fake_entry = BaseIndexEntry((manifest_entry[0], b"\0" * 20, 0, manifest_entry[3]))
        # try write flag
        self._assert_entries(rw_repo.index.add([manifest_fake_entry], write=False))
        # add actually resolves the null-hex-sha for us as a feature, but we can
        # edit the index manually
        assert rw_repo.index.entries[manifest_key].binsha != Object.NULL_BIN_SHA
        # must operate on the same index for this ! Its a bit problematic as
        # it might confuse people
        index = rw_repo.index
        index.entries[manifest_key] = IndexEntry.from_base(manifest_fake_entry)
        index.write()
        self.assertEqual(rw_repo.index.entries[manifest_key].hexsha, Diff.NULL_HEX_SHA)

        # write an unchanged index ( just for the fun of it )
        rw_repo.index.write()

        # a three way merge would result in a conflict and fails as the command will
        # not overwrite any entries in our index and hence leave them unmerged. This is
        # mainly a protection feature as the current index is not yet in a tree
        self.failUnlessRaises(GitCommandError, index.merge_tree, next_commit, base=parent_commit)

        # the only way to get the merged entries is to safe the current index away into a tree,
        # which is like a temporary commit for us. This fails as well as the NULL sha deos not
        # have a corresponding object
        # NOTE: missing_ok is not a kwarg anymore, missing_ok is always true
        # self.failUnlessRaises(GitCommandError, index.write_tree)

        # if missing objects are okay, this would work though ( they are always okay now )
        # As we can't read back the tree with NULL_SHA, we rather set it to something else
        index.entries[manifest_key] = IndexEntry(manifest_entry[:1] + (hex_to_bin('f' * 40),) + manifest_entry[2:])
        tree = index.write_tree()

        # now make a proper three way merge with unmerged entries
        unmerged_tree = IndexFile.from_tree(rw_repo, parent_commit, tree, next_commit)
        unmerged_blobs = unmerged_tree.unmerged_blobs()
        self.assertEqual(len(unmerged_blobs), 1)
        self.assertEqual(list(unmerged_blobs.keys())[0], manifest_key[0])

    @with_rw_repo('0.1.6')
    def test_index_file_diffing(self, rw_repo):
        # default Index instance points to our index
        index = IndexFile(rw_repo)
        assert index.path is not None
        assert len(index.entries)

        # write the file back
        index.write()

        # could sha it, or check stats

        # test diff
        # resetting the head will leave the index in a different state, and the
        # diff will yield a few changes
        cur_head_commit = rw_repo.head.reference.commit
        rw_repo.head.reset('HEAD~6', index=True, working_tree=False)

        # diff against same index is 0
        diff = index.diff()
        self.assertEqual(len(diff), 0)

        # against HEAD as string, must be the same as it matches index
        diff = index.diff('HEAD')
        self.assertEqual(len(diff), 0)

        # against previous head, there must be a difference
        diff = index.diff(cur_head_commit)
        assert len(diff)

        # we reverse the result
        adiff = index.diff(str(cur_head_commit), R=True)
        odiff = index.diff(cur_head_commit, R=False)    # now its not reversed anymore
        assert adiff != odiff
        self.assertEqual(odiff, diff)                    # both unreversed diffs against HEAD

        # against working copy - its still at cur_commit
        wdiff = index.diff(None)
        assert wdiff != adiff
        assert wdiff != odiff

        # against something unusual
        self.failUnlessRaises(ValueError, index.diff, int)

        # adjust the index to match an old revision
        cur_branch = rw_repo.active_branch
        cur_commit = cur_branch.commit
        rev_head_parent = 'HEAD~1'
        assert index.reset(rev_head_parent) is index

        self.assertEqual(cur_branch, rw_repo.active_branch)
        self.assertEqual(cur_commit, rw_repo.head.commit)

        # there must be differences towards the working tree which is in the 'future'
        assert index.diff(None)

        # reset the working copy as well to current head,to pull 'back' as well
        new_data = b"will be reverted"
        file_path = osp.join(rw_repo.working_tree_dir, "CHANGES")
        with open(file_path, "wb") as fp:
            fp.write(new_data)
        index.reset(rev_head_parent, working_tree=True)
        assert not index.diff(None)
        self.assertEqual(cur_branch, rw_repo.active_branch)
        self.assertEqual(cur_commit, rw_repo.head.commit)
        with open(file_path, 'rb') as fp:
            assert fp.read() != new_data

        # test full checkout
        test_file = osp.join(rw_repo.working_tree_dir, "CHANGES")
        with open(test_file, 'ab') as fd:
            fd.write(b"some data")
        rval = index.checkout(None, force=True, fprogress=self._fprogress)
        assert 'CHANGES' in list(rval)
        self._assert_fprogress([None])
        assert osp.isfile(test_file)

        os.remove(test_file)
        rval = index.checkout(None, force=False, fprogress=self._fprogress)
        assert 'CHANGES' in list(rval)
        self._assert_fprogress([None])
        assert osp.isfile(test_file)

        # individual file
        os.remove(test_file)
        rval = index.checkout(test_file, fprogress=self._fprogress)
        self.assertEqual(list(rval)[0], 'CHANGES')
        self._assert_fprogress([test_file])
        assert osp.exists(test_file)

        # checking out non-existing file throws
        self.failUnlessRaises(CheckoutError, index.checkout, "doesnt_exist_ever.txt.that")
        self.failUnlessRaises(CheckoutError, index.checkout, paths=["doesnt/exist"])

        # checkout file with modifications
        append_data = b"hello"
        with open(test_file, "ab") as fp:
            fp.write(append_data)
        try:
            index.checkout(test_file)
        except CheckoutError as e:
            self.assertEqual(len(e.failed_files), 1)
            self.assertEqual(e.failed_files[0], osp.basename(test_file))
            self.assertEqual(len(e.failed_files), len(e.failed_reasons))
            self.assertIsInstance(e.failed_reasons[0], string_types)
            self.assertEqual(len(e.valid_files), 0)
            with open(test_file, 'rb') as fd:
                s = fd.read()
            self.assertTrue(s.endswith(append_data), s)
        else:
            raise AssertionError("Exception CheckoutError not thrown")

        # if we force it it should work
        index.checkout(test_file, force=True)
        assert not open(test_file, 'rb').read().endswith(append_data)

        # checkout directory
        rmtree(osp.join(rw_repo.working_tree_dir, "lib"))
        rval = index.checkout('lib')
        assert len(list(rval)) > 1

    def _count_existing(self, repo, files):
        """
        Returns count of files that actually exist in the repository directory.
        """
        existing = 0
        basedir = repo.working_tree_dir
        for f in files:
            existing += osp.isfile(osp.join(basedir, f))
        # END for each deleted file
        return existing
    # END num existing helper

    @skipIf(HIDE_WINDOWS_KNOWN_ERRORS and Git.is_cygwin(),
            """FIXME: File "C:\\projects\\gitpython\\git\\test\\test_index.py", line 642, in test_index_mutation
                self.assertEqual(fd.read(), link_target)
                AssertionError: '!<symlink>\xff\xfe/\x00e\x00t\x00c\x00/\x00t\x00h\x00a\x00t\x00\x00\x00'
                != '/etc/that'
                """)
    @with_rw_repo('0.1.6')
    def test_index_mutation(self, rw_repo):
        index = rw_repo.index
        num_entries = len(index.entries)
        cur_head = rw_repo.head

        uname = u"Thomas Müller"
        umail = "sd@company.com"
        with rw_repo.config_writer() as writer:
            writer.set_value("user", "name", uname)
            writer.set_value("user", "email", umail)
        self.assertEqual(writer.get_value("user", "name"), uname)

        # remove all of the files, provide a wild mix of paths, BaseIndexEntries,
        # IndexEntries
        def mixed_iterator():
            count = 0
            for entry in index.entries.values():
                type_id = count % 4
                if type_id == 0:    # path
                    yield entry.path
                elif type_id == 1:  # blob
                    yield Blob(rw_repo, entry.binsha, entry.mode, entry.path)
                elif type_id == 2:  # BaseIndexEntry
                    yield BaseIndexEntry(entry[:4])
                elif type_id == 3:  # IndexEntry
                    yield entry
                else:
                    raise AssertionError("Invalid Type")
                count += 1
            # END for each entry
        # END mixed iterator
        deleted_files = index.remove(mixed_iterator(), working_tree=False)
        assert deleted_files
        self.assertEqual(self._count_existing(rw_repo, deleted_files), len(deleted_files))
        self.assertEqual(len(index.entries), 0)

        # reset the index to undo our changes
        index.reset()
        self.assertEqual(len(index.entries), num_entries)

        # remove with working copy
        deleted_files = index.remove(mixed_iterator(), working_tree=True)
        assert deleted_files
        self.assertEqual(self._count_existing(rw_repo, deleted_files), 0)

        # reset everything
        index.reset(working_tree=True)
        self.assertEqual(self._count_existing(rw_repo, deleted_files), len(deleted_files))

        # invalid type
        self.failUnlessRaises(TypeError, index.remove, [1])

        # absolute path
        deleted_files = index.remove([osp.join(rw_repo.working_tree_dir, "lib")], r=True)
        assert len(deleted_files) > 1
        self.failUnlessRaises(ValueError, index.remove, ["/doesnt/exists"])

        # TEST COMMITTING
        # commit changed index
        cur_commit = cur_head.commit
        commit_message = u"commit default head by Frèderic Çaufl€"

        new_commit = index.commit(commit_message, head=False)
        assert cur_commit != new_commit
        self.assertEqual(new_commit.author.name, uname)
        self.assertEqual(new_commit.author.email, umail)
        self.assertEqual(new_commit.committer.name, uname)
        self.assertEqual(new_commit.committer.email, umail)
        self.assertEqual(new_commit.message, commit_message)
        self.assertEqual(new_commit.parents[0], cur_commit)
        self.assertEqual(len(new_commit.parents), 1)
        self.assertEqual(cur_head.commit, cur_commit)

        # commit with other actor
        cur_commit = cur_head.commit

        my_author = Actor(u"Frèderic Çaufl€", "author@example.com")
        my_committer = Actor(u"Committing Frèderic Çaufl€", "committer@example.com")
        commit_actor = index.commit(commit_message, author=my_author, committer=my_committer)
        assert cur_commit != commit_actor
        self.assertEqual(commit_actor.author.name, u"Frèderic Çaufl€")
        self.assertEqual(commit_actor.author.email, "author@example.com")
        self.assertEqual(commit_actor.committer.name, u"Committing Frèderic Çaufl€")
        self.assertEqual(commit_actor.committer.email, "committer@example.com")
        self.assertEqual(commit_actor.message, commit_message)
        self.assertEqual(commit_actor.parents[0], cur_commit)
        self.assertEqual(len(new_commit.parents), 1)
        self.assertEqual(cur_head.commit, commit_actor)
        self.assertEqual(cur_head.log()[-1].actor, my_committer)

        # commit with author_date and commit_date
        cur_commit = cur_head.commit
        commit_message = u"commit with dates by Avinash Sajjanshetty"

        new_commit = index.commit(commit_message, author_date="2006-04-07T22:13:13", commit_date="2005-04-07T22:13:13")
        assert cur_commit != new_commit
        print(new_commit.authored_date, new_commit.committed_date)
        self.assertEqual(new_commit.message, commit_message)
        self.assertEqual(new_commit.authored_date, 1144447993)
        self.assertEqual(new_commit.committed_date, 1112911993)

        # same index, no parents
        commit_message = "index without parents"
        commit_no_parents = index.commit(commit_message, parent_commits=list(), head=True)
        self.assertEqual(commit_no_parents.message, commit_message)
        self.assertEqual(len(commit_no_parents.parents), 0)
        self.assertEqual(cur_head.commit, commit_no_parents)

        # same index, multiple parents
        commit_message = "Index with multiple parents\n    commit with another line"
        commit_multi_parent = index.commit(commit_message, parent_commits=(commit_no_parents, new_commit))
        self.assertEqual(commit_multi_parent.message, commit_message)
        self.assertEqual(len(commit_multi_parent.parents), 2)
        self.assertEqual(commit_multi_parent.parents[0], commit_no_parents)
        self.assertEqual(commit_multi_parent.parents[1], new_commit)
        self.assertEqual(cur_head.commit, commit_multi_parent)

        # re-add all files in lib
        # get the lib folder back on disk, but get an index without it
        index.reset(new_commit.parents[0], working_tree=True).reset(new_commit, working_tree=False)
        lib_file_path = osp.join("lib", "git", "__init__.py")
        assert (lib_file_path, 0) not in index.entries
        assert osp.isfile(osp.join(rw_repo.working_tree_dir, lib_file_path))

        # directory
        entries = index.add(['lib'], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        assert len(entries) > 1

        # glob
        entries = index.reset(new_commit).add([osp.join('lib', 'git', '*.py')], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(len(entries), 14)

        # same file
        entries = index.reset(new_commit).add(
            [osp.join(rw_repo.working_tree_dir, 'lib', 'git', 'head.py')] * 2, fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self.assertEqual(entries[0].mode & 0o644, 0o644)
        # would fail, test is too primitive to handle this case
        # self._assert_fprogress(entries)
        self._reset_progress()
        self.assertEqual(len(entries), 2)

        # missing path
        self.failUnlessRaises(OSError, index.reset(new_commit).add, ['doesnt/exist/must/raise'])

        # blob from older revision overrides current index revision
        old_blob = new_commit.parents[0].tree.blobs[0]
        entries = index.reset(new_commit).add([old_blob], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(index.entries[(old_blob.path, 0)].hexsha, old_blob.hexsha)
        self.assertEqual(len(entries), 1)

        # mode 0 not allowed
        null_hex_sha = Diff.NULL_HEX_SHA
        null_bin_sha = b"\0" * 20
        self.failUnlessRaises(ValueError, index.reset(
            new_commit).add, [BaseIndexEntry((0, null_bin_sha, 0, "doesntmatter"))])

        # add new file
        new_file_relapath = "my_new_file"
        self._make_file(new_file_relapath, "hello world", rw_repo)
        entries = index.reset(new_commit).add(
            [BaseIndexEntry((0o10644, null_bin_sha, 0, new_file_relapath))], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        self.assertEqual(len(entries), 1)
        self.assertNotEquals(entries[0].hexsha, null_hex_sha)

        # add symlink
        if not is_win:
            for target in ('/etc/nonexisting', '/etc/passwd', '/etc'):
                basename = "my_real_symlink"

                link_file = osp.join(rw_repo.working_tree_dir, basename)
                os.symlink(target, link_file)
                entries = index.reset(new_commit).add([link_file], fprogress=self._fprogress_add)
                self._assert_entries(entries)
                self._assert_fprogress(entries)
                self.assertEqual(len(entries), 1)
                self.assertTrue(S_ISLNK(entries[0].mode))
                self.assertTrue(S_ISLNK(index.entries[index.entry_key("my_real_symlink", 0)].mode))

                # we expect only the target to be written
                self.assertEqual(index.repo.odb.stream(entries[0].binsha).read().decode('ascii'), target)

                os.remove(link_file)
            # end for each target
        # END real symlink test

        # add fake symlink and assure it checks-our as symlink
        fake_symlink_relapath = "my_fake_symlink"
        link_target = "/etc/that"
        fake_symlink_path = self._make_file(fake_symlink_relapath, link_target, rw_repo)
        fake_entry = BaseIndexEntry((0o120000, null_bin_sha, 0, fake_symlink_relapath))
        entries = index.reset(new_commit).add([fake_entry], fprogress=self._fprogress_add)
        self._assert_entries(entries)
        self._assert_fprogress(entries)
        assert entries[0].hexsha != null_hex_sha
        self.assertEqual(len(entries), 1)
        self.assertTrue(S_ISLNK(entries[0].mode))

        # assure this also works with an alternate method
        full_index_entry = IndexEntry.from_base(BaseIndexEntry((0o120000, entries[0].binsha, 0, entries[0].path)))
        entry_key = index.entry_key(full_index_entry)
        index.reset(new_commit)

        assert entry_key not in index.entries
        index.entries[entry_key] = full_index_entry
        index.write()
        index.update()  # force reread of entries
        new_entry = index.entries[entry_key]
        assert S_ISLNK(new_entry.mode)

        # a tree created from this should contain the symlink
        tree = index.write_tree()
        assert fake_symlink_relapath in tree
        index.write()                       # flush our changes for the checkout

        # checkout the fakelink, should be a link then
        assert not S_ISLNK(os.stat(fake_symlink_path)[ST_MODE])
        os.remove(fake_symlink_path)
        index.checkout(fake_symlink_path)

        # on windows we will never get symlinks
        if is_win:
            # simlinks should contain the link as text ( which is what a
            # symlink actually is )
            with open(fake_symlink_path, 'rt') as fd:
                self.assertEqual(fd.read(), link_target)
        else:
            self.assertTrue(S_ISLNK(os.lstat(fake_symlink_path)[ST_MODE]))

        # TEST RENAMING
        def assert_mv_rval(rval):
            for source, dest in rval:
                assert not osp.exists(source) and osp.exists(dest)
            # END for each renamed item
        # END move assertion utility

        self.failUnlessRaises(ValueError, index.move, ['just_one_path'])
        # file onto existing file
        files = ['AUTHORS', 'LICENSE']
        self.failUnlessRaises(GitCommandError, index.move, files)

        # again, with force
        assert_mv_rval(index.move(files, f=True))

        # files into directory - dry run
        paths = ['LICENSE', 'VERSION', 'doc']
        rval = index.move(paths, dry_run=True)
        self.assertEqual(len(rval), 2)
        assert osp.exists(paths[0])

        # again, no dry run
        rval = index.move(paths)
        assert_mv_rval(rval)

        # dir into dir
        rval = index.move(['doc', 'test'])
        assert_mv_rval(rval)

        # TEST PATH REWRITING
        ######################
        count = [0]

        def rewriter(entry):
            rval = str(count[0])
            count[0] += 1
            return rval
        # END rewriter

        def make_paths():
            # two existing ones, one new one
            yield 'CHANGES'
            yield 'ez_setup.py'
            yield index.entries[index.entry_key('README', 0)]
            yield index.entries[index.entry_key('.gitignore', 0)]

            for fid in range(3):
                fname = 'newfile%i' % fid
                with open(fname, 'wb') as fd:
                    fd.write(b"abcd")
                yield Blob(rw_repo, Blob.NULL_BIN_SHA, 0o100644, fname)
            # END for each new file
        # END path producer
        paths = list(make_paths())
        self._assert_entries(index.add(paths, path_rewriter=rewriter))

        for filenum in range(len(paths)):
            assert index.entry_key(str(filenum), 0) in index.entries

        # TEST RESET ON PATHS
        ######################
        arela = "aa"
        brela = "bb"
        afile = self._make_file(arela, "adata", rw_repo)
        bfile = self._make_file(brela, "bdata", rw_repo)
        akey = index.entry_key(arela, 0)
        bkey = index.entry_key(brela, 0)
        keys = (akey, bkey)
        absfiles = (afile, bfile)
        files = (arela, brela)

        for fkey in keys:
            assert fkey not in index.entries

        index.add(files, write=True)
        nc = index.commit("2 files committed", head=False)

        for fkey in keys:
            assert fkey in index.entries

        # just the index
        index.reset(paths=(arela, afile))
        assert akey not in index.entries
        assert bkey in index.entries

        # now with working tree - files on disk as well as entries must be recreated
        rw_repo.head.commit = nc
        for absfile in absfiles:
            os.remove(absfile)

        index.reset(working_tree=True, paths=files)

        for fkey in keys:
            assert fkey in index.entries
        for absfile in absfiles:
            assert osp.isfile(absfile)

    @with_rw_repo('HEAD')
    def test_compare_write_tree(self, rw_repo):
        # write all trees and compare them
        # its important to have a few submodules in there too
        max_count = 25
        count = 0
        for commit in rw_repo.head.commit.traverse():
            if count >= max_count:
                break
            count += 1
            index = rw_repo.index.reset(commit)
            orig_tree = commit.tree
            self.assertEqual(index.write_tree(), orig_tree)
        # END for each commit

    def test_index_new(self):
        B = self.rorepo.tree("6d9b1f4f9fa8c9f030e3207e7deacc5d5f8bba4e")
        H = self.rorepo.tree("25dca42bac17d511b7e2ebdd9d1d679e7626db5f")
        M = self.rorepo.tree("e746f96bcc29238b79118123028ca170adc4ff0f")

        for args in ((B,), (B, H), (B, H, M)):
            index = IndexFile.new(self.rorepo, *args)
            assert isinstance(index, IndexFile)
        # END for each arg tuple

    @with_rw_repo('HEAD', bare=True)
    def test_index_bare_add(self, rw_bare_repo):
        # Something is wrong after cloning to a bare repo, reading the
        # property rw_bare_repo.working_tree_dir will return '/tmp'
        # instead of throwing the Exception we are expecting. This is
        # a quick hack to make this test fail when expected.
        assert rw_bare_repo.working_tree_dir is None
        assert rw_bare_repo.bare
        contents = b'This is a BytesIO file'
        filesize = len(contents)
        fileobj = BytesIO(contents)
        filename = 'my-imaginary-file'
        istream = rw_bare_repo.odb.store(
            IStream(Blob.type, filesize, fileobj))
        entry = BaseIndexEntry((0o100644, istream.binsha, 0, filename))
        try:
            rw_bare_repo.index.add([entry])
        except AssertionError:
            self.fail("Adding to the index of a bare repo is not allowed.")

        # Adding using a path should still require a non-bare repository.
        asserted = False
        path = osp.join('git', 'test', 'test_index.py')
        try:
            rw_bare_repo.index.add([path])
        except InvalidGitRepositoryError:
            asserted = True
        assert asserted, "Adding using a filename is not correctly asserted."

    @skipIf(HIDE_WINDOWS_KNOWN_ERRORS and not PY3, r"""
        FIXME:  File "C:\projects\gitpython\git\util.py", line 125, in to_native_path_linux
        return path.replace('\\', '/')
        UnicodeDecodeError: 'ascii' codec can't decode byte 0xc3 in position 0: ordinal not in range(128)""")
    @with_rw_directory
    def test_add_utf8P_path(self, rw_dir):
        # NOTE: fp is not a Unicode object in python 2 (which is the source of the problem)
        fp = osp.join(rw_dir, 'ø.txt')
        with open(fp, 'wb') as fs:
            fs.write(u'content of ø'.encode('utf-8'))

        r = Repo.init(rw_dir)
        r.index.add([fp])
        r.index.commit('Added orig and prestable')

    @with_rw_directory
    def test_add_a_file_with_wildcard_chars(self, rw_dir):
        # see issue #407
        fp = osp.join(rw_dir, '[.exe')
        with open(fp, "wb") as f:
            f.write(b'something')

        r = Repo.init(rw_dir)
        r.index.add([fp])
        r.index.commit('Added [.exe')

    @with_rw_repo('HEAD', bare=True)
    def test_pre_commit_hook_success(self, rw_repo):
        index = rw_repo.index
        _make_hook(
            index.repo.git_dir,
            'pre-commit',
            "exit 0"
        )
        index.commit("This should not fail")

    @with_rw_repo('HEAD', bare=True)
    def test_pre_commit_hook_fail(self, rw_repo):
        index = rw_repo.index
        hp = _make_hook(
            index.repo.git_dir,
            'pre-commit',
            "echo stdout; echo stderr 1>&2; exit 1"
        )
        try:
            index.commit("This should fail")
        except HookExecutionError as err:
            if is_win:
                self.assertIsInstance(err.status, OSError)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, '')
                self.assertEqual(err.stderr, '')
                assert str(err)
            else:
                self.assertEqual(err.status, 1)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "\n  stdout: 'stdout\n'")
                self.assertEqual(err.stderr, "\n  stderr: 'stderr\n'")
                assert str(err)
        else:
            raise AssertionError("Should have caught a HookExecutionError")

    @with_rw_repo('HEAD', bare=True)
    def test_commit_msg_hook_success(self, rw_repo):
        commit_message = u"commit default head by Frèderic Çaufl€"
        from_hook_message = u"from commit-msg"
        index = rw_repo.index
        _make_hook(
            index.repo.git_dir,
            'commit-msg',
            'echo -n " {0}" >> "$1"'.format(from_hook_message)
        )
        new_commit = index.commit(commit_message)
        self.assertEqual(new_commit.message, u"{0} {1}".format(commit_message, from_hook_message))

    @with_rw_repo('HEAD', bare=True)
    def test_commit_msg_hook_fail(self, rw_repo):
        index = rw_repo.index
        hp = _make_hook(
            index.repo.git_dir,
            'commit-msg',
            "echo stdout; echo stderr 1>&2; exit 1"
        )
        try:
            index.commit("This should fail")
        except HookExecutionError as err:
            if is_win:
                self.assertIsInstance(err.status, OSError)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, '')
                self.assertEqual(err.stderr, '')
                assert str(err)
            else:
                self.assertEqual(err.status, 1)
                self.assertEqual(err.command, [hp])
                self.assertEqual(err.stdout, "\n  stdout: 'stdout\n'")
                self.assertEqual(err.stderr, "\n  stderr: 'stderr\n'")
                assert str(err)
        else:
            raise AssertionError("Should have cought a HookExecutionError")
