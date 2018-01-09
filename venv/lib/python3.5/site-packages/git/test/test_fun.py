from io import BytesIO
from stat import S_IFDIR, S_IFREG, S_IFLNK
from os import stat
import os.path as osp

try:
    from unittest import skipIf, SkipTest
except ImportError:
    from unittest2 import skipIf, SkipTest

from git import Git
from git.compat import PY3
from git.index import IndexFile
from git.index.fun import (
    aggressive_tree_merge
)
from git.objects.fun import (
    traverse_tree_recursive,
    traverse_trees_recursive,
    tree_to_stream,
    tree_entries_from_data,
)
from git.repo.fun import (
    find_worktree_git_dir
)
from git.test.lib import (
    assert_true,
    TestBase,
    with_rw_repo,
    with_rw_directory
)
from git.util import bin_to_hex, cygpath, join_path_native
from gitdb.base import IStream
from gitdb.typ import str_tree_type


class TestFun(TestBase):

    def _assert_index_entries(self, entries, trees):
        index = IndexFile.from_tree(self.rorepo, *[self.rorepo.tree(bin_to_hex(t).decode('ascii')) for t in trees])
        assert entries
        assert len(index.entries) == len(entries)
        for entry in entries:
            assert (entry.path, entry.stage) in index.entries
        # END assert entry matches fully

    def test_aggressive_tree_merge(self):
        # head tree with additions, removals and modification compared to its predecessor
        odb = self.rorepo.odb
        HC = self.rorepo.commit("6c1faef799095f3990e9970bc2cb10aa0221cf9c")
        H = HC.tree
        B = HC.parents[0].tree

        # entries from single tree
        trees = [H.binsha]
        self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)

        # from multiple trees
        trees = [B.binsha, H.binsha]
        self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)

        # three way, no conflict
        tree = self.rorepo.tree
        B = tree("35a09c0534e89b2d43ec4101a5fb54576b577905")
        H = tree("4fe5cfa0e063a8d51a1eb6f014e2aaa994e5e7d4")
        M = tree("1f2b19de3301e76ab3a6187a49c9c93ff78bafbd")
        trees = [B.binsha, H.binsha, M.binsha]
        self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)

        # three-way, conflict in at least one file, both modified
        B = tree("a7a4388eeaa4b6b94192dce67257a34c4a6cbd26")
        H = tree("f9cec00938d9059882bb8eabdaf2f775943e00e5")
        M = tree("44a601a068f4f543f73fd9c49e264c931b1e1652")
        trees = [B.binsha, H.binsha, M.binsha]
        self._assert_index_entries(aggressive_tree_merge(odb, trees), trees)

        # too many trees
        self.failUnlessRaises(ValueError, aggressive_tree_merge, odb, trees * 2)

    def mktree(self, odb, entries):
        """create a tree from the given tree entries and safe it to the database"""
        sio = BytesIO()
        tree_to_stream(entries, sio.write)
        sio.seek(0)
        istream = odb.store(IStream(str_tree_type, len(sio.getvalue()), sio))
        return istream.binsha

    @with_rw_repo('0.1.6')
    def test_three_way_merge(self, rwrepo):
        def mkfile(name, sha, executable=0):
            return (sha, S_IFREG | 0o644 | executable * 0o111, name)

        def mkcommit(name, sha):
            return (sha, S_IFDIR | S_IFLNK, name)

        def assert_entries(entries, num_entries, has_conflict=False):
            assert len(entries) == num_entries
            assert has_conflict == (len([e for e in entries if e.stage != 0]) > 0)
        mktree = self.mktree

        shaa = b"\1" * 20
        shab = b"\2" * 20
        shac = b"\3" * 20

        odb = rwrepo.odb

        # base tree
        bfn = 'basefile'
        fbase = mkfile(bfn, shaa)
        tb = mktree(odb, [fbase])

        # non-conflicting new files, same data
        fa = mkfile('1', shab)
        th = mktree(odb, [fbase, fa])
        fb = mkfile('2', shac)
        tm = mktree(odb, [fbase, fb])

        # two new files, same base file
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 3)

        # both delete same file, add own one
        fa = mkfile('1', shab)
        th = mktree(odb, [fa])
        fb = mkfile('2', shac)
        tm = mktree(odb, [fb])

        # two new files
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 2)

        # same file added in both, differently
        fa = mkfile('1', shab)
        th = mktree(odb, [fa])
        fb = mkfile('1', shac)
        tm = mktree(odb, [fb])

        # expect conflict
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 2, True)

        # same file added, different mode
        fa = mkfile('1', shab)
        th = mktree(odb, [fa])
        fb = mkcommit('1', shab)
        tm = mktree(odb, [fb])

        # expect conflict
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 2, True)

        # same file added in both
        fa = mkfile('1', shab)
        th = mktree(odb, [fa])
        fb = mkfile('1', shab)
        tm = mktree(odb, [fb])

        # expect conflict
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 1)

        # modify same base file, differently
        fa = mkfile(bfn, shab)
        th = mktree(odb, [fa])
        fb = mkfile(bfn, shac)
        tm = mktree(odb, [fb])

        # conflict, 3 versions on 3 stages
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 3, True)

        # change mode on same base file, by making one a commit, the other executable
        # no content change ( this is totally unlikely to happen in the real world )
        fa = mkcommit(bfn, shaa)
        th = mktree(odb, [fa])
        fb = mkfile(bfn, shaa, executable=1)
        tm = mktree(odb, [fb])

        # conflict, 3 versions on 3 stages, because of different mode
        trees = [tb, th, tm]
        assert_entries(aggressive_tree_merge(odb, trees), 3, True)

        for is_them in range(2):
            # only we/they change contents
            fa = mkfile(bfn, shab)
            th = mktree(odb, [fa])

            trees = [tb, th, tb]
            if is_them:
                trees = [tb, tb, th]
            entries = aggressive_tree_merge(odb, trees)
            assert len(entries) == 1 and entries[0].binsha == shab

            # only we/they change the mode
            fa = mkcommit(bfn, shaa)
            th = mktree(odb, [fa])

            trees = [tb, th, tb]
            if is_them:
                trees = [tb, tb, th]
            entries = aggressive_tree_merge(odb, trees)
            assert len(entries) == 1 and entries[0].binsha == shaa and entries[0].mode == fa[1]

            # one side deletes, the other changes = conflict
            fa = mkfile(bfn, shab)
            th = mktree(odb, [fa])
            tm = mktree(odb, [])
            trees = [tb, th, tm]
            if is_them:
                trees = [tb, tm, th]
            # as one is deleted, there are only 2 entries
            assert_entries(aggressive_tree_merge(odb, trees), 2, True)
        # END handle ours, theirs

    def _assert_tree_entries(self, entries, num_trees):
        for entry in entries:
            assert len(entry) == num_trees
            paths = set(e[2] for e in entry if e)

            # only one path per set of entries
            assert len(paths) == 1
        # END verify entry

    def test_tree_traversal(self):
        # low level tree tarversal
        odb = self.rorepo.odb
        H = self.rorepo.tree('29eb123beb1c55e5db4aa652d843adccbd09ae18')    # head tree
        M = self.rorepo.tree('e14e3f143e7260de9581aee27e5a9b2645db72de')    # merge tree
        B = self.rorepo.tree('f606937a7a21237c866efafcad33675e6539c103')    # base tree
        B_old = self.rorepo.tree('1f66cfbbce58b4b552b041707a12d437cc5f400a')    # old base tree

        # two very different trees
        entries = traverse_trees_recursive(odb, [B_old.binsha, H.binsha], '')
        self._assert_tree_entries(entries, 2)

        oentries = traverse_trees_recursive(odb, [H.binsha, B_old.binsha], '')
        assert len(oentries) == len(entries)
        self._assert_tree_entries(oentries, 2)

        # single tree
        is_no_tree = lambda i, d: i.type != 'tree'
        entries = traverse_trees_recursive(odb, [B.binsha], '')
        assert len(entries) == len(list(B.traverse(predicate=is_no_tree)))
        self._assert_tree_entries(entries, 1)

        # two trees
        entries = traverse_trees_recursive(odb, [B.binsha, H.binsha], '')
        self._assert_tree_entries(entries, 2)

        # tree trees
        entries = traverse_trees_recursive(odb, [B.binsha, H.binsha, M.binsha], '')
        self._assert_tree_entries(entries, 3)

    def test_tree_traversal_single(self):
        max_count = 50
        count = 0
        odb = self.rorepo.odb
        for commit in self.rorepo.commit("29eb123beb1c55e5db4aa652d843adccbd09ae18").traverse():
            if count >= max_count:
                break
            count += 1
            entries = traverse_tree_recursive(odb, commit.tree.binsha, '')
            assert entries
        # END for each commit

    @with_rw_directory
    def test_linked_worktree_traversal(self, rw_dir):
        """Check that we can identify a linked worktree based on a .git file"""
        git = Git(rw_dir)
        if git.version_info[:3] < (2, 5, 1):
            raise SkipTest("worktree feature unsupported")

        rw_master = self.rorepo.clone(join_path_native(rw_dir, 'master_repo'))
        branch = rw_master.create_head('aaaaaaaa')
        worktree_path = join_path_native(rw_dir, 'worktree_repo')
        if Git.is_cygwin():
            worktree_path = cygpath(worktree_path)
        rw_master.git.worktree('add', worktree_path, branch.name)

        dotgit = osp.join(worktree_path, ".git")
        statbuf = stat(dotgit)
        assert_true(statbuf.st_mode & S_IFREG)

        gitdir = find_worktree_git_dir(dotgit)
        self.assertIsNotNone(gitdir)
        statbuf = stat(gitdir)
        assert_true(statbuf.st_mode & S_IFDIR)

    @skipIf(PY3, 'odd types returned ... maybe figure it out one day')
    def test_tree_entries_from_data_with_failing_name_decode_py2(self):
        r = tree_entries_from_data(b'100644 \x9f\0aaa')
        assert r == [('aaa', 33188, u'\udc9f')], r

    @skipIf(not PY3, 'odd types returned ... maybe figure it out one day')
    def test_tree_entries_from_data_with_failing_name_decode_py3(self):
        r = tree_entries_from_data(b'100644 \x9f\0aaa')
        assert r == [(b'aaa', 33188, '\udc9f')], r
