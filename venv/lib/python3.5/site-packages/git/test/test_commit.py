# -*- coding: utf-8 -*-
# test_commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from __future__ import print_function

from datetime import datetime
from io import BytesIO
import re
import sys
import time

from git import (
    Commit,
    Actor,
)
from git import Repo
from git.compat import (
    string_types,
    text_type
)
from git.objects.util import tzoffset, utc
from git.repo.fun import touch
from git.test.lib import (
    TestBase,
    assert_equal,
    assert_not_equal,
    with_rw_repo,
    fixture_path,
    StringProcessAdapter
)
from git.test.lib import with_rw_directory
from gitdb import IStream

import os.path as osp


try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock


def assert_commit_serialization(rwrepo, commit_id, print_performance_info=False):
    """traverse all commits in the history of commit identified by commit_id and check
    if the serialization works.
    :param print_performance_info: if True, we will show how fast we are"""
    ns = 0      # num serializations
    nds = 0     # num deserializations

    st = time.time()
    for cm in rwrepo.commit(commit_id).traverse():
        nds += 1

        # assert that we deserialize commits correctly, hence we get the same
        # sha on serialization
        stream = BytesIO()
        cm._serialize(stream)
        ns += 1
        streamlen = stream.tell()
        stream.seek(0)

        istream = rwrepo.odb.store(IStream(Commit.type, streamlen, stream))
        assert_equal(istream.hexsha, cm.hexsha.encode('ascii'))

        nc = Commit(rwrepo, Commit.NULL_BIN_SHA, cm.tree,
                    cm.author, cm.authored_date, cm.author_tz_offset,
                    cm.committer, cm.committed_date, cm.committer_tz_offset,
                    cm.message, cm.parents, cm.encoding)

        assert_equal(nc.parents, cm.parents)
        stream = BytesIO()
        nc._serialize(stream)
        ns += 1
        streamlen = stream.tell()
        stream.seek(0)

        # reuse istream
        istream.size = streamlen
        istream.stream = stream
        istream.binsha = None
        nc.binsha = rwrepo.odb.store(istream).binsha

        # if it worked, we have exactly the same contents !
        assert_equal(nc.hexsha, cm.hexsha)
    # END check commits
    elapsed = time.time() - st

    if print_performance_info:
        print("Serialized %i and deserialized %i commits in %f s ( (%f, %f) commits / s"
              % (ns, nds, elapsed, ns / elapsed, nds / elapsed), file=sys.stderr)
    # END handle performance info


class TestCommit(TestBase):

    def test_bake(self):

        commit = self.rorepo.commit('2454ae89983a4496a445ce347d7a41c0bb0ea7ae')
        # commits have no dict
        self.failUnlessRaises(AttributeError, setattr, commit, 'someattr', 1)
        commit.author  # bake

        assert_equal("Sebastian Thiel", commit.author.name)
        assert_equal("byronimo@gmail.com", commit.author.email)
        self.assertEqual(commit.author, commit.committer)
        assert isinstance(commit.authored_date, int) and isinstance(commit.committed_date, int)
        assert isinstance(commit.author_tz_offset, int) and isinstance(commit.committer_tz_offset, int)
        self.assertEqual(commit.message, "Added missing information to docstrings of commit and stats module\n")

    def test_stats(self):
        commit = self.rorepo.commit('33ebe7acec14b25c5f84f35a664803fcab2f7781')
        stats = commit.stats

        def check_entries(d):
            assert isinstance(d, dict)
            for key in ("insertions", "deletions", "lines"):
                assert key in d
        # END assertion helper
        assert stats.files
        assert stats.total

        check_entries(stats.total)
        assert "files" in stats.total

        for filepath, d in stats.files.items():  # @UnusedVariable
            check_entries(d)
        # END for each stated file

        # assure data is parsed properly
        michael = Actor._from_string("Michael Trier <mtrier@gmail.com>")
        self.assertEqual(commit.author, michael)
        self.assertEqual(commit.committer, michael)
        self.assertEqual(commit.authored_date, 1210193388)
        self.assertEqual(commit.committed_date, 1210193388)
        self.assertEqual(commit.author_tz_offset, 14400, commit.author_tz_offset)
        self.assertEqual(commit.committer_tz_offset, 14400, commit.committer_tz_offset)
        self.assertEqual(commit.message, "initial project\n")

    def test_unicode_actor(self):
        # assure we can parse unicode actors correctly
        name = u"Üäöß ÄußÉ"
        self.assertEqual(len(name), 9)
        special = Actor._from_string(u"%s <something@this.com>" % name)
        self.assertEqual(special.name, name)
        assert isinstance(special.name, text_type)

    def test_traversal(self):
        start = self.rorepo.commit("a4d06724202afccd2b5c54f81bcf2bf26dea7fff")
        first = self.rorepo.commit("33ebe7acec14b25c5f84f35a664803fcab2f7781")
        p0 = start.parents[0]
        p1 = start.parents[1]
        p00 = p0.parents[0]
        p10 = p1.parents[0]

        # basic branch first, depth first
        dfirst = start.traverse(branch_first=False)
        bfirst = start.traverse(branch_first=True)
        self.assertEqual(next(dfirst), p0)
        self.assertEqual(next(dfirst), p00)

        self.assertEqual(next(bfirst), p0)
        self.assertEqual(next(bfirst), p1)
        self.assertEqual(next(bfirst), p00)
        self.assertEqual(next(bfirst), p10)

        # at some point, both iterations should stop
        self.assertEqual(list(bfirst)[-1], first)
        stoptraverse = self.rorepo.commit("254d04aa3180eb8b8daf7b7ff25f010cd69b4e7d").traverse(as_edge=True)
        self.assertEqual(len(next(stoptraverse)), 2)

        # ignore self
        self.assertEqual(next(start.traverse(ignore_self=False)), start)

        # depth
        self.assertEqual(len(list(start.traverse(ignore_self=False, depth=0))), 1)

        # prune
        self.assertEqual(next(start.traverse(branch_first=1, prune=lambda i, d: i == p0)), p1)

        # predicate
        self.assertEqual(next(start.traverse(branch_first=1, predicate=lambda i, d: i == p1)), p1)

        # traversal should stop when the beginning is reached
        self.failUnlessRaises(StopIteration, next, first.traverse())

        # parents of the first commit should be empty ( as the only parent has a null
        # sha )
        self.assertEqual(len(first.parents), 0)

    def test_iteration(self):
        # we can iterate commits
        all_commits = Commit.list_items(self.rorepo, self.rorepo.head)
        assert all_commits
        self.assertEqual(all_commits, list(self.rorepo.iter_commits()))

        # this includes merge commits
        mcomit = self.rorepo.commit('d884adc80c80300b4cc05321494713904ef1df2d')
        assert mcomit in all_commits

        # we can limit the result to paths
        ltd_commits = list(self.rorepo.iter_commits(paths='CHANGES'))
        assert ltd_commits and len(ltd_commits) < len(all_commits)

        # show commits of multiple paths, resulting in a union of commits
        less_ltd_commits = list(Commit.iter_items(self.rorepo, 'master', paths=('CHANGES', 'AUTHORS')))
        assert len(ltd_commits) < len(less_ltd_commits)

    def test_iter_items(self):
        # pretty not allowed
        self.failUnlessRaises(ValueError, Commit.iter_items, self.rorepo, 'master', pretty="raw")

    def test_rev_list_bisect_all(self):
        """
        'git rev-list --bisect-all' returns additional information
        in the commit header.  This test ensures that we properly parse it.
        """
        revs = self.rorepo.git.rev_list('933d23bf95a5bd1624fbcdf328d904e1fa173474',
                                        first_parent=True,
                                        bisect_all=True)

        commits = Commit._iter_from_process_or_stream(self.rorepo, StringProcessAdapter(revs.encode('ascii')))
        expected_ids = (
            '7156cece3c49544abb6bf7a0c218eb36646fad6d',
            '1f66cfbbce58b4b552b041707a12d437cc5f400a',
            '33ebe7acec14b25c5f84f35a664803fcab2f7781',
            '933d23bf95a5bd1624fbcdf328d904e1fa173474'
        )
        for sha1, commit in zip(expected_ids, commits):
            assert_equal(sha1, commit.hexsha)

    @with_rw_directory
    def test_ambiguous_arg_iteration(self, rw_dir):
        rw_repo = Repo.init(osp.join(rw_dir, 'test_ambiguous_arg'))
        path = osp.join(rw_repo.working_tree_dir, 'master')
        touch(path)
        rw_repo.index.add([path])
        rw_repo.index.commit('initial commit')
        list(rw_repo.iter_commits(rw_repo.head.ref))  # should fail unless bug is fixed

    def test_count(self):
        self.assertEqual(self.rorepo.tag('refs/tags/0.1.5').commit.count(), 143)

    def test_list(self):
        # This doesn't work anymore, as we will either attempt getattr with bytes, or compare 20 byte string
        # with actual 20 byte bytes. This usage makes no sense anyway
        assert isinstance(Commit.list_items(self.rorepo, '0.1.5', max_count=5)[
                          '5117c9c8a4d3af19a9958677e45cda9269de1541'], Commit)

    def test_str(self):
        commit = Commit(self.rorepo, Commit.NULL_BIN_SHA)
        assert_equal(Commit.NULL_HEX_SHA, str(commit))

    def test_repr(self):
        commit = Commit(self.rorepo, Commit.NULL_BIN_SHA)
        assert_equal('<git.Commit "%s">' % Commit.NULL_HEX_SHA, repr(commit))

    def test_equality(self):
        commit1 = Commit(self.rorepo, Commit.NULL_BIN_SHA)
        commit2 = Commit(self.rorepo, Commit.NULL_BIN_SHA)
        commit3 = Commit(self.rorepo, "\1" * 20)
        assert_equal(commit1, commit2)
        assert_not_equal(commit2, commit3)

    def test_iter_parents(self):
        # should return all but ourselves, even if skip is defined
        c = self.rorepo.commit('0.1.5')
        for skip in (0, 1):
            piter = c.iter_parents(skip=skip)
            first_parent = next(piter)
            assert first_parent != c
            self.assertEqual(first_parent, c.parents[0])
        # END for each

    def test_name_rev(self):
        name_rev = self.rorepo.head.commit.name_rev
        assert isinstance(name_rev, string_types)

    @with_rw_repo('HEAD', bare=True)
    def test_serialization(self, rwrepo):
        # create all commits of our repo
        assert_commit_serialization(rwrepo, '0.1.6')

    def test_serialization_unicode_support(self):
        self.assertEqual(Commit.default_encoding.lower(), 'utf-8')

        # create a commit with unicode in the message, and the author's name
        # Verify its serialization and deserialization
        cmt = self.rorepo.commit('0.1.6')
        assert isinstance(cmt.message, text_type)     # it automatically decodes it as such
        assert isinstance(cmt.author.name, text_type)  # same here

        cmt.message = u"üäêèß"
        self.assertEqual(len(cmt.message), 5)

        cmt.author.name = u"äüß"
        self.assertEqual(len(cmt.author.name), 3)

        cstream = BytesIO()
        cmt._serialize(cstream)
        cstream.seek(0)
        assert len(cstream.getvalue())

        ncmt = Commit(self.rorepo, cmt.binsha)
        ncmt._deserialize(cstream)

        self.assertEqual(cmt.author.name, ncmt.author.name)
        self.assertEqual(cmt.message, ncmt.message)
        # actually, it can't be printed in a shell as repr wants to have ascii only
        # it appears
        cmt.author.__repr__()

    def test_invalid_commit(self):
        cmt = self.rorepo.commit()
        with open(fixture_path('commit_invalid_data'), 'rb') as fd:
            cmt._deserialize(fd)

        self.assertEqual(cmt.author.name, u'E.Azer Ko�o�o�oculu', cmt.author.name)
        self.assertEqual(cmt.author.email, 'azer@kodfabrik.com', cmt.author.email)

    def test_gpgsig(self):
        cmt = self.rorepo.commit()
        with open(fixture_path('commit_with_gpgsig'), 'rb') as fd:
            cmt._deserialize(fd)

        fixture_sig = """-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iQIcBAABAgAGBQJRk8zMAAoJEG5mS6x6i9IjsTEP/0v2Wx/i7dqyKban6XMIhVdj
uI0DycfXqnCCZmejidzeao+P+cuK/ZAA/b9fU4MtwkDm2USvnIOrB00W0isxsrED
sdv6uJNa2ybGjxBolLrfQcWutxGXLZ1FGRhEvkPTLMHHvVriKoNFXcS7ewxP9MBf
NH97K2wauqA+J4BDLDHQJgADCOmLrGTAU+G1eAXHIschDqa6PZMH5nInetYZONDh
3SkOOv8VKFIF7gu8X7HC+7+Y8k8U0TW0cjlQ2icinwCc+KFoG6GwXS7u/VqIo1Yp
Tack6sxIdK7NXJhV5gAeAOMJBGhO0fHl8UUr96vGEKwtxyZhWf8cuIPOWLk06jA0
g9DpLqmy/pvyRfiPci+24YdYRBua/vta+yo/Lp85N7Hu/cpIh+q5WSLvUlv09Dmo
TTTG8Hf6s3lEej7W8z2xcNZoB6GwXd8buSDU8cu0I6mEO9sNtAuUOHp2dBvTA6cX
PuQW8jg3zofnx7CyNcd3KF3nh2z8mBcDLgh0Q84srZJCPRuxRcp9ylggvAG7iaNd
XMNvSK8IZtWLkx7k3A3QYt1cN4y1zdSHLR2S+BVCEJea1mvUE+jK5wiB9S4XNtKm
BX/otlTa8pNE3fWYBxURvfHnMY4i3HQT7Bc1QjImAhMnyo2vJk4ORBJIZ1FTNIhJ
JzJMZDRLQLFvnzqZuCjE
=przd
-----END PGP SIGNATURE-----"""
        self.assertEqual(cmt.gpgsig, fixture_sig)

        cmt.gpgsig = "<test\ndummy\nsig>"
        assert cmt.gpgsig != fixture_sig

        cstream = BytesIO()
        cmt._serialize(cstream)
        assert re.search(r"^gpgsig <test\n dummy\n sig>$", cstream.getvalue().decode('ascii'), re.MULTILINE)

        self.assert_gpgsig_deserialization(cstream)

        cstream.seek(0)
        cmt.gpgsig = None
        cmt._deserialize(cstream)
        self.assertEqual(cmt.gpgsig, "<test\ndummy\nsig>")

        cmt.gpgsig = None
        cstream = BytesIO()
        cmt._serialize(cstream)
        assert not re.search(r"^gpgsig ", cstream.getvalue().decode('ascii'), re.MULTILINE)

    def assert_gpgsig_deserialization(self, cstream):
        assert 'gpgsig' in 'precondition: need gpgsig'

        class RepoMock:
            def __init__(self, bytestr):
                self.bytestr = bytestr

            @property
            def odb(self):
                class ODBMock:
                    def __init__(self, bytestr):
                        self.bytestr = bytestr

                    def stream(self, *args):
                        stream = Mock(spec_set=['read'], return_value=self.bytestr)
                        stream.read.return_value = self.bytestr
                        return ('binsha', 'typename', 'size', stream)

                return ODBMock(self.bytestr)

        repo_mock = RepoMock(cstream.getvalue())
        for field in Commit.__slots__:
            c = Commit(repo_mock, b'x' * 20)
            assert getattr(c, field) is not None

    def test_datetimes(self):
        commit = self.rorepo.commit('4251bd5')
        self.assertEqual(commit.authored_date, 1255018625)
        self.assertEqual(commit.committed_date, 1255026171)
        self.assertEqual(commit.authored_datetime,
                         datetime(2009, 10, 8, 18, 17, 5, tzinfo=tzoffset(-7200)), commit.authored_datetime)  # noqa
        self.assertEqual(commit.authored_datetime,
                         datetime(2009, 10, 8, 16, 17, 5, tzinfo=utc), commit.authored_datetime)
        self.assertEqual(commit.committed_datetime,
                         datetime(2009, 10, 8, 20, 22, 51, tzinfo=tzoffset(-7200)))
        self.assertEqual(commit.committed_datetime,
                         datetime(2009, 10, 8, 18, 22, 51, tzinfo=utc), commit.committed_datetime)
