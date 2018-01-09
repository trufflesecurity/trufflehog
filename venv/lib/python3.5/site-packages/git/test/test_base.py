# -*- coding: utf-8 -*-
# test_base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
import sys
import tempfile
try:
    from unittest import SkipTest, skipIf
except ImportError:
    from unittest2 import SkipTest, skipIf

from git import (
    Blob,
    Tree,
    Commit,
    TagObject
)
from git.compat import is_win
from git.objects.util import get_object_type_by_name
from git.test.lib import (
    TestBase,
    assert_raises,
    with_rw_repo,
    with_rw_and_rw_remote_repo
)
from git.util import hex_to_bin

import git.objects.base as base
import os.path as osp


class TestBase(TestBase):

    def tearDown(self):
        import gc
        gc.collect()

    type_tuples = (("blob", "8741fc1d09d61f02ffd8cded15ff603eff1ec070", "blob.py"),
                   ("tree", "3a6a5e3eeed3723c09f1ef0399f81ed6b8d82e79", "directory"),
                   ("commit", "4251bd59fb8e11e40c40548cba38180a9536118c", None),
                   ("tag", "e56a60e8e9cd333cfba0140a77cd12b0d9398f10", None))

    def test_base_object(self):
        # test interface of base object classes
        types = (Blob, Tree, Commit, TagObject)
        self.assertEqual(len(types), len(self.type_tuples))

        s = set()
        num_objs = 0
        num_index_objs = 0
        for obj_type, (typename, hexsha, path) in zip(types, self.type_tuples):
            binsha = hex_to_bin(hexsha)
            item = None
            if path is None:
                item = obj_type(self.rorepo, binsha)
            else:
                item = obj_type(self.rorepo, binsha, 0, path)
            # END handle index objects
            num_objs += 1
            self.assertEqual(item.hexsha, hexsha)
            self.assertEqual(item.type, typename)
            assert item.size
            self.assertEqual(item, item)
            self.assertNotEqual(not item, item)
            self.assertEqual(str(item), item.hexsha)
            assert repr(item)
            s.add(item)

            if isinstance(item, base.IndexObject):
                num_index_objs += 1
                if hasattr(item, 'path'):                        # never runs here
                    assert not item.path.startswith("/")        # must be relative
                    assert isinstance(item.mode, int)
            # END index object check

            # read from stream
            data_stream = item.data_stream
            data = data_stream.read()
            assert data

            tmpfilename = tempfile.mktemp(suffix='test-stream')
            with open(tmpfilename, 'wb+') as tmpfile:
                self.assertEqual(item, item.stream_data(tmpfile))
                tmpfile.seek(0)
                self.assertEqual(tmpfile.read(), data)
            os.remove(tmpfilename)
        # END for each object type to create

        # each has a unique sha
        self.assertEqual(len(s), num_objs)
        self.assertEqual(len(s | s), num_objs)
        self.assertEqual(num_index_objs, 2)

    def test_get_object_type_by_name(self):
        for tname in base.Object.TYPES:
            assert base.Object in get_object_type_by_name(tname).mro()
        # END for each known type

        assert_raises(ValueError, get_object_type_by_name, b"doesntexist")

    def test_object_resolution(self):
        # objects must be resolved to shas so they compare equal
        self.assertEqual(self.rorepo.head.reference.object, self.rorepo.active_branch.object)

    @with_rw_repo('HEAD', bare=True)
    def test_with_bare_rw_repo(self, bare_rw_repo):
        assert bare_rw_repo.config_reader("repository").getboolean("core", "bare")
        assert osp.isfile(osp.join(bare_rw_repo.git_dir, 'HEAD'))

    @with_rw_repo('0.1.6')
    def test_with_rw_repo(self, rw_repo):
        assert not rw_repo.config_reader("repository").getboolean("core", "bare")
        assert osp.isdir(osp.join(rw_repo.working_tree_dir, 'lib'))

    #@skipIf(HIDE_WINDOWS_FREEZE_ERRORS, "FIXME: Freezes!  sometimes...")
    @with_rw_and_rw_remote_repo('0.1.6')
    def test_with_rw_remote_and_rw_repo(self, rw_repo, rw_remote_repo):
        assert not rw_repo.config_reader("repository").getboolean("core", "bare")
        assert rw_remote_repo.config_reader("repository").getboolean("core", "bare")
        assert osp.isdir(osp.join(rw_repo.working_tree_dir, 'lib'))

    @skipIf(sys.version_info < (3,) and is_win,
            "Unicode woes, see https://github.com/gitpython-developers/GitPython/pull/519")
    @with_rw_repo('0.1.6')
    def test_add_unicode(self, rw_repo):
        filename = u"שלום.txt"

        file_path = osp.join(rw_repo.working_dir, filename)

        # verify first that we could encode file name in this environment
        try:
            file_path.encode(sys.getfilesystemencoding())
        except UnicodeEncodeError:
            raise SkipTest("Environment doesn't support unicode filenames")

        with open(file_path, "wb") as fp:
            fp.write(b'something')

        if is_win:
            # on windows, there is no way this works, see images on
            # https://github.com/gitpython-developers/GitPython/issues/147#issuecomment-68881897
            # Therefore, it must be added using the python implementation
            rw_repo.index.add([file_path])
            # However, when the test winds down, rmtree fails to delete this file, which is recognized
            # as ??? only.
        else:
            # on posix, we can just add unicode files without problems
            rw_repo.git.add(rw_repo.working_dir)
        # end
        rw_repo.index.commit('message')
