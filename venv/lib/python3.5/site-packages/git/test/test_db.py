# test_repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.db import GitCmdObjectDB
from git.exc import BadObject
from git.test.lib import TestBase
from git.util import bin_to_hex

import os.path as osp


class TestDB(TestBase):

    def test_base(self):
        gdb = GitCmdObjectDB(osp.join(self.rorepo.git_dir, 'objects'), self.rorepo.git)

        # partial to complete - works with everything
        hexsha = bin_to_hex(gdb.partial_to_complete_sha_hex("0.1.6"))
        assert len(hexsha) == 40

        assert bin_to_hex(gdb.partial_to_complete_sha_hex(hexsha[:20])) == hexsha

        # fails with BadObject
        for invalid_rev in ("0000", "bad/ref", "super bad"):
            self.failUnlessRaises(BadObject, gdb.partial_to_complete_sha_hex, invalid_rev)
