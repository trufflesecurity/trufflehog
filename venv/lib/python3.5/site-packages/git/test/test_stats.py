# test_stats.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.test.lib import (
    TestBase,
    fixture,
    assert_equal
)
from git import Stats
from git.compat import defenc


class TestStats(TestBase):

    def test_list_from_string(self):
        output = fixture('diff_numstat').decode(defenc)
        stats = Stats._list_from_string(self.rorepo, output)

        assert_equal(2, stats.total['files'])
        assert_equal(52, stats.total['lines'])
        assert_equal(29, stats.total['insertions'])
        assert_equal(23, stats.total['deletions'])

        assert_equal(29, stats.files["a.txt"]['insertions'])
        assert_equal(18, stats.files["a.txt"]['deletions'])

        assert_equal(0, stats.files["b.txt"]['insertions'])
        assert_equal(5, stats.files["b.txt"]['deletions'])
