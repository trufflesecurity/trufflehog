# test_actor.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.test.lib import assert_equal
from git import Actor


class TestActor(object):

    def test_from_string_should_separate_name_and_email(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert_equal("Michael Trier", a.name)
        assert_equal("mtrier@example.com", a.email)

        # base type capabilities
        assert a == a
        assert not (a != a)
        m = set()
        m.add(a)
        m.add(a)
        assert len(m) == 1

    def test_from_string_should_handle_just_name(self):
        a = Actor._from_string("Michael Trier")
        assert_equal("Michael Trier", a.name)
        assert_equal(None, a.email)

    def test_should_display_representation(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert_equal('<git.Actor "Michael Trier <mtrier@example.com>">', repr(a))

    def test_str_should_alias_name(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert_equal(a.name, str(a))
