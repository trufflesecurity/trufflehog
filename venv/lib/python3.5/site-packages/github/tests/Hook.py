# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
#                                                                              #
# This file is part of PyGithub.                                               #
# http://pygithub.github.io/PyGithub/v1/index.html                             #
#                                                                              #
# PyGithub is free software: you can redistribute it and/or modify it under    #
# the terms of the GNU Lesser General Public License as published by the Free  #
# Software Foundation, either version 3 of the License, or (at your option)    #
# any later version.                                                           #
#                                                                              #
# PyGithub is distributed in the hope that it will be useful, but WITHOUT ANY  #
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS    #
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more #
# details.                                                                     #
#                                                                              #
# You should have received a copy of the GNU Lesser General Public License     #
# along with PyGithub. If not, see <http://www.gnu.org/licenses/>.             #
#                                                                              #
# ##############################################################################

from . import Framework

import datetime


class Hook(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.hook = self.g.get_user().get_repo("PyGithub").get_hook(257993)

    def testAttributes(self):
        self.assertTrue(self.hook.active)  # WTF
        self.assertEqual(self.hook.config, {"url": "http://foobar.com"})
        self.assertEqual(self.hook.created_at, datetime.datetime(2012, 5, 19, 6, 1, 45))
        self.assertEqual(self.hook.events, ["push"])
        self.assertEqual(self.hook.id, 257993)
        self.assertEqual(self.hook.last_response.status, "ok")
        self.assertEqual(self.hook.last_response.message, "OK")
        self.assertEqual(self.hook.last_response.code, 200)
        self.assertEqual(self.hook.name, "web")
        self.assertEqual(self.hook.updated_at, datetime.datetime(2012, 5, 29, 18, 49, 47))
        self.assertEqual(self.hook.url, "https://api.github.com/repos/jacquev6/PyGithub/hooks/257993")

        # test __repr__() based on this attributes
        self.assertEqual(self.hook.__repr__(), 'Hook(url="https://api.github.com/repos/jacquev6/PyGithub/hooks/257993", id=257993)')

    def testEditWithMinimalParameters(self):
        self.hook.edit("web", {"url": "http://foobar.com/hook"})
        self.assertEqual(self.hook.config, {"url": "http://foobar.com/hook"})
        self.assertEqual(self.hook.updated_at, datetime.datetime(2012, 5, 19, 5, 8, 16))

    def testDelete(self):
        self.hook.delete()

    def testTest(self):
        self.hook.test()  # This does not update attributes of hook

    def testEditWithAllParameters(self):
        self.hook.edit("web", {"url": "http://foobar.com"}, events=["fork", "push"])
        self.assertEqual(self.hook.events, ["fork", "push"])
        self.hook.edit("web", {"url": "http://foobar.com"}, add_events=["push"])
        self.assertEqual(self.hook.events, ["fork", "push"])
        self.hook.edit("web", {"url": "http://foobar.com"}, remove_events=["fork"])
        self.assertEqual(self.hook.events, ["push"])
        self.hook.edit("web", {"url": "http://foobar.com"}, active=True)
        self.assertTrue(self.hook.active)
