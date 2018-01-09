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


class Authorization(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.authorization = self.g.get_user().get_authorization(372259)

    def testAttributes(self):
        self.assertEqual(self.authorization.app.url, "http://developer.github.com/v3/oauth/#oauth-authorizations-api")
        self.assertEqual(self.authorization.app.name, "GitHub API")
        self.assertEqual(self.authorization.created_at, datetime.datetime(2012, 5, 22, 18, 3, 17))
        self.assertEqual(self.authorization.id, 372259)
        self.assertEqual(self.authorization.note, None)
        self.assertEqual(self.authorization.note_url, None)
        self.assertEqual(self.authorization.scopes, [])
        self.assertEqual(self.authorization.token, "82459c4500086f8f0cc67d2936c17d1e27ad1c33")
        self.assertEqual(self.authorization.updated_at, datetime.datetime(2012, 5, 22, 18, 3, 17))
        self.assertEqual(self.authorization.url, "https://api.github.com/authorizations/372259")

    def testEdit(self):
        self.authorization.edit()
        self.assertEqual(self.authorization.scopes, [])
        self.authorization.edit(scopes=["user"])
        self.assertEqual(self.authorization.scopes, ["user"])
        self.authorization.edit(add_scopes=["repo"])
        self.assertEqual(self.authorization.scopes, ["user", "repo"])
        self.authorization.edit(remove_scopes=["repo"])
        self.assertEqual(self.authorization.scopes, ["user"])
        self.assertEqual(self.authorization.note, None)
        self.assertEqual(self.authorization.note_url, None)
        self.authorization.edit(note="Note created by PyGithub", note_url="http://vincent-jacques.net/PyGithub")
        self.assertEqual(self.authorization.note, "Note created by PyGithub")
        self.assertEqual(self.authorization.note_url, "http://vincent-jacques.net/PyGithub")

    def testDelete(self):
        self.authorization.delete()
