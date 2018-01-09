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

import datetime

from . import Framework


class GitTag(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.tag = self.g.get_user().get_repo("PyGithub").get_git_tag("f5f37322407b02a80de4526ad88d5f188977bc3c")

    def testAttributes(self):
        self.assertEqual(self.tag.message, "Version 0.6\n")
        self.assertEqual(self.tag.object.sha, "4303c5b90e2216d927155e9609436ccb8984c495")
        self.assertEqual(self.tag.object.type, "commit")
        self.assertEqual(self.tag.object.url, "https://api.github.com/repos/jacquev6/PyGithub/git/commits/4303c5b90e2216d927155e9609436ccb8984c495")
        self.assertEqual(self.tag.sha, "f5f37322407b02a80de4526ad88d5f188977bc3c")
        self.assertEqual(self.tag.tag, "v0.6")
        self.assertEqual(self.tag.tagger.date, datetime.datetime(2012, 5, 10, 18, 14, 15))
        self.assertEqual(self.tag.tagger.email, "vincent@vincent-jacques.net")
        self.assertEqual(self.tag.tagger.name, "Vincent Jacques")
        self.assertEqual(self.tag.url, "https://api.github.com/repos/jacquev6/PyGithub/git/tags/f5f37322407b02a80de4526ad88d5f188977bc3c")

        # test __repr__() based on this attributes
        self.assertEqual(self.tag.__repr__(), 'GitTag(tag="v0.6", sha="f5f37322407b02a80de4526ad88d5f188977bc3c")')