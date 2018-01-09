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


class GitCommit(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.commit = self.g.get_user().get_repo("PyGithub").get_git_commit("4303c5b90e2216d927155e9609436ccb8984c495")

    def testAttributes(self):
        self.assertEqual(self.commit.author.name, "Vincent Jacques")
        self.assertEqual(self.commit.author.email, "vincent@vincent-jacques.net")
        self.assertEqual(self.commit.author.date, datetime.datetime(2012, 4, 17, 17, 55, 16))
        self.assertEqual(self.commit.committer.name, "Vincent Jacques")
        self.assertEqual(self.commit.committer.email, "vincent@vincent-jacques.net")
        self.assertEqual(self.commit.committer.date, datetime.datetime(2012, 4, 17, 17, 55, 16))
        self.assertEqual(self.commit.message, "Merge branch 'develop'\n")
        self.assertEqual(len(self.commit.parents), 2)
        self.assertEqual(self.commit.parents[0].sha, "936f4a97f1a86392637ec002bbf89ff036a5062d")
        self.assertEqual(self.commit.parents[1].sha, "2a7e80e6421c5d4d201d60619068dea6bae612cb")
        self.assertEqual(self.commit.sha, "4303c5b90e2216d927155e9609436ccb8984c495")
        self.assertEqual(self.commit.tree.sha, "f492784d8ca837779650d1fb406a1a3587a764ad")
        self.assertEqual(self.commit.url, "https://api.github.com/repos/jacquev6/PyGithub/git/commits/4303c5b90e2216d927155e9609436ccb8984c495")

        # test __repr__() based on this attributes
        self.assertEqual(self.commit.__repr__(),
                         'GitCommit(sha="4303c5b90e2216d927155e9609436ccb8984c495")')