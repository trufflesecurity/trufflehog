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

import github

from . import Framework


class Issue87(Framework.TestCase):  # https://github.com/jacquev6/PyGithub/issues/87
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user().get_repo("PyGithub")

    def testCreateIssueWithPercentInTitle(self):
        issue = self.repo.create_issue("Issue with percent % in title created by PyGithub")
        self.assertEqual(issue.number, 99)

    def testCreateIssueWithPercentInBody(self):
        issue = self.repo.create_issue("Issue created by PyGithub", "Percent % in body")
        self.assertEqual(issue.number, 98)

    def testCreateIssueWithEscapedPercentInTitle(self):
        issue = self.repo.create_issue("Issue with escaped percent %25 in title created by PyGithub")
        self.assertEqual(issue.number, 97)

    def testCreateIssueWithEscapedPercentInBody(self):
        issue = self.repo.create_issue("Issue created by PyGithub", "Escaped percent %25 in body")
        self.assertEqual(issue.number, 96)
