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


class Issue214(Framework.TestCase):  # https://github.com/jacquev6/PyGithub/issues/214
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user().get_repo("PyGithub")
        self.issue = self.repo.get_issue(1)

    def testAssignees(self):
        self.assertTrue(self.repo.has_in_assignees('farrd'))
        self.assertFalse(self.repo.has_in_assignees('fake'))

    def testCollaborators(self):
        self.assertTrue(self.repo.has_in_collaborators('farrd'))
        self.assertFalse(self.repo.has_in_collaborators('fake'))

        self.assertFalse(self.repo.has_in_collaborators('marcmenges'))
        self.repo.add_to_collaborators('marcmenges')
        self.assertTrue(self.repo.has_in_collaborators('marcmenges'))

        self.repo.remove_from_collaborators('marcmenges')
        self.assertFalse(self.repo.has_in_collaborators('marcmenges'))

    def testEditIssue(self):
        self.assertEqual(self.issue.assignee, None)

        self.issue.edit(assignee='farrd')
        self.assertEqual(self.issue.assignee.login, 'farrd')

        self.issue.edit(assignee=None)
        self.assertEqual(self.issue.assignee, None)

    def testCreateIssue(self):
        issue = self.repo.create_issue("Issue created by PyGithub", assignee='farrd')
        self.assertEqual(issue.assignee.login, 'farrd')

    def testGetIssues(self):
        issues = self.repo.get_issues(assignee='farrd')

        for issue in issues:
            self.assertEqual(issue.assignee.login, 'farrd')
