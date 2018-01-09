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


class Issue50(Framework.TestCase):  # https://github.com/jacquev6/PyGithub/issues/50
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user().get_repo("PyGithub")
        self.issue = self.repo.get_issue(50)
        self.labelName = "Label with spaces and strange characters (&*#$)"

    def testCreateLabel(self):
        label = self.repo.create_label(self.labelName, "ffff00")
        self.assertEqual(label.name, self.labelName)

    def testGetLabel(self):
        label = self.repo.get_label(self.labelName)
        self.assertEqual(label.name, self.labelName)

    def testGetLabels(self):
        self.assertListKeyEqual(self.repo.get_labels(), lambda l: l.name, ["Refactoring", "Public interface", "Functionalities", "Project management", "Bug", "Question", "RequestedByUser", self.labelName])

    def testAddLabelToIssue(self):
        self.issue.add_to_labels(self.repo.get_label(self.labelName))

    def testRemoveLabelFromIssue(self):
        self.issue.remove_from_labels(self.repo.get_label(self.labelName))

    def testSetIssueLabels(self):
        self.issue.set_labels(self.repo.get_label("Bug"), self.repo.get_label("RequestedByUser"), self.repo.get_label(self.labelName))

    def testIssueLabels(self):
        self.assertListKeyEqual(self.issue.labels, lambda l: l.name, ["Bug", self.labelName, "RequestedByUser"])

    def testIssueGetLabels(self):
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", self.labelName, "RequestedByUser"])

    def testGetIssuesWithLabel(self):
        self.assertListKeyEqual(self.repo.get_issues(labels=[self.repo.get_label(self.labelName)]), lambda i: i.number, [52, 50])

    def testCreateIssueWithLabel(self):
        issue = self.repo.create_issue("Issue created by PyGithub to test issue #50", labels=[self.repo.get_label(self.labelName)])
        self.assertListKeyEqual(issue.labels, lambda l: l.name, [self.labelName])
        self.assertEqual(issue.number, 52)
