# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 Stuart Glaser <stuglaser@gmail.com>                           #
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


class Issue(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user().get_repo("PyGithub")
        self.issue = self.repo.get_issue(28)

    def testAttributes(self):
        self.assertEqual(self.issue.assignee.login, "jacquev6")
        self.assertListKeyEqual(self.issue.assignees, lambda a: a.login, ["jacquev6", "stuglaser"])
        self.assertEqual(self.issue.body, "Body edited by PyGithub")
        self.assertEqual(self.issue.closed_at, datetime.datetime(2012, 5, 26, 14, 59, 33))
        self.assertEqual(self.issue.closed_by.login, "jacquev6")
        self.assertEqual(self.issue.comments, 0)
        self.assertEqual(self.issue.created_at, datetime.datetime(2012, 5, 19, 10, 38, 23))
        self.assertEqual(self.issue.html_url, "https://github.com/jacquev6/PyGithub/issues/28")
        self.assertEqual(self.issue.id, 4653757)
        self.assertListKeyEqual(self.issue.labels, lambda l: l.name, ["Bug", "Project management", "Question"])
        self.assertEqual(self.issue.milestone.title, "Version 0.4")
        self.assertEqual(self.issue.number, 28)
        self.assertEqual(self.issue.pull_request.diff_url, None)
        self.assertEqual(self.issue.pull_request.patch_url, None)
        self.assertEqual(self.issue.pull_request.html_url, None)
        self.assertEqual(self.issue.state, "closed")
        self.assertEqual(self.issue.title, "Issue created by PyGithub")
        self.assertEqual(self.issue.updated_at, datetime.datetime(2012, 5, 26, 14, 59, 33))
        self.assertEqual(self.issue.url, "https://api.github.com/repos/jacquev6/PyGithub/issues/28")
        self.assertEqual(self.issue.user.login, "jacquev6")
        self.assertEqual(self.issue.repository.name, "PyGithub")

        # test __repr__() based on this attributes
        self.assertEqual(self.issue.__repr__(), 'Issue(title="Issue created by PyGithub", number=28)')

    def testEditWithoutParameters(self):
        self.issue.edit()

    def testEditWithAllParameters(self):
        user = self.g.get_user("jacquev6")
        milestone = self.repo.get_milestone(2)
        self.issue.edit("Title edited by PyGithub", "Body edited by PyGithub", user, "open", milestone, ["Bug"], ["jacquev6", "stuglaser"])
        self.assertEqual(self.issue.assignee.login, "jacquev6")
        self.assertListKeyEqual(self.issue.assignees, lambda a: a.login, ["jacquev6", "stuglaser"])
        self.assertEqual(self.issue.body, "Body edited by PyGithub")
        self.assertEqual(self.issue.state, "open")
        self.assertEqual(self.issue.title, "Title edited by PyGithub")
        self.assertListKeyEqual(self.issue.labels, lambda l: l.name, ["Bug"])

    def testEditResetMilestone(self):
        self.assertEqual(self.issue.milestone.title, "Version 0.4")
        self.issue.edit(milestone=None)
        self.assertEqual(self.issue.milestone, None)

    def testEditResetAssignee(self):
        self.assertEqual(self.issue.assignee.login, "jacquev6")
        self.issue.edit(assignee=None)
        self.assertEqual(self.issue.assignee, None)

    def testCreateComment(self):
        comment = self.issue.create_comment("Comment created by PyGithub")
        self.assertEqual(comment.id, 5808311)

    def testGetComments(self):
        self.assertListKeyEqual(self.issue.get_comments(), lambda c: c.user.login, ["jacquev6", "roskakori"])

    def testGetCommentsSince(self):
        self.assertListKeyEqual(self.issue.get_comments(datetime.datetime(2012, 5, 26, 13, 59, 33)), lambda c: c.user.login, ["jacquev6", "roskakori"])

    def testGetEvents(self):
        self.assertListKeyEqual(self.issue.get_events(), lambda e: e.id, [15819975, 15820048])

    def testGetLabels(self):
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])

    def testAddAndRemoveAssignees(self):
        user1 = "jayfk"
        user2 = self.g.get_user("jzelinskie")
        self.assertListKeyEqual(self.issue.assignees, lambda a: a.login, ["jacquev6", "stuglaser"])
        self.issue.add_to_assignees(user1, user2)
        self.assertListKeyEqual(self.issue.assignees, lambda a: a.login, ["jacquev6", "stuglaser", "jayfk", "jzelinskie"])
        self.issue.remove_from_assignees(user1, user2)
        self.assertListKeyEqual(self.issue.assignees, lambda a: a.login, ["jacquev6", "stuglaser"])

    def testAddAndRemoveLabels(self):
        bug = self.repo.get_label("Bug")
        question = self.repo.get_label("Question")
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])
        self.issue.remove_from_labels(bug)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Project management", "Question"])
        self.issue.remove_from_labels(question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Project management"])
        self.issue.add_to_labels(bug, question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])

    def testAddAndRemoveLabelsWithStringArguments(self):
        bug = "Bug"
        question = "Question"
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])
        self.issue.remove_from_labels(bug)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Project management", "Question"])
        self.issue.remove_from_labels(question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Project management"])
        self.issue.add_to_labels(bug, question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])

    def testDeleteAndSetLabels(self):
        bug = self.repo.get_label("Bug")
        question = self.repo.get_label("Question")
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])
        self.issue.delete_labels()
        self.assertListKeyEqual(self.issue.get_labels(), None, [])
        self.issue.set_labels(bug, question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Question"])

    def testDeleteAndSetLabelsWithStringArguments(self):
        bug = "Bug"
        question = "Question"
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Project management", "Question"])
        self.issue.delete_labels()
        self.assertListKeyEqual(self.issue.get_labels(), None, [])
        self.issue.set_labels(bug, question)
        self.assertListKeyEqual(self.issue.get_labels(), lambda l: l.name, ["Bug", "Question"])
