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


class PullRequest(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user().get_repo("PyGithub")
        self.pull = self.repo.get_pull(31)

    def testAttributes(self):
        self.assertEqual(self.pull.additions, 511)
        self.assertEqual(self.pull.assignee.login, "jacquev6")
        self.assertListKeyEqual(self.pull.assignees, lambda a: a.login, ["stuglaser", "jacquev6"])
        self.assertEqual(self.pull.base.label, "jacquev6:topic/RewriteWithGeneratedCode")
        self.assertEqual(self.pull.base.sha, "ed866fc43833802ab553e5ff8581c81bb00dd433")
        self.assertEqual(self.pull.base.user.login, "jacquev6")
        self.assertEqual(self.pull.base.ref, "topic/RewriteWithGeneratedCode")
        self.assertEqual(self.pull.base.repo.full_name, "jacquev6/PyGithub")
        self.assertEqual(self.pull.body, "Body edited by PyGithub")
        self.assertEqual(self.pull.changed_files, 45)
        self.assertEqual(self.pull.closed_at, datetime.datetime(2012, 5, 27, 10, 29, 7))
        self.assertEqual(self.pull.comments, 1)
        self.assertEqual(self.pull.commits, 3)
        self.assertEqual(self.pull.created_at, datetime.datetime(2012, 5, 27, 9, 25, 36))
        self.assertEqual(self.pull.deletions, 384)
        self.assertEqual(self.pull.diff_url, "https://github.com/jacquev6/PyGithub/pull/31.diff")
        self.assertEqual(self.pull.head.label, "BeaverSoftware:master")
        self.assertEqual(self.pull.html_url, "https://github.com/jacquev6/PyGithub/pull/31")
        self.assertEqual(self.pull.id, 1436215)
        self.assertEqual(self.pull.issue_url, "https://github.com/jacquev6/PyGithub/issues/31")
        self.assertFalse(self.pull.mergeable)
        self.assertTrue(self.pull.merged)
        self.assertEqual(self.pull.merged_at, datetime.datetime(2012, 5, 27, 10, 29, 7))
        self.assertEqual(self.pull.merged_by.login, "jacquev6")
        self.assertEqual(self.pull.number, 31)
        self.assertEqual(self.pull.patch_url, "https://github.com/jacquev6/PyGithub/pull/31.patch")
        self.assertEqual(self.pull.review_comments, 1)
        self.assertEqual(self.pull.state, "closed")
        self.assertEqual(self.pull.title, "Title edited by PyGithub")
        self.assertEqual(self.pull.updated_at, datetime.datetime(2012, 11, 3, 8, 19, 40))
        self.assertEqual(self.pull.url, "https://api.github.com/repos/jacquev6/PyGithub/pulls/31")
        self.assertEqual(self.pull.user.login, "jacquev6")

        # test __repr__() based on this attributes
        self.assertEqual(self.pull.__repr__(), 'PullRequest(title="Title edited by PyGithub", number=31)')

    def testCreateComment(self):
        commit = self.repo.get_commit("8a4f306d4b223682dd19410d4a9150636ebe4206")
        comment = self.pull.create_comment("Comment created by PyGithub", commit, "src/github/Issue.py", 5)
        self.assertEqual(comment.id, 886298)

    def testGetComments(self):
        self.assertListKeyEqual(self.pull.get_comments(), lambda c: c.id, [886298])

    def testCreateIssueComment(self):
        comment = self.pull.create_issue_comment("Issue comment created by PyGithub")
        self.assertEqual(comment.id, 8387331)

    def testGetIssueComments(self):
        self.assertListKeyEqual(self.pull.get_issue_comments(), lambda c: c.id, [8387331])

    def testGetIssueComment(self):
        comment = self.pull.get_issue_comment(8387331)
        self.assertEqual(comment.body, "Issue comment created by PyGithub")

    def testEditWithoutArguments(self):
        self.pull.edit()

    def testEditWithAllArguments(self):
        self.pull.edit("Title edited by PyGithub", "Body edited by PyGithub", "open")
        self.assertEqual(self.pull.title, "Title edited by PyGithub")
        self.assertEqual(self.pull.body, "Body edited by PyGithub")
        self.assertEqual(self.pull.state, "open")

    def testGetCommits(self):
        self.assertListKeyEqual(self.pull.get_commits(), lambda c: c.sha, ["4aadfff21cdd2d2566b0e4bd7309c233b5f4ae23", "93dcae5cf207de376c91d0599226e7c7563e1d16", "8a4f306d4b223682dd19410d4a9150636ebe4206"])

    def testGetFiles(self):
        self.assertListKeyEqual(self.pull.get_files(), lambda f: f.filename, ["codegen/templates/GithubObject.py", "src/github/AuthenticatedUser.py", "src/github/Authorization.py", "src/github/Branch.py", "src/github/Commit.py", "src/github/CommitComment.py", "src/github/CommitFile.py", "src/github/CommitStats.py", "src/github/Download.py", "src/github/Event.py", "src/github/Gist.py", "src/github/GistComment.py", "src/github/GistHistoryState.py", "src/github/GitAuthor.py", "src/github/GitBlob.py", "src/github/GitCommit.py", "src/github/GitObject.py", "src/github/GitRef.py", "src/github/GitTag.py", "src/github/GitTree.py", "src/github/GitTreeElement.py", "src/github/Hook.py", "src/github/Issue.py", "src/github/IssueComment.py", "src/github/IssueEvent.py", "src/github/Label.py", "src/github/Milestone.py", "src/github/NamedUser.py", "src/github/Organization.py", "src/github/Permissions.py", "src/github/Plan.py", "src/github/PullRequest.py", "src/github/PullRequestComment.py", "src/github/PullRequestFile.py", "src/github/Repository.py", "src/github/RepositoryKey.py", "src/github/Tag.py", "src/github/Team.py", "src/github/UserKey.py", "test/Issue.py", "test/IssueEvent.py", "test/ReplayData/Issue.testAddAndRemoveLabels.txt", "test/ReplayData/Issue.testDeleteAndSetLabels.txt", "test/ReplayData/Issue.testGetLabels.txt", "test/ReplayData/IssueEvent.setUp.txt"])

    def testMerge(self):
        self.assertFalse(self.pull.is_merged())
        status = self.pull.merge()
        self.assertEqual(status.sha, "688208b1a5a074871d0e9376119556897439697d")
        self.assertTrue(status.merged)
        self.assertEqual(status.message, "Pull Request successfully merged")
        self.assertTrue(self.pull.is_merged())

    def testMergeWithCommitMessage(self):
        self.g.get_user().get_repo("PyGithub").get_pull(39).merge("Custom commit message created by PyGithub")
