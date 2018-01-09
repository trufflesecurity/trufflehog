# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
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


class ExposeAllAttributes(Framework.TestCase):
    def testAllClasses(self):
        authenticatedUser = self.g.get_user()
        namedUser = self.g.get_user("nvie")
        repository = authenticatedUser.get_repo("PyGithub")
        organization = self.g.get_organization("BeaverSoftware")
        plan = authenticatedUser.plan
        branch = repository.get_branch("master")
        commit = repository.get_commit("1292bf0e22c796e91cc3d6e24b544aece8c21f2a")
        commitStats = commit.stats
        commitStatus = commit.get_statuses()[0]
        milestone = repository.get_milestone(17)
        gist = self.g.get_gist("149016")
        gistComment = gist.get_comment(4565)
        gistFile = gist.files[".gitignore"]
        gistHistoryState = gist.history[0]
        gitCommit = repository.get_git_commit("be37b8a7f3a68631c32672dcd84d9eba27438ee6")
        gitAuthor = gitCommit.author
        gitTree = repository.get_git_tree("6f7c2d8c66d78863f7b91792deaead619799a1ce")
        gitTreeElement = gitTree.tree[0]
        gitBlob = repository.get_git_blob("681fb61f1761743a02f5c790f1c762cbfe8cfad1")
        gitRef = repository.get_git_ref("tags/v1.17.0")
        gitObject = gitRef.object
        issue = repository.get_issue(188)
        issueComment = issue.get_comment(22686536)
        issueEvent = issue.get_events()[0]
        issuePullRequest = issue.pull_request
        gitignoreTemplate = self.g.get_gitignore_template("Python")
        team = organization.get_team(141487)
        label = repository.get_label("Bug")
        pullRequest = repository.get_pull(31)
        pullRequestComment = pullRequest.get_review_comment(1580134)
        pullRequestPart = pullRequest.base
        file = pullRequest.get_files()[0]
        commitComment = repository.get_comment(3630301)
        status = self.g.get_api_status()
        statusMessage = self.g.get_last_api_status_message()
        rateLimit = self.g.get_rate_limit()
        rate = rateLimit.rate
        hook = repository.get_hooks()[0]
        hookResponse = hook.last_response
        hookDescription = self.g.get_hooks()[0]
        comparison = repository.compare("master", "develop")
        contentFile = repository.get_file_contents("README.rst")
        permissions = repository.permissions
        event = repository.get_events()[0]
        notification = authenticatedUser.get_notification("8406712")
        notificationSubject = notification.subject

        missingAttributes = self.gatherMissingAttributes([
            authenticatedUser,
            # authorization,  # Security issue if put as-is in ReplayData
            # authorizationApplication,  # Security issue if put as-is in ReplayData
            branch,
            commit,
            commitComment,
            commitStats,
            commitStatus,
            comparison,
            contentFile,
            # download,  # Deprecated: https://github.com/blog/1302-goodbye-uploads
            event,
            file,
            gist,
            gistComment,
            gistFile,
            gistHistoryState,
            gitAuthor,
            gitBlob,
            gitCommit,
            gitignoreTemplate,
            gitObject,
            gitRef,
            # gitTag,
            gitTree,
            gitTreeElement,
            hook,
            hookDescription,
            hookResponse,
            issue,
            issueComment,
            issueEvent,
            issuePullRequest,
            label,
            milestone,
            namedUser,
            notification,
            notificationSubject,
            organization,
            permissions,
            plan,
            pullRequest,
            pullRequestComment,
            # pullRequestMergeStatus,  # Only obtained when merging a pull request through the API
            pullRequestPart,
            rate,
            rateLimit,
            repository,
            # repositoryKey,  # Security issue if put as-is in ReplayData
            status,
            statusMessage,
            # tag,
            team,
            # userKey,  # Security issue if put as-is in ReplayData
        ])

        for className, attributesMissingInClass in sorted(missingAttributes.items()):
            for attrName, value in sorted(attributesMissingInClass.items()):
                print(className, attrName, "->", repr(value))

        self.assertEqual(sum(len(attrs) for attrs in list(missingAttributes.values())), 0)

    def findMissingAttributes(self, obj):
        if hasattr(obj, "update"):
            obj.update()
        className = obj.__class__.__name__
        missingAttributes = {}
        for attribute in obj.raw_data:
            if attribute != "_links":
                if not hasattr(obj, attribute):
                    missingAttributes[attribute] = obj.raw_data[attribute]
        return (className, missingAttributes)

    def gatherMissingAttributes(self, objs):
        allMissingAttributes = dict()

        for obj in objs:
            className, attributesMissingInClass = self.findMissingAttributes(obj)
            if len(attributesMissingInClass) > 0:
                if className not in allMissingAttributes:
                    allMissingAttributes[className] = dict()
                allMissingAttributes[className].update(attributesMissingInClass)

        return allMissingAttributes
