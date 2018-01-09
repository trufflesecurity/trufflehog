# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2013 martinqt <m.ki2@laposte.net>                                  #
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

import github.GithubObject
import github.PaginatedList

import github.GitCommit
import github.NamedUser
import github.CommitStatus
import github.CommitCombinedStatus
import github.File
import github.CommitStats
import github.CommitComment


class Commit(github.GithubObject.CompletableGithubObject):
    """
    This class represents Commits. The reference can be found here http://developer.github.com/v3/git/commits/
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value})

    @property
    def author(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._author)
        return self._author.value

    @property
    def comments_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._comments_url)
        return self._comments_url.value

    @property
    def commit(self):
        """
        :type: :class:`github.GitCommit.GitCommit`
        """
        self._completeIfNotSet(self._commit)
        return self._commit.value

    @property
    def committer(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._committer)
        return self._committer.value

    @property
    def files(self):
        """
        :type: list of :class:`github.File.File`
        """
        self._completeIfNotSet(self._files)
        return self._files.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    @property
    def parents(self):
        """
        :type: list of :class:`github.Commit.Commit`
        """
        self._completeIfNotSet(self._parents)
        return self._parents.value

    @property
    def sha(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._sha)
        return self._sha.value

    @property
    def stats(self):
        """
        :type: :class:`github.CommitStats.CommitStats`
        """
        self._completeIfNotSet(self._stats)
        return self._stats.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def create_comment(self, body, line=github.GithubObject.NotSet, path=github.GithubObject.NotSet, position=github.GithubObject.NotSet):
        """
        :calls: `POST /repos/:owner/:repo/commits/:sha/comments <http://developer.github.com/v3/repos/comments>`_
        :param body: string
        :param line: integer
        :param path: string
        :param position: integer
        :rtype: :class:`github.CommitComment.CommitComment`
        """
        assert isinstance(body, str), body
        assert line is github.GithubObject.NotSet or isinstance(line, int), line
        assert path is github.GithubObject.NotSet or isinstance(path, str), path
        assert position is github.GithubObject.NotSet or isinstance(position, int), position
        post_parameters = {
            "body": body,
        }
        if line is not github.GithubObject.NotSet:
            post_parameters["line"] = line
        if path is not github.GithubObject.NotSet:
            post_parameters["path"] = path
        if position is not github.GithubObject.NotSet:
            post_parameters["position"] = position
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/comments",
            input=post_parameters
        )
        return github.CommitComment.CommitComment(self._requester, headers, data, completed=True)

    def create_status(self, state, target_url=github.GithubObject.NotSet, description=github.GithubObject.NotSet, context=github.GithubObject.NotSet):
        """
        :calls: `POST /repos/:owner/:repo/statuses/:sha <http://developer.github.com/v3/repos/statuses>`_
        :param state: string
        :param target_url: string
        :param description: string
        :param context: string
        :rtype: :class:`github.CommitStatus.CommitStatus`
        """
        assert isinstance(state, str), state
        assert target_url is github.GithubObject.NotSet or isinstance(target_url, str), target_url
        assert description is github.GithubObject.NotSet or isinstance(description, str), description
        assert context is github.GithubObject.NotSet or isinstance(context, str), context
        post_parameters = {
            "state": state,
        }
        if target_url is not github.GithubObject.NotSet:
            post_parameters["target_url"] = target_url
        if description is not github.GithubObject.NotSet:
            post_parameters["description"] = description
        if context is not github.GithubObject.NotSet:
            post_parameters["context"] = context
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self._parentUrl(self._parentUrl(self.url)) + "/statuses/" + self.sha,
            input=post_parameters
        )
        return github.CommitStatus.CommitStatus(self._requester, headers, data, completed=True)

    def get_comments(self):
        """
        :calls: `GET /repos/:owner/:repo/commits/:sha/comments <http://developer.github.com/v3/repos/comments>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.CommitComment.CommitComment`
        """
        return github.PaginatedList.PaginatedList(
            github.CommitComment.CommitComment,
            self._requester,
            self.url + "/comments",
            None
        )

    def get_statuses(self):
        """
        :calls: `GET /repos/:owner/:repo/statuses/:ref <http://developer.github.com/v3/repos/statuses>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.CommitStatus.CommitStatus`
        """
        return github.PaginatedList.PaginatedList(
            github.CommitStatus.CommitStatus,
            self._requester,
            self._parentUrl(self._parentUrl(self.url)) + "/statuses/" + self.sha,
            None
        )

    def get_combined_status(self):
        """
        :calls: `GET /repos/:owner/:repo/commits/:ref/status/ <http://developer.github.com/v3/repos/statuses>`_
        :rtype: :class:`github.CommitCombinedStatus.CommitCombinedStatus`
        """
        headers, data = self._requester.requestJsonAndCheck(
            "GET",
            self.url + "/status"
        )
        return github.CommitCombinedStatus.CommitCombinedStatus(self._requester, headers, data, completed=True)

    @property
    def _identity(self):
        return self.sha

    def _initAttributes(self):
        self._author = github.GithubObject.NotSet
        self._comments_url = github.GithubObject.NotSet
        self._commit = github.GithubObject.NotSet
        self._committer = github.GithubObject.NotSet
        self._files = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._parents = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._stats = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "author" in attributes:  # pragma no branch
            self._author = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["author"])
        if "comments_url" in attributes:  # pragma no branch
            self._comments_url = self._makeStringAttribute(attributes["comments_url"])
        if "commit" in attributes:  # pragma no branch
            self._commit = self._makeClassAttribute(github.GitCommit.GitCommit, attributes["commit"])
        if "committer" in attributes:  # pragma no branch
            self._committer = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["committer"])
        if "files" in attributes:  # pragma no branch
            self._files = self._makeListOfClassesAttribute(github.File.File, attributes["files"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "parents" in attributes:  # pragma no branch
            self._parents = self._makeListOfClassesAttribute(Commit, attributes["parents"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "stats" in attributes:  # pragma no branch
            self._stats = self._makeClassAttribute(github.CommitStats.CommitStats, attributes["stats"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
