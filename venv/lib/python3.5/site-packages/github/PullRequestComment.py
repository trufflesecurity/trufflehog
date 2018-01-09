# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Michael Stead <michael.stead@gmail.com>                       #
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

import github.NamedUser


class PullRequestComment(github.GithubObject.CompletableGithubObject):
    """
    This class represents PullRequestComments. The reference can be found here http://developer.github.com/v3/pulls/comments/
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "user": self._user.value})

    @property
    def body(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._body)
        return self._body.value

    @property
    def commit_id(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._commit_id)
        return self._commit_id.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def diff_hunk(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._diff_hunk)
        return self._diff_hunk.value

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def original_commit_id(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._original_commit_id)
        return self._original_commit_id.value

    @property
    def original_position(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._original_position)
        return self._original_position.value

    @property
    def path(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._path)
        return self._path.value

    @property
    def position(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._position)
        return self._position.value

    @property
    def pull_request_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._pull_request_url)
        return self._pull_request_url.value

    @property
    def updated_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._updated_at)
        return self._updated_at.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    @property
    def user(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._user)
        return self._user.value

    def delete(self):
        """
        :calls: `DELETE /repos/:owner/:repo/pulls/comments/:number <http://developer.github.com/v3/pulls/comments>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def edit(self, body):
        """
        :calls: `PATCH /repos/:owner/:repo/pulls/comments/:number <http://developer.github.com/v3/pulls/comments>`_
        :param body: string
        :rtype: None
        """
        assert isinstance(body, str), body
        post_parameters = {
            "body": body,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def _initAttributes(self):
        self._body = github.GithubObject.NotSet
        self._commit_id = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._diff_hunk = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._original_commit_id = github.GithubObject.NotSet
        self._original_position = github.GithubObject.NotSet
        self._path = github.GithubObject.NotSet
        self._position = github.GithubObject.NotSet
        self._pull_request_url = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._user = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "body" in attributes:  # pragma no branch
            self._body = self._makeStringAttribute(attributes["body"])
        if "commit_id" in attributes:  # pragma no branch
            self._commit_id = self._makeStringAttribute(attributes["commit_id"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "diff_hunk" in attributes:  # pragma no branch
            self._diff_hunk = self._makeStringAttribute(attributes["diff_hunk"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "original_commit_id" in attributes:  # pragma no branch
            self._original_commit_id = self._makeStringAttribute(attributes["original_commit_id"])
        if "original_position" in attributes:  # pragma no branch
            self._original_position = self._makeIntAttribute(attributes["original_position"])
        if "path" in attributes:  # pragma no branch
            self._path = self._makeStringAttribute(attributes["path"])
        if "position" in attributes:  # pragma no branch
            self._position = self._makeIntAttribute(attributes["position"])
        if "pull_request_url" in attributes:  # pragma no branch
            self._pull_request_url = self._makeStringAttribute(attributes["pull_request_url"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "user" in attributes:  # pragma no branch
            self._user = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["user"])
