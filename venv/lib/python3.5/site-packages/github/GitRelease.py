# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2015 Ed Holland <eholland@alertlogic.com>                          #
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
import github.GitAuthor


class GitRelease(github.GithubObject.CompletableGithubObject):
    """
    This class represents GitRelease as returned for example by https://developer.github.com/v3/repos/releases
    """

    def __repr__(self):
        return self.get__repr__({"title": self._title.value})

    @property
    def body(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._body)
        return self._body.value

    @property
    def title(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._title)
        return self._title.value

    @property
    def tag_name(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._tag_name)
        return self._tag_name.value

    @property
    def author(self):
        """
        :type: :class:`github.GitAuthor.GitAuthor`
        """
        self._completeIfNotSet(self._author)
        return self._author.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    @property
    def upload_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._upload_url)
        return self._upload_url.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    def delete_release(self):
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )
        return True

    def update_release(self, name, message, draft=False, prerelease=False):
        assert isinstance(name, str), name
        assert isinstance(message, str), message
        assert isinstance(draft, bool), draft
        assert isinstance(prerelease, bool), prerelease
        post_parameters = {
            "tag_name": self.tag_name,
            "name": name,
            "body": message,
            "draft": draft,
            "prerelease": prerelease,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        return github.GitRelease.GitRelease(self._requester, headers, data, completed=True)

    def _initAttributes(self):
        self._body = github.GithubObject.NotSet
        self._title = github.GithubObject.NotSet
        self._tag_name = github.GithubObject.NotSet
        self._author = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._upload_url = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "body" in attributes:
            self._body = self._makeStringAttribute(attributes["body"])
        if "name" in attributes:
            self._title = self._makeStringAttribute(attributes["name"])
        if "tag_name" in attributes:
            self._tag_name = self._makeStringAttribute(attributes["tag_name"])
        if "author" in attributes:
            self._author = self._makeClassAttribute(github.GitAuthor.GitAuthor, attributes["author"])
        if "url" in attributes:
            self._url = self._makeStringAttribute(attributes["url"])
        if "upload_url" in attributes:
            self._upload_url = self._makeStringAttribute(attributes["upload_url"])
        if "html_url" in attributes:
            self._html_url = self._makeStringAttribute(attributes["html_url"])
