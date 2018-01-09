# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
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

import github.GithubObject

import github.NamedUser
import github.CommitStats
import github.Gist


class GistHistoryState(github.GithubObject.CompletableGithubObject):
    """
    This class represents GistHistoryStates as returned for example by http://developer.github.com/v3/todo
    """

    @property
    def change_status(self):
        """
        :type: :class:`github.CommitStats.CommitStats`
        """
        self._completeIfNotSet(self._change_status)
        return self._change_status.value

    @property
    def comments(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._comments)
        return self._comments.value

    @property
    def comments_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._comments_url)
        return self._comments_url.value

    @property
    def commits_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._commits_url)
        return self._commits_url.value

    @property
    def committed_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._committed_at)
        return self._committed_at.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def description(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._description)
        return self._description.value

    @property
    def files(self):
        """
        :type: dict of string to :class:`github.GistFile.GistFile`
        """
        self._completeIfNotSet(self._files)
        return self._files.value

    @property
    def forks(self):
        """
        :type: list of :class:`github.Gist.Gist`
        """
        self._completeIfNotSet(self._forks)
        return self._forks.value

    @property
    def forks_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._forks_url)
        return self._forks_url.value

    @property
    def git_pull_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._git_pull_url)
        return self._git_pull_url.value

    @property
    def git_push_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._git_push_url)
        return self._git_push_url.value

    @property
    def history(self):
        """
        :type: list of :class:`GistHistoryState`
        """
        self._completeIfNotSet(self._history)
        return self._history.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    @property
    def id(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def owner(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._owner)
        return self._owner.value

    @property
    def public(self):
        """
        :type: bool
        """
        self._completeIfNotSet(self._public)
        return self._public.value

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
    def user(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._user)
        return self._user.value

    @property
    def version(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._version)
        return self._version.value

    def _initAttributes(self):
        self._change_status = github.GithubObject.NotSet
        self._comments = github.GithubObject.NotSet
        self._comments_url = github.GithubObject.NotSet
        self._commits_url = github.GithubObject.NotSet
        self._committed_at = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._description = github.GithubObject.NotSet
        self._files = github.GithubObject.NotSet
        self._forks = github.GithubObject.NotSet
        self._forks_url = github.GithubObject.NotSet
        self._git_pull_url = github.GithubObject.NotSet
        self._git_push_url = github.GithubObject.NotSet
        self._history = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._owner = github.GithubObject.NotSet
        self._public = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._user = github.GithubObject.NotSet
        self._version = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "change_status" in attributes:  # pragma no branch
            self._change_status = self._makeClassAttribute(github.CommitStats.CommitStats, attributes["change_status"])
        if "comments" in attributes:  # pragma no branch
            self._comments = self._makeIntAttribute(attributes["comments"])
        if "comments_url" in attributes:  # pragma no branch
            self._comments_url = self._makeStringAttribute(attributes["comments_url"])
        if "commits_url" in attributes:  # pragma no branch
            self._commits_url = self._makeStringAttribute(attributes["commits_url"])
        if "committed_at" in attributes:  # pragma no branch
            self._committed_at = self._makeDatetimeAttribute(attributes["committed_at"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "description" in attributes:  # pragma no branch
            self._description = self._makeStringAttribute(attributes["description"])
        if "files" in attributes:  # pragma no branch
            self._files = self._makeDictOfStringsToClassesAttribute(github.GistFile.GistFile, attributes["files"])
        if "forks" in attributes:  # pragma no branch
            self._forks = self._makeListOfClassesAttribute(github.Gist.Gist, attributes["forks"])
        if "forks_url" in attributes:  # pragma no branch
            self._forks_url = self._makeStringAttribute(attributes["forks_url"])
        if "git_pull_url" in attributes:  # pragma no branch
            self._git_pull_url = self._makeStringAttribute(attributes["git_pull_url"])
        if "git_push_url" in attributes:  # pragma no branch
            self._git_push_url = self._makeStringAttribute(attributes["git_push_url"])
        if "history" in attributes:  # pragma no branch
            self._history = self._makeListOfClassesAttribute(GistHistoryState, attributes["history"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeStringAttribute(attributes["id"])
        if "owner" in attributes:  # pragma no branch
            self._owner = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["owner"])
        if "public" in attributes:  # pragma no branch
            self._public = self._makeBoolAttribute(attributes["public"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "user" in attributes:  # pragma no branch
            self._user = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["user"])
        if "version" in attributes:  # pragma no branch
            self._version = self._makeStringAttribute(attributes["version"])
