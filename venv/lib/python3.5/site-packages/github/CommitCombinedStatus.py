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

import github.CommitStatus
import github.Repository


class CommitCombinedStatus(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents CommitCombinedStatus as returned for example by https://developer.github.com/v3/repos/statuses/
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value, "state": self._state.value})

    @property
    def state(self):
        """
        :type: string
        """
        return self._state.value

    @property
    def sha(self):
        """
        :type: string
        """
        return self._sha.value

    @property
    def total_count(self):
        """
        :type: integer
        """
        return self._total_count.value

    @property
    def commit_url(self):
        """
        :type: string
        """
        return self._commit_url.value

    @property
    def url(self):
        """
        :type: string
        """
        return self._url.value

    @property
    def repository(self):
        """
        :type: :class:`github.Repository.Repository`
        """
        return self._repository.value

    @property
    def statuses(self):
        """
        :type: list of :class:`CommitStatus`
        """
        return self._statuses.value

    def _initAttributes(self):
        self._state = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._total_count = github.GithubObject.NotSet
        self._commit_url = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._repository = github.GithubObject.NotSet
        self._statuses = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "state" in attributes:  # pragma no branch
            self._state = self._makeStringAttribute(attributes["state"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "total_count" in attributes:  # pragma no branch
            self._total_count = self._makeIntAttribute(attributes["total_count"])
        if "commit_url" in attributes:  # pragma no branch
            self._commit_url = self._makeStringAttribute(attributes["commit_url"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "repository" in attributes:  # pragma no branch
            self._repository = self._makeClassAttribute(github.Repository.Repository, attributes["repository"])
        if "statuses" in attributes:  # pragma no branch
            self._statuses = self._makeListOfClassesAttribute(github.CommitStatus.CommitStatus, attributes["statuses"])
