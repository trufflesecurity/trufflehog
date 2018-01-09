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

import github.Repository
import github.NamedUser


class PullRequestPart(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents PullRequestParts as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value})

    @property
    def label(self):
        """
        :type: string
        """
        return self._label.value

    @property
    def ref(self):
        """
        :type: string
        """
        return self._ref.value

    @property
    def repo(self):
        """
        :type: :class:`github.Repository.Repository`
        """
        return self._repo.value

    @property
    def sha(self):
        """
        :type: string
        """
        return self._sha.value

    @property
    def user(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        return self._user.value

    def _initAttributes(self):
        self._label = github.GithubObject.NotSet
        self._ref = github.GithubObject.NotSet
        self._repo = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._user = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "label" in attributes:  # pragma no branch
            self._label = self._makeStringAttribute(attributes["label"])
        if "ref" in attributes:  # pragma no branch
            self._ref = self._makeStringAttribute(attributes["ref"])
        if "repo" in attributes:  # pragma no branch
            self._repo = self._makeClassAttribute(github.Repository.Repository, attributes["repo"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "user" in attributes:  # pragma no branch
            self._user = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["user"])
