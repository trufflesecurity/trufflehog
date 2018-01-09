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


class Plan(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Plans as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"name": self._name.value})

    @property
    def collaborators(self):
        """
        :type: integer
        """
        return self._collaborators.value

    @property
    def name(self):
        """
        :type: string
        """
        return self._name.value

    @property
    def private_repos(self):
        """
        :type: integer
        """
        return self._private_repos.value

    @property
    def space(self):
        """
        :type: integer
        """
        return self._space.value

    def _initAttributes(self):
        self._collaborators = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._private_repos = github.GithubObject.NotSet
        self._space = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "collaborators" in attributes:  # pragma no branch
            self._collaborators = self._makeIntAttribute(attributes["collaborators"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "private_repos" in attributes:  # pragma no branch
            self._private_repos = self._makeIntAttribute(attributes["private_repos"])
        if "space" in attributes:  # pragma no branch
            self._space = self._makeIntAttribute(attributes["space"])
