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

import github.GithubObject

import github.NamedUser


class StatsParticipation(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents statistics of participation. The reference can be found here http://developer.github.com/v3/repos/statistics/#get-the-weekly-commit-count-for-the-repo-owner-and-everyone-else
    """

    @property
    def all(self):
        """
        :type: list of int
        """
        return self._all.value

    @property
    def owner(self):
        """
        :type: list of int
        """
        return self._owner.value

    def _initAttributes(self):
        self._all = github.GithubObject.NotSet
        self._owner = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "all" in attributes:  # pragma no branch
            self._all = self._makeListOfIntsAttribute(attributes["all"])
        if "owner" in attributes:  # pragma no branch
            self._owner = self._makeListOfIntsAttribute(attributes["owner"])
