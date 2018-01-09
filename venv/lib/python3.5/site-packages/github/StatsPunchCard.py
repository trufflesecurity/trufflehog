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


class StatsPunchCard(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents the punch card. The reference can be found here http://developer.github.com/v3/repos/statistics/#get-the-number-of-commits-per-hour-in-each-day
    """

    def get(self, day, hour):
        """
        Get a specific element
        :param day: int
        :param hour: int
        :rtype: int
        """
        return self._dict[(day, hour)]

    def _initAttributes(self):
        self._dict = {}

    def _useAttributes(self, attributes):
        for day, hour, commits in attributes:
            self._dict[(day, hour)] = commits
