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


class StatsCommitActivity(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents statistics of commit activity. The reference can be found here http://developer.github.com/v3/repos/statistics/#get-the-last-year-of-commit-activity-data
    """

    @property
    def week(self):
        """
        :type: datetime.datetime
        """
        return self._week.value

    @property
    def total(self):
        """
        :type: int
        """
        return self._total.value

    @property
    def days(self):
        """
        :type: list of int
        """
        return self._days.value

    def _initAttributes(self):
        self._week = github.GithubObject.NotSet
        self._total = github.GithubObject.NotSet
        self._days = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "week" in attributes:  # pragma no branch
            self._week = self._makeTimestampAttribute(attributes["week"])
        if "total" in attributes:  # pragma no branch
            self._total = self._makeIntAttribute(attributes["total"])
        if "days" in attributes:  # pragma no branch
            self._days = self._makeListOfIntsAttribute(attributes["days"])
