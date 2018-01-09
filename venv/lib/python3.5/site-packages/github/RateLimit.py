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
import github.Rate


class RateLimit(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents rate limits as defined in http://developer.github.com/v3/rate_limit
    """

    def __repr__(self):
        return self.get__repr__({"rate": self._rate.value})

    @property
    def rate(self):
        """
        :type: class:`github.Rate.Rate`
        """
        return self._rate.value

    def _initAttributes(self):
        self._rate = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "rate" in attributes:  # pragma no branch
            self._rate = self._makeClassAttribute(github.Rate.Rate, attributes["rate"])
