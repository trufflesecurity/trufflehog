# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2016 Jannis gebauier <ja.geb@me.com>                               #
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

import datetime

import github.GithubObject
import github.PaginatedList
import github.NamedUser


class InstallationAuthorization(github.GithubObject.NonCompletableGithubObject):
    """
    InstallationAuthorization as obtained from a GitHub integration.
    """

    def __repr__(self):
        return self.get__repr__({"expires_at": self._expires_at.value})

    @property
    def token(self):
        """
        :type: string
        """
        return self._token.value

    @property
    def expires_at(self):
        """
        :type: datetime
        """
        return self._expires_at.value

    @property
    def on_behalf_of(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        return self._on_behalf_of.value

    def _initAttributes(self):
        self._token = github.GithubObject.NotSet
        self._expires_at = github.GithubObject.NotSet
        self._on_behalf_of = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "token" in attributes:  # pragma no branch
            self._token = self._makeStringAttribute(attributes["token"])
        if "expires_at" in attributes:  # pragma no branch
            self._expires_at = self._makeDatetimeAttribute(attributes["expires_at"])
        if "on_behalf_of" in attributes:  # pragma no branch
            self._on_behalf_of = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["on_behalf_of"])