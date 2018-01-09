# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2013 martinqt <m.ki2@laposte.net>                                  #
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

import github.Commit


class Tag(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Tags. The reference can be found here http://developer.github.com/v3/git/tags/
    """

    def __repr__(self):
        return self.get__repr__({
            "name": self._name.value,
            "commit": self._commit.value
        })

    @property
    def commit(self):
        """
        :type: :class:`github.Commit.Commit`
        """
        return self._commit.value

    @property
    def name(self):
        """
        :type: string
        """
        return self._name.value

    @property
    def tarball_url(self):
        """
        :type: string
        """
        return self._tarball_url.value

    @property
    def zipball_url(self):
        """
        :type: string
        """
        return self._zipball_url.value

    def _initAttributes(self):
        self._commit = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._tarball_url = github.GithubObject.NotSet
        self._zipball_url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "commit" in attributes:  # pragma no branch
            self._commit = self._makeClassAttribute(github.Commit.Commit, attributes["commit"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "tarball_url" in attributes:  # pragma no branch
            self._tarball_url = self._makeStringAttribute(attributes["tarball_url"])
        if "zipball_url" in attributes:  # pragma no branch
            self._zipball_url = self._makeStringAttribute(attributes["zipball_url"])
