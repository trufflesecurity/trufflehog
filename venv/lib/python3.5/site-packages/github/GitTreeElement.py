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


class GitTreeElement(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents GitTreeElements as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value, "path": self._path.value})

    @property
    def mode(self):
        """
        :type: string
        """
        return self._mode.value

    @property
    def path(self):
        """
        :type: string
        """
        return self._path.value

    @property
    def sha(self):
        """
        :type: string
        """
        return self._sha.value

    @property
    def size(self):
        """
        :type: integer
        """
        return self._size.value

    @property
    def type(self):
        """
        :type: string
        """
        return self._type.value

    @property
    def url(self):
        """
        :type: string
        """
        return self._url.value

    def _initAttributes(self):
        self._mode = github.GithubObject.NotSet
        self._path = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._size = github.GithubObject.NotSet
        self._type = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "mode" in attributes:  # pragma no branch
            self._mode = self._makeStringAttribute(attributes["mode"])
        if "path" in attributes:  # pragma no branch
            self._path = self._makeStringAttribute(attributes["path"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "size" in attributes:  # pragma no branch
            self._size = self._makeIntAttribute(attributes["size"])
        if "type" in attributes:  # pragma no branch
            self._type = self._makeStringAttribute(attributes["type"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
