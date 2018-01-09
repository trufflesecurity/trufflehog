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


class GistFile(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents GistFiles as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"filename": self._filename.value})

    @property
    def content(self):
        """
        :type: string
        """
        return self._content.value

    @property
    def filename(self):
        """
        :type: string
        """
        return self._filename.value

    @property
    def language(self):
        """
        :type: string
        """
        return self._language.value

    @property
    def raw_url(self):
        """
        :type: string
        """
        return self._raw_url.value

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

    def _initAttributes(self):
        self._content = github.GithubObject.NotSet
        self._filename = github.GithubObject.NotSet
        self._language = github.GithubObject.NotSet
        self._raw_url = github.GithubObject.NotSet
        self._size = github.GithubObject.NotSet
        self._type = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "content" in attributes:  # pragma no branch
            self._content = self._makeStringAttribute(attributes["content"])
        if "filename" in attributes:  # pragma no branch
            self._filename = self._makeStringAttribute(attributes["filename"])
        if "language" in attributes:  # pragma no branch
            self._language = self._makeStringAttribute(attributes["language"])
        if "raw_url" in attributes:  # pragma no branch
            self._raw_url = self._makeStringAttribute(attributes["raw_url"])
        if "size" in attributes:  # pragma no branch
            self._size = self._makeIntAttribute(attributes["size"])
        if "type" in attributes:  # pragma no branch
            self._type = self._makeStringAttribute(attributes["type"])
