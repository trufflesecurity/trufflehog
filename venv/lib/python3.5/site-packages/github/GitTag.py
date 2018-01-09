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

import github.GitAuthor
import github.GitObject


class GitTag(github.GithubObject.CompletableGithubObject):
    """
    This class represents GitTags as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value, "tag": self._tag.value})

    @property
    def message(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._message)
        return self._message.value

    @property
    def object(self):
        """
        :type: :class:`github.GitObject.GitObject`
        """
        self._completeIfNotSet(self._object)
        return self._object.value

    @property
    def sha(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._sha)
        return self._sha.value

    @property
    def tag(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._tag)
        return self._tag.value

    @property
    def tagger(self):
        """
        :type: :class:`github.GitAuthor.GitAuthor`
        """
        self._completeIfNotSet(self._tagger)
        return self._tagger.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def _initAttributes(self):
        self._message = github.GithubObject.NotSet
        self._object = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._tag = github.GithubObject.NotSet
        self._tagger = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "message" in attributes:  # pragma no branch
            self._message = self._makeStringAttribute(attributes["message"])
        if "object" in attributes:  # pragma no branch
            self._object = self._makeClassAttribute(github.GitObject.GitObject, attributes["object"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "tag" in attributes:  # pragma no branch
            self._tag = self._makeStringAttribute(attributes["tag"])
        if "tagger" in attributes:  # pragma no branch
            self._tagger = self._makeClassAttribute(github.GitAuthor.GitAuthor, attributes["tagger"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
