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

import github.NamedUser


class CommitStatus(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents CommitStatuss as returned for example by https://developer.github.com/v3/repos/statuses/
    """

    def __repr__(self):
        return self.get__repr__({
            "id": self._id.value,
            "state": self._state.value,
            "context": self._context.value
        })

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        return self._created_at.value

    @property
    def creator(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        return self._creator.value

    @property
    def description(self):
        """
        :type: string
        """
        return self._description.value

    @property
    def id(self):
        """
        :type: integer
        """
        return self._id.value

    @property
    def state(self):
        """
        :type: string
        """
        return self._state.value

    @property
    def context(self):
        """
        :type: string
        """
        return self._context.value

    @property
    def target_url(self):
        """
        :type: string
        """
        return self._target_url.value

    @property
    def updated_at(self):
        """
        :type: datetime.datetime
        """
        return self._updated_at.value

    @property
    def url(self):
        """
        :type: string
        """
        return self._url.value

    def _initAttributes(self):
        self._created_at = github.GithubObject.NotSet
        self._creator = github.GithubObject.NotSet
        self._description = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._state = github.GithubObject.NotSet
        self._context = github.GithubObject.NotSet
        self._target_url = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "creator" in attributes:  # pragma no branch
            self._creator = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["creator"])
        if "description" in attributes:  # pragma no branch
            self._description = self._makeStringAttribute(attributes["description"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "state" in attributes:  # pragma no branch
            self._state = self._makeStringAttribute(attributes["state"])
        if "context" in attributes:  # pragma no branch
            self._context = self._makeStringAttribute(attributes["context"])
        if "target_url" in attributes:  # pragma no branch
            self._target_url = self._makeStringAttribute(attributes["target_url"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
