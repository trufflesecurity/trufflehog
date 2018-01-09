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

import github.Organization
import github.Repository
import github.NamedUser


class Event(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Events. The reference can be found here http://developer.github.com/v3/activity/events/
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "type": self._type.value})

    @property
    def actor(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        return self._actor.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        return self._created_at.value

    @property
    def id(self):
        """
        :type: string
        """
        return self._id.value

    @property
    def org(self):
        """
        :type: :class:`github.Organization.Organization`
        """
        return self._org.value

    @property
    def payload(self):
        """
        :type: dict
        """
        return self._payload.value

    @property
    def public(self):
        """
        :type: bool
        """
        return self._public.value

    @property
    def repo(self):
        """
        :type: :class:`github.Repository.Repository`
        """
        return self._repo.value

    @property
    def type(self):
        """
        :type: string
        """
        return self._type.value

    def _initAttributes(self):
        self._actor = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._org = github.GithubObject.NotSet
        self._payload = github.GithubObject.NotSet
        self._public = github.GithubObject.NotSet
        self._repo = github.GithubObject.NotSet
        self._type = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "actor" in attributes:  # pragma no branch
            self._actor = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["actor"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeStringAttribute(attributes["id"])
        if "org" in attributes:  # pragma no branch
            self._org = self._makeClassAttribute(github.Organization.Organization, attributes["org"])
        if "payload" in attributes:  # pragma no branch
            self._payload = self._makeDictAttribute(attributes["payload"])
        if "public" in attributes:  # pragma no branch
            self._public = self._makeBoolAttribute(attributes["public"])
        if "repo" in attributes:  # pragma no branch
            self._repo = self._makeClassAttribute(github.Repository.Repository, attributes["repo"])
        if "type" in attributes:  # pragma no branch
            self._type = self._makeStringAttribute(attributes["type"])
