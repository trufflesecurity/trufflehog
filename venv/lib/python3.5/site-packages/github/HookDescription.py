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


class HookDescription(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents HookDescriptions as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"name": self._name.value})

    @property
    def events(self):
        """
        :type: list of string
        """
        return self._events.value

    @property
    def name(self):
        """
        :type: string
        """
        return self._name.value

    @property
    def schema(self):
        """
        :type: list of list of string
        """
        return self._schema.value

    @property
    def supported_events(self):
        """
        :type: list of string
        """
        return self._supported_events.value

    def _initAttributes(self):
        self._events = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._schema = github.GithubObject.NotSet
        self._supported_events = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "events" in attributes:  # pragma no branch
            self._events = self._makeListOfStringsAttribute(attributes["events"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "schema" in attributes:  # pragma no branch
            self._schema = self._makeListOfListOfStringsAttribute(attributes["schema"])
        if "supported_events" in attributes:  # pragma no branch
            self._supported_events = self._makeListOfStringsAttribute(attributes["supported_events"])
