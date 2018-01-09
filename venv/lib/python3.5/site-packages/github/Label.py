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

import urllib.request, urllib.parse, urllib.error

import github.GithubObject


class Label(github.GithubObject.CompletableGithubObject):
    """
    This class represents Labels. The reference can be found here http://developer.github.com/v3/issues/labels/
    """

    def __repr__(self):
        return self.get__repr__({"name": self._name.value})

    @property
    def color(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._color)
        return self._color.value

    @property
    def name(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._name)
        return self._name.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def delete(self):
        """
        :calls: `DELETE /repos/:owner/:repo/labels/:name <http://developer.github.com/v3/issues/labels>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def edit(self, name, color):
        """
        :calls: `PATCH /repos/:owner/:repo/labels/:name <http://developer.github.com/v3/issues/labels>`_
        :param name: string
        :param color: string
        :rtype: None
        """
        assert isinstance(name, str), name
        assert isinstance(color, str), color
        post_parameters = {
            "name": name,
            "color": color,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    @property
    def _identity(self):
        return urllib.parse.quote(self.name)

    def _initAttributes(self):
        self._color = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "color" in attributes:  # pragma no branch
            self._color = self._makeStringAttribute(attributes["color"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
