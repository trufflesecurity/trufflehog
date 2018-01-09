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

import github.HookResponse


class Hook(github.GithubObject.CompletableGithubObject):
    """
    This class represents Hooks as returned for example by http://developer.github.com/v3/repos/hooks
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "url": self._url.value})

    @property
    def active(self):
        """
        :type: bool
        """
        self._completeIfNotSet(self._active)
        return self._active.value

    @property
    def config(self):
        """
        :type: dict
        """
        self._completeIfNotSet(self._config)
        return self._config.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def events(self):
        """
        :type: list of string
        """
        self._completeIfNotSet(self._events)
        return self._events.value

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def last_response(self):
        """
        :type: :class:`github.HookResponse.HookResponse`
        """
        self._completeIfNotSet(self._last_response)
        return self._last_response.value

    @property
    def name(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._name)
        return self._name.value

    @property
    def test_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._test_url)
        return self._test_url.value

    @property
    def updated_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._updated_at)
        return self._updated_at.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def delete(self):
        """
        :calls: `DELETE /repos/:owner/:repo/hooks/:id <http://developer.github.com/v3/repos/hooks>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def edit(self, name, config, events=github.GithubObject.NotSet, add_events=github.GithubObject.NotSet, remove_events=github.GithubObject.NotSet, active=github.GithubObject.NotSet):
        """
        :calls: `PATCH /repos/:owner/:repo/hooks/:id <http://developer.github.com/v3/repos/hooks>`_
        :param name: string
        :param config: dict
        :param events: list of string
        :param add_events: list of string
        :param remove_events: list of string
        :param active: bool
        :rtype: None
        """
        assert isinstance(name, str), name
        assert isinstance(config, dict), config
        assert events is github.GithubObject.NotSet or all(isinstance(element, str) for element in events), events
        assert add_events is github.GithubObject.NotSet or all(isinstance(element, str) for element in add_events), add_events
        assert remove_events is github.GithubObject.NotSet or all(isinstance(element, str) for element in remove_events), remove_events
        assert active is github.GithubObject.NotSet or isinstance(active, bool), active
        post_parameters = {
            "name": name,
            "config": config,
        }
        if events is not github.GithubObject.NotSet:
            post_parameters["events"] = events
        if add_events is not github.GithubObject.NotSet:
            post_parameters["add_events"] = add_events
        if remove_events is not github.GithubObject.NotSet:
            post_parameters["remove_events"] = remove_events
        if active is not github.GithubObject.NotSet:
            post_parameters["active"] = active
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def test(self):
        """
        :calls: `POST /repos/:owner/:repo/hooks/:id/tests <http://developer.github.com/v3/repos/hooks>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/tests"
        )

    def _initAttributes(self):
        self._active = github.GithubObject.NotSet
        self._config = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._events = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._last_response = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._test_url = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "active" in attributes:  # pragma no branch
            self._active = self._makeBoolAttribute(attributes["active"])
        if "config" in attributes:  # pragma no branch
            self._config = self._makeDictAttribute(attributes["config"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "events" in attributes:  # pragma no branch
            self._events = self._makeListOfStringsAttribute(attributes["events"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "last_response" in attributes:  # pragma no branch
            self._last_response = self._makeClassAttribute(github.HookResponse.HookResponse, attributes["last_response"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "test_url" in attributes:  # pragma no branch
            self._test_url = self._makeStringAttribute(attributes["test_url"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
