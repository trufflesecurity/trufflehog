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

import github.AuthorizationApplication


class Authorization(github.GithubObject.CompletableGithubObject):
    """
    This class represents Authorizations as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"scopes": self._scopes.value})

    @property
    def app(self):
        """
        :type: :class:`github.AuthorizationApplication.AuthorizationApplication`
        """
        self._completeIfNotSet(self._app)
        return self._app.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def note(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._note)
        return self._note.value

    @property
    def note_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._note_url)
        return self._note_url.value

    @property
    def scopes(self):
        """
        :type: list of string
        """
        self._completeIfNotSet(self._scopes)
        return self._scopes.value

    @property
    def token(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._token)
        return self._token.value

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
        :calls: `DELETE /authorizations/:id <http://developer.github.com/v3/oauth>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def edit(self, scopes=github.GithubObject.NotSet, add_scopes=github.GithubObject.NotSet, remove_scopes=github.GithubObject.NotSet, note=github.GithubObject.NotSet, note_url=github.GithubObject.NotSet):
        """
        :calls: `PATCH /authorizations/:id <http://developer.github.com/v3/oauth>`_
        :param scopes: list of string
        :param add_scopes: list of string
        :param remove_scopes: list of string
        :param note: string
        :param note_url: string
        :rtype: None
        """
        assert scopes is github.GithubObject.NotSet or all(isinstance(element, str) for element in scopes), scopes
        assert add_scopes is github.GithubObject.NotSet or all(isinstance(element, str) for element in add_scopes), add_scopes
        assert remove_scopes is github.GithubObject.NotSet or all(isinstance(element, str) for element in remove_scopes), remove_scopes
        assert note is github.GithubObject.NotSet or isinstance(note, str), note
        assert note_url is github.GithubObject.NotSet or isinstance(note_url, str), note_url
        post_parameters = dict()
        if scopes is not github.GithubObject.NotSet:
            post_parameters["scopes"] = scopes
        if add_scopes is not github.GithubObject.NotSet:
            post_parameters["add_scopes"] = add_scopes
        if remove_scopes is not github.GithubObject.NotSet:
            post_parameters["remove_scopes"] = remove_scopes
        if note is not github.GithubObject.NotSet:
            post_parameters["note"] = note
        if note_url is not github.GithubObject.NotSet:
            post_parameters["note_url"] = note_url
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def _initAttributes(self):
        self._app = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._note = github.GithubObject.NotSet
        self._note_url = github.GithubObject.NotSet
        self._scopes = github.GithubObject.NotSet
        self._token = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "app" in attributes:  # pragma no branch
            self._app = self._makeClassAttribute(github.AuthorizationApplication.AuthorizationApplication, attributes["app"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "note" in attributes:  # pragma no branch
            self._note = self._makeStringAttribute(attributes["note"])
        if "note_url" in attributes:  # pragma no branch
            self._note_url = self._makeStringAttribute(attributes["note_url"])
        if "scopes" in attributes:  # pragma no branch
            self._scopes = self._makeListOfStringsAttribute(attributes["scopes"])
        if "token" in attributes:  # pragma no branch
            self._token = self._makeStringAttribute(attributes["token"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
