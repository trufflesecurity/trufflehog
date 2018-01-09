# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Srijan Choudhary <srijan4@gmail.com>                          #
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


class RepositoryKey(github.GithubObject.CompletableGithubObject):
    """
    This class represents RepositoryKeys. The reference can be found here http://developer.github.com/v3/repos/keys/
    """

    def __init__(self, requester, headers, attributes, completed, repoUrl):
        github.GithubObject.CompletableGithubObject.__init__(self, requester, headers, attributes, completed)
        self.__repoUrl = repoUrl

    def __repr__(self):
        return self.get__repr__({"id": self._id.value})

    @property
    def __customUrl(self):
        return self.__repoUrl + "/keys/" + str(self.id)

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def key(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._key)
        return self._key.value

    @property
    def title(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._title)
        return self._title.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    @property
    def verified(self):
        """
        :type: bool
        """
        self._completeIfNotSet(self._verified)
        return self._verified.value

    def delete(self):
        """
        :calls: `DELETE /repos/:owner/:repo/keys/:id <http://developer.github.com/v3/repos/keys>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.__customUrl
        )

    def edit(self, title=github.GithubObject.NotSet, key=github.GithubObject.NotSet):
        """
        :calls: `PATCH /repos/:owner/:repo/keys/:id <http://developer.github.com/v3/repos/keys>`_
        :param title: string
        :param key: string
        :rtype: None
        """
        assert title is github.GithubObject.NotSet or isinstance(title, str), title
        assert key is github.GithubObject.NotSet or isinstance(key, str), key
        post_parameters = dict()
        if title is not github.GithubObject.NotSet:
            post_parameters["title"] = title
        if key is not github.GithubObject.NotSet:
            post_parameters["key"] = key
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.__customUrl,
            input=post_parameters
        )
        self._useAttributes(data)

    def _initAttributes(self):
        self._id = github.GithubObject.NotSet
        self._key = github.GithubObject.NotSet
        self._title = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._verified = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "key" in attributes:  # pragma no branch
            self._key = self._makeStringAttribute(attributes["key"])
        if "title" in attributes:  # pragma no branch
            self._title = self._makeStringAttribute(attributes["title"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "verified" in attributes:  # pragma no branch
            self._verified = self._makeBoolAttribute(attributes["verified"])
