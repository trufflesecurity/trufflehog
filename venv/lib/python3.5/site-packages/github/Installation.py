# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2017 Jannis Gebauer <ja.geb@me.com>                                #
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
import github.PaginatedList

import github.Gist
import github.Repository
import github.NamedUser
import github.Plan
import github.Organization
import github.UserKey
import github.Issue
import github.Event
import github.Authorization
import github.Notification

INTEGRATION_PREVIEW_HEADERS = {"Accept": "application/vnd.github.machine-man-preview+json"}


class Installation(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Installations as in https://developer.github.com/v3/integrations/installations
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value})

    @property
    def id(self):
        return self._id

    def get_repos(self):
        """
        :calls: `GET /installation/repositories <https://developer.github.com/v3/integrations/installations/#list-repositories>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Repository.Repository`
        """
        url_parameters = dict()

        return github.PaginatedList.PaginatedList(
            contentClass=github.Repository.Repository,
            requester=self._requester,
            firstUrl="/installation/repositories",
            firstParams=url_parameters,
            headers=INTEGRATION_PREVIEW_HEADERS,
            list_item='repositories'
        )

    def _initAttributes(self):
        self._id = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])