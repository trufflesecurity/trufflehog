# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
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


class NotificationSubject(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Subjects of Notifications as returned for example by http://developer.github.com/v3/activity/notifications/#list-your-notifications
    """

    def __repr__(self):
        return self.get__repr__({"title": self._title.value})

    @property
    def title(self):
        """
        :type: string
        """
        return self._title.value

    @property
    def url(self):
        """
        :type: string
        """
        return self._url.value

    @property
    def latest_comment_url(self):
        """
        :type: string
        """
        return self._latest_comment_url.value

    @property
    def type(self):
        """
        :type: string
        """
        return self._type.value

    def _initAttributes(self):
        self._title = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._latest_comment_url = github.GithubObject.NotSet
        self._type = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "title" in attributes:  # pragma no branch
            self._title = self._makeStringAttribute(attributes["title"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "latest_comment_url" in attributes:  # pragma no branch
            self._latest_comment_url = self._makeStringAttribute(attributes["latest_comment_url"])
        if "type" in attributes:  # pragma no branch
            self._type = self._makeStringAttribute(attributes["type"])
