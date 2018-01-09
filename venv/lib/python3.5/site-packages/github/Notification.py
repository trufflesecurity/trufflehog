# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Peter Golm <golm.peter@gmail.com>                             #
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

import github.Repository
import github.NotificationSubject


class Notification(github.GithubObject.CompletableGithubObject):
    """
    This class represents Notifications. The reference can be found here http://developer.github.com/v3/activity/notifications/
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "subject": self._subject.value})

    @property
    def id(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def last_read_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._last_read_at)
        return self._last_read_at.value

    @property
    def repository(self):
        """
        :type: :class:`github.Repository.Repository`
        """
        self._completeIfNotSet(self._repository)
        return self._repository.value

    @property
    def subject(self):
        """
        :type: :class:`github.NotificationSubject.NotificationSubject`
        """
        self._completeIfNotSet(self._subject)
        return self._subject.value

    @property
    def reason(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._reason)
        return self._reason.value

    @property
    def subscription_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._subscription_url)
        return self._subscription_url.value

    @property
    def unread(self):
        """
        :type: bool
        """
        self._completeIfNotSet(self._unread)
        return self._unread.value

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

    def _initAttributes(self):
        self._id = github.GithubObject.NotSet
        self._last_read_at = github.GithubObject.NotSet
        self._repository = github.GithubObject.NotSet
        self._reason = github.GithubObject.NotSet
        self._subscription_url = github.GithubObject.NotSet
        self._unread = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "id" in attributes:  # pragma no branch
            self._id = self._makeStringAttribute(attributes["id"])
        if "last_read_at" in attributes:  # pragma no branch
            self._last_read_at = self._makeDatetimeAttribute(attributes["last_read_at"])
        if "repository" in attributes:  # pragma no branch
            self._repository = self._makeClassAttribute(github.Repository.Repository, attributes["repository"])
        if "subject" in attributes:  # pragma no branch
            self._subject = self._makeClassAttribute(github.NotificationSubject.NotificationSubject, attributes["subject"])
        if "reason" in attributes:  # pragma no branch
            self._reason = self._makeStringAttribute(attributes["reason"])
        if "subscription_url" in attributes:  # pragma no branch
            self._subscription_url = self._makeStringAttribute(attributes["subscription_url"])
        if "unread" in attributes:  # pragma no branch
            self._unread = self._makeBoolAttribute(attributes["unread"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
