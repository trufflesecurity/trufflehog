# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Christopher Gilbert <christopher.john.gilbert@gmail.com>      #
# Copyright 2012 Steve English <steve.english@navetas.com>                     #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Adrian Petrescu <adrian.petrescu@maluuba.com>                 #
# Copyright 2013 Mark Roddy <markroddy@gmail.com>                              #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2013 martinqt <m.ki2@laposte.net>                                  #
# Copyright 2015 Dan Vanderkam <danvdk@gmail.com>                              #
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

import github


class Stargazer(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Stargazers with the date of starring as returned by
    https://developer.github.com/v3/activity/starring/#alternative-response-with-star-creation-timestamps
    """

    def __repr__(self):
        return self.get__repr__({"user": self._user.value._login.value})

    @property
    def starred_at(self):
        """
        :type: datetime.datetime
        """
        return self._starred_at.value

    @property
    def user(self):
        """
        :type: :class:`github.NamedUser`
        """
        return self._user.value

    def _initAttributes(self):
        self._starred_at = github.GithubObject.NotSet
        self._user = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if 'starred_at' in attributes:
            self._starred_at = self._makeDatetimeAttribute(attributes['starred_at'])
        if 'user' in attributes:
            self._user = self._makeClassAttribute(github.NamedUser.NamedUser, attributes['user'])
