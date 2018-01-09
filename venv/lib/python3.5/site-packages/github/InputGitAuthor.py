# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
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


class InputGitAuthor(object):
    """
    """

    def __init__(self, name, email, date=github.GithubObject.NotSet):
        """
        :param name: string
        :param email: string
        :param date: string
        """

        assert isinstance(name, str), name
        assert isinstance(email, str), email
        assert date is github.GithubObject.NotSet or isinstance(date, str), date  # @todo Datetime?

        self.__name = name
        self.__email = email
        self.__date = date

    def __repr__(self):
        return 'InputGitAuthor(name="{}")'.format(self.__name)

    @property
    def _identity(self):
        identity = {
            "name": self.__name,
            "email": self.__email,
        }
        if self.__date is not github.GithubObject.NotSet:
            identity["date"] = self.__date
        return identity
