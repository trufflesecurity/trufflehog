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


class GithubException(Exception):
    """
    Error handling in PyGithub is done with exceptions. This class is the base of all exceptions raised by PyGithub (but :class:`github.GithubException.BadAttributeException`).

    Some other types of exceptions might be raised by underlying libraries, for example for network-related issues.
    """

    def __init__(self, status, data):
        Exception.__init__(self)
        self.__status = status
        self.__data = data
        self.args = [status, data]

    @property
    def status(self):
        """
        The status returned by the Github API
        """
        return self.__status

    @property
    def data(self):
        """
        The (decoded) data returned by the Github API
        """
        return self.__data

    def __str__(self):
        return str(self.status) + " " + str(self.data)


class BadCredentialsException(GithubException):
    """
    Exception raised in case of bad credentials (when Github API replies with a 401 or 403 HTML status)
    """


class UnknownObjectException(GithubException):
    """
    Exception raised when a non-existing object is requested (when Github API replies with a 404 HTML status)
    """


class BadUserAgentException(GithubException):
    """
    Exception raised when request is sent with a bad user agent header (when Github API replies with a 403 bad user agent HTML status)
    """


class RateLimitExceededException(GithubException):
    """
    Exception raised when the rate limit is exceeded (when Github API replies with a 403 rate limit exceeded HTML status)
    """


class BadAttributeException(Exception):
    """
    Exception raised when Github returns an attribute with the wrong type.
    """
    def __init__(self, actualValue, expectedType, transformationException):
        self.__actualValue = actualValue
        self.__expectedType = expectedType
        self.__transformationException = transformationException

    @property
    def actual_value(self):
        """
        The value returned by Github
        """
        return self.__actualValue

    @property
    def expected_type(self):
        """
        The type PyGithub expected
        """
        return self.__expectedType

    @property
    def transformation_exception(self):
        """
        The exception raised when PyGithub tried to parse the value
        """
        return self.__transformationException


class TwoFactorException(GithubException):
    """
    Exception raised when Github requires a onetime password for two-factor authentication
    """
