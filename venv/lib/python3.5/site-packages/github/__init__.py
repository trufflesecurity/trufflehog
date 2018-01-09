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

"""
The primary class you will instanciate is :class:`github.MainClass.Github`.
From its ``get_``, ``create_`` methods, you will obtain instances of all Github objects
like :class:`github.NamedUser.NamedUser` or :class:`github.Repository.Repository`.

All classes inherit from :class:`github.GithubObject.GithubObject`.
"""

import logging

from .MainClass import Github, GithubIntegration
from .GithubException import GithubException, BadCredentialsException, UnknownObjectException, BadUserAgentException, RateLimitExceededException, BadAttributeException
from .InputFileContent import InputFileContent
from .InputGitAuthor import InputGitAuthor
from .InputGitTreeElement import InputGitTreeElement


def enable_console_debug_logging():  # pragma no cover (Function useful only outside test environment)
    """
    This function sets up a very simple logging configuration (log everything on standard output) that is useful for troubleshooting.
    """

    logger = logging.getLogger("github")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
