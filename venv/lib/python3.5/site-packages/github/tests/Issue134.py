# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
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

from . import Framework
import github


class Issue134(Framework.BasicTestCase):  # https://github.com/jacquev6/PyGithub/pull/134
    def testGetAuthorizationsFailsWhenAutenticatedThroughOAuth(self):
        g = github.Github(self.oauth_token)
        raised = False
        try:
            list(g.get_user().get_authorizations())
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 404)
        self.assertTrue(raised)

    def testGetAuthorizationsSucceedsWhenAutenticatedThroughLoginPassword(self):
        g = github.Github(self.login, self.password)
        self.assertListKeyEqual(g.get_user().get_authorizations(), lambda a: a.note, [None, None, 'cligh', None, None, 'GitHub Android App'])

    def testGetOAuthScopesFromHeader(self):
        g = github.Github(self.oauth_token)
        self.assertEqual(g.oauth_scopes, None)
        g.get_user().name
        self.assertEqual(g.oauth_scopes, ['repo', 'user', 'gist'])
