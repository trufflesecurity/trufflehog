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

import github

from . import Framework


# Replay data for this test case is forged, because I don't have access to a real Github Enterprise install
class Enterprise(Framework.BasicTestCase):
    def testHttps(self):
        g = github.Github(self.login, self.password, base_url="https://my.enterprise.com")
        self.assertListKeyEqual(g.get_user().get_repos(), lambda r: r.name, ["TestPyGithub", "django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "Hacking", "vincent-jacques.net", "Contests", "Candidates", "Tests", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])

    def testHttp(self):
        g = github.Github(self.login, self.password, base_url="http://my.enterprise.com")
        self.assertListKeyEqual(g.get_user().get_repos(), lambda r: r.name, ["TestPyGithub", "django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "Hacking", "vincent-jacques.net", "Contests", "Candidates", "Tests", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])

    def testUnknownUrlScheme(self):  # To stay compatible with Python 2.6, we do not use self.assertRaises with only one argument
        try:
            github.Github(self.login, self.password, base_url="foobar://my.enterprise.com")
        except AssertionError as exception:
            raised = True
            self.assertEqual(exception.args[0], "Unknown URL scheme")
        self.assertTrue(raised)

    def testLongUrl(self):
        g = github.Github(self.login, self.password, base_url="http://my.enterprise.com/path/to/github")
        repos = g.get_user().get_repos()
        self.assertListKeyEqual(repos, lambda r: r.name, ["TestPyGithub", "django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "Hacking", "vincent-jacques.net", "Contests", "Candidates", "Tests", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])
        self.assertEqual(repos[0].owner.name, "Vincent Jacques")

    def testSpecificPort(self):
        g = github.Github(self.login, self.password, base_url="http://my.enterprise.com:8080")
        self.assertListKeyEqual(g.get_user().get_repos(), lambda r: r.name, ["TestPyGithub", "django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "Hacking", "vincent-jacques.net", "Contests", "Candidates", "Tests", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])
