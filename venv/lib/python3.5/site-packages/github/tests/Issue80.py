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


class Issue80(Framework.BasicTestCase):  # https://github.com/jacquev6/PyGithub/issues/80
    def testIgnoreHttpsFromGithubEnterprise(self):
        g = github.Github(self.login, self.password, base_url="http://my.enterprise.com/some/prefix")  # http here
        org = g.get_organization("BeaverSoftware")
        self.assertEqual(org.url, "https://my.enterprise.com/some/prefix/orgs/BeaverSoftware")  # https returned
        self.assertListKeyEqual(org.get_repos(), lambda r: r.name, ["FatherBeaver", "TestPyGithub"])  # But still http in second request based on org.url

    def testIgnoreHttpsFromGithubEnterpriseWithPort(self):
        g = github.Github(self.login, self.password, base_url="http://my.enterprise.com:1234/some/prefix")  # http here
        org = g.get_organization("BeaverSoftware")
        self.assertEqual(org.url, "https://my.enterprise.com:1234/some/prefix/orgs/BeaverSoftware")  # https returned
        self.assertListKeyEqual(org.get_repos(), lambda r: r.name, ["FatherBeaver", "TestPyGithub"])  # But still http in second request based on org.url
