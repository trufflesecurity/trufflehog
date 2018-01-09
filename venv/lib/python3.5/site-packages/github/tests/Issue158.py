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


class Issue158(Framework.TestCase):  # https://github.com/jacquev6/PyGithub/issues/158
    # Warning: I don't have a scret key, so the requests for this test are forged
    def testPaginationWithSecretKeyAuthentication(self):
        g = github.Github(client_id=self.client_id, client_secret=self.client_secret)
        self.assertListKeyEqual(g.get_organization("BeaverSoftware").get_repos("public"), lambda r: r.name, ["FatherBeaver", "PyGithub"])
