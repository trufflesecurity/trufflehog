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

from . import Framework


class Branch(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.branch = self.g.get_user().get_repo("PyGithub").get_branches()[0]

    def testAttributes(self):
        self.assertEqual(self.branch.name, "topic/RewriteWithGeneratedCode")
        self.assertEqual(self.branch.commit.sha, "1292bf0e22c796e91cc3d6e24b544aece8c21f2a")

        # test __repr__() based on this attributes
        self.assertEqual(self.branch.__repr__(), 'Branch(name="topic/RewriteWithGeneratedCode")')

    def testProtectedAttributes(self):
        self.branch = self.g.get_user().get_repo("PyGithub").get_protected_branch("master")
        self.assertEqual(self.branch.name, "master")
        self.assertFalse(self.branch.protected)
        self.assertEqual(self.branch.enforcement_level, "off")
        self.assertEqual(self.branch.contexts, [])
