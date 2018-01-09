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


class GitRef(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.ref = self.g.get_user().get_repo("PyGithub").get_git_ref("heads/BranchCreatedByPyGithub")

    def testAttributes(self):
        self.assertEqual(self.ref.object.sha, "1292bf0e22c796e91cc3d6e24b544aece8c21f2a")
        self.assertEqual(self.ref.object.type, "commit")
        self.assertEqual(self.ref.object.url, "https://api.github.com/repos/jacquev6/PyGithub/git/commits/1292bf0e22c796e91cc3d6e24b544aece8c21f2a")
        self.assertEqual(self.ref.ref, "refs/heads/BranchCreatedByPyGithub")
        self.assertEqual(self.ref.url, "https://api.github.com/repos/jacquev6/PyGithub/git/refs/heads/BranchCreatedByPyGithub")

        # test __repr__() based on this attributes
        self.assertEqual(self.ref.__repr__(),
                         'GitRef(ref="refs/heads/BranchCreatedByPyGithub")')

    def testEdit(self):
        self.ref.edit("04cde900a0775b51f762735637bd30de392a2793")

    def testEditWithForce(self):
        self.ref.edit("4303c5b90e2216d927155e9609436ccb8984c495", force=True)

    def testDelete(self):
        self.ref.delete()
