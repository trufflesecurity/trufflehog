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


class Tag(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.tag = self.g.get_user().get_repo("PyGithub").get_tags()[0]

    def testAttributes(self):
        self.assertEqual(self.tag.commit.sha, "636e6112deb72277b3bffcc3303cd7e8a7431a5d")
        self.assertEqual(self.tag.name, "v0.3")
        self.assertEqual(self.tag.tarball_url, "https://github.com/jacquev6/PyGithub/tarball/v0.3")
        self.assertEqual(self.tag.zipball_url, "https://github.com/jacquev6/PyGithub/zipball/v0.3")

        # test __repr__() based on this attributes
        self.assertEqual(self.tag.__repr__(), 'Tag(name="v0.3", commit=Commit(sha="636e6112deb72277b3bffcc3303cd7e8a7431a5d"))')
