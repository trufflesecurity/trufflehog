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


class Label(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.label = self.g.get_user().get_repo("PyGithub").get_label("Bug")

    def testAttributes(self):
        self.assertEqual(self.label.color, "e10c02")
        self.assertEqual(self.label.name, "Bug")
        self.assertEqual(self.label.url, "https://api.github.com/repos/jacquev6/PyGithub/labels/Bug")

        # test __repr__() based on this attributes
        self.assertEqual(self.label.__repr__(), 'Label(name="Bug")')

    def testEdit(self):
        self.label.edit("LabelEditedByPyGithub", "0000ff")
        self.assertEqual(self.label.color, "0000ff")
        self.assertEqual(self.label.name, "LabelEditedByPyGithub")
        self.assertEqual(self.label.url, "https://api.github.com/repos/jacquev6/PyGithub/labels/LabelEditedByPyGithub")

    def testDelete(self):
        self.label.delete()
