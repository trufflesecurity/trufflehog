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

import datetime


class Milestone(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.milestone = self.g.get_user().get_repo("PyGithub").get_milestone(1)

    def testAttributes(self):
        self.assertEqual(self.milestone.closed_issues, 2)
        self.assertEqual(self.milestone.created_at, datetime.datetime(2012, 3, 8, 12, 22, 10))
        self.assertEqual(self.milestone.description, "")
        self.assertEqual(self.milestone.due_on, datetime.datetime(2012, 3, 13, 7, 0, 0))
        self.assertEqual(self.milestone.id, 93546)
        self.assertEqual(self.milestone.number, 1)
        self.assertEqual(self.milestone.open_issues, 0)
        self.assertEqual(self.milestone.state, "closed")
        self.assertEqual(self.milestone.title, "Version 0.4")
        self.assertEqual(self.milestone.url, "https://api.github.com/repos/jacquev6/PyGithub/milestones/1")
        self.assertEqual(self.milestone.creator.login, "jacquev6")

        # test __repr__() based on this attributes
        self.assertEqual(self.milestone.__repr__(), 'Milestone(number=1)')

    def testEditWithMinimalParameters(self):
        self.milestone.edit("Title edited by PyGithub")
        self.assertEqual(self.milestone.title, "Title edited by PyGithub")

    def testEditWithAllParameters(self):
        self.milestone.edit("Title edited twice by PyGithub", "closed", "Description edited by PyGithub", due_on=datetime.date(2012, 6, 16))
        self.assertEqual(self.milestone.title, "Title edited twice by PyGithub")
        self.assertEqual(self.milestone.state, "closed")
        self.assertEqual(self.milestone.description, "Description edited by PyGithub")
        self.assertEqual(self.milestone.due_on, datetime.datetime(2012, 6, 16, 7, 0, 0))

    def testGetLabels(self):
        self.assertListKeyEqual(self.milestone.get_labels(), lambda l: l.name, ["Public interface", "Project management"])

    def testDelete(self):
        self.milestone.delete()
