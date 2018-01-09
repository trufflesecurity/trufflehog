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


class IssueEvent(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.event = self.g.get_user().get_repo("PyGithub").get_issues_event(16348656)

    def testAttributes(self):
        self.assertEqual(self.event.actor.login, "jacquev6")
        self.assertEqual(self.event.commit_id, "ed866fc43833802ab553e5ff8581c81bb00dd433")
        self.assertEqual(self.event.created_at, datetime.datetime(2012, 5, 27, 7, 29, 25))
        self.assertEqual(self.event.event, "referenced")
        self.assertEqual(self.event.id, 16348656)
        self.assertEqual(self.event.issue.number, 30)
        self.assertEqual(self.event.url, "https://api.github.com/repos/jacquev6/PyGithub/issues/events/16348656")

        # test __repr__() based on this attributes
        self.assertEqual(self.event.__repr__(), 'IssueEvent(id=16348656)')