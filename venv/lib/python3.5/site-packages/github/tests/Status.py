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
import datetime


class Status(Framework.TestCase):
    def testGetStatus(self):
        status = self.g.get_api_status()
        self.assertEqual(status.status, "good")
        self.assertEqual(status.last_updated, datetime.datetime(2013, 9, 6, 8, 29, 27))

    def testGetLastMessage(self):
        message = self.g.get_last_api_status_message()
        self.assertEqual(message.status, "good")
        self.assertEqual(message.body, "Everything operating normally.")
        self.assertEqual(message.created_on, datetime.datetime(2013, 9, 1, 15, 41, 46))

    def testGetMessages(self):
        self.assertListKeyEqual(self.g.get_api_status_messages(), lambda m: m.status, ["good", "minor", "good", "minor", "good", "minor", "good", "minor", "good", "major", "good", "minor"])
