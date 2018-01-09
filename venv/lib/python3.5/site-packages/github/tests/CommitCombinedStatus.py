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


class CommitCombinedStatus(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.combined_status = self.g.get_repo("edx/edx-platform").get_commit("74e70119a23fa3ffb3db19d4590eccfebd72b659").get_combined_status()

    def testAttributes(self):
        self.assertEqual(self.combined_status.state, "success")
        self.assertEqual(self.combined_status.statuses[0].url, "https://api.github.com/repos/edx/edx-platform/statuses/74e70119a23fa3ffb3db19d4590eccfebd72b659")
        self.assertEqual(self.combined_status.statuses[1].id, 390603044)
        self.assertEqual(self.combined_status.statuses[2].state, "success")
        self.assertEqual(self.combined_status.statuses[3].description, "Build finished.")
        self.assertEqual(self.combined_status.statuses[4].target_url, "https://build.testeng.edx.org/job/edx-platform-python-unittests-pr/10504/")
        self.assertEqual(self.combined_status.statuses[4].created_at, datetime.datetime(2015, 12, 14, 13, 24, 18))
        self.assertEqual(self.combined_status.statuses[3].updated_at, datetime.datetime(2015, 12, 14, 13, 23, 35))
        self.assertEqual(self.combined_status.sha, "74e70119a23fa3ffb3db19d4590eccfebd72b659")
        self.assertEqual(self.combined_status.total_count, 6)
        self.assertEqual(self.combined_status.repository.id, 10391073)
        self.assertEqual(self.combined_status.repository.full_name, "edx/edx-platform")
        self.assertEqual(self.combined_status.commit_url, "https://api.github.com/repos/edx/edx-platform/commits/74e70119a23fa3ffb3db19d4590eccfebd72b659")
        self.assertEqual(self.combined_status.url, "https://api.github.com/repos/edx/edx-platform/commits/74e70119a23fa3ffb3db19d4590eccfebd72b659/status")

        # test __repr__() based on this attributes
        self.assertEqual(self.combined_status.__repr__(),
                         'CommitCombinedStatus(state="success", sha="74e70119a23fa3ffb3db19d4590eccfebd72b659")')