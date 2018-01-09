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

class PullRequestReviewerRequests(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_repo("PyGithub/PyGithub")
        self.pull = self.repo.get_pull(538)
        
        self.pullreviewerrequests = self.pull.get_reviewer_requests()
        self.pullreviewerrequest = self.pullreviewerrequests[0]


    def testAttributes(self):

        self.assertEqual(self.pullreviewerrequest.id, 2930472)
        self.assertEqual(self.pullreviewerrequest.login, "jayfk")
 
        # test __repr__() based on this attributes
        self.assertEqual(self.pullreviewerrequest.__repr__(), 'PullRequestReviewerRequest(login="jayfk", id=2930472)')

