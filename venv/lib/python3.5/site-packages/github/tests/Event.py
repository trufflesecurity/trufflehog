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


class Event(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.event = self.g.get_user("jacquev6").get_events()[0]

    def testAttributes(self):
        self.assertEqual(self.event.actor.login, "jacquev6")
        self.assertEqual(self.event.created_at, datetime.datetime(2012, 5, 26, 10, 1, 39))
        self.assertEqual(self.event.id, "1556114751")
        self.assertEqual(self.event.org, None)
        self.assertEqual(self.event.payload, {'commits': [{'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/5bb654d26dd014d36794acd1e6ecf3736f12aad7', 'sha': '5bb654d26dd014d36794acd1e6ecf3736f12aad7', 'message': 'Implement the three authentication schemes', 'distinct': False, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/cb0313157bf904f2d364377d35d9397b269547a5', 'sha': 'cb0313157bf904f2d364377d35d9397b269547a5', 'message': "Merge branch 'topic/Authentication' into develop", 'distinct': False, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/0cec0d25e606c023a62a4fc7cdc815309ebf6d16', 'sha': '0cec0d25e606c023a62a4fc7cdc815309ebf6d16', 'message': 'Publish version 0.7', 'distinct': False, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/ecda065e01876209d2bdf5fe4e91cee8ffaa9ff7', 'sha': 'ecda065e01876209d2bdf5fe4e91cee8ffaa9ff7', 'message': "Merge branch 'develop'", 'distinct': False, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/3a3bf4763192ee1234eb0557628133e06f3dfc76', 'sha': '3a3bf4763192ee1234eb0557628133e06f3dfc76', 'message': "Merge branch 'master' into topic/RewriteWithGeneratedCode\n\nConflicts:\n\tgithub/Github.py\n\tgithub/Requester.py", 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/608f17794664f61693a3dc05e6056fea8fbef0ff', 'sha': '608f17794664f61693a3dc05e6056fea8fbef0ff', 'message': 'Restore some form of Authorization header in replay data', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/2c04b8adbd91d38eef4f0767337ab7a12b2f684b', 'sha': '2c04b8adbd91d38eef4f0767337ab7a12b2f684b', 'message': 'Allow test without pre-set-up Github', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/5b97389988b6fe43e15a079702f6f1671257fb28', 'sha': '5b97389988b6fe43e15a079702f6f1671257fb28', 'message': 'Test three authentication schemes', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/12747613c5ec00deccf296b8619ad507f7050475', 'sha': '12747613c5ec00deccf296b8619ad507f7050475', 'message': 'Test Issue.getComments', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/2982fa96c5ca75abe717d974d83f9135d664232e', 'sha': '2982fa96c5ca75abe717d974d83f9135d664232e', 'message': 'Test the new Repository.full_name attribute', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}, {'url': 'https://api.github.com/repos/jacquev6/PyGithub/commits/619eae8d51c5988f0d2889fc767fa677438ba95d', 'sha': '619eae8d51c5988f0d2889fc767fa677438ba95d', 'message': 'Improve coverage of AuthenticatedUser', 'distinct': True, 'author': {'name': 'Vincent Jacques', 'email': 'vincent@vincent-jacques.net'}}], 'head': '619eae8d51c5988f0d2889fc767fa677438ba95d', 'push_id': 80673538, 'ref': 'refs/heads/topic/RewriteWithGeneratedCode', 'size': 11})
        self.assertTrue(self.event.public)
        self.assertEqual(self.event.repo.name, "jacquev6/PyGithub")
        self.assertEqual(self.event.type, "PushEvent")

        # test __repr__() based on this attributes
        self.assertEqual(self.event.__repr__(), 'Event(type="PushEvent", id="1556114751")')
