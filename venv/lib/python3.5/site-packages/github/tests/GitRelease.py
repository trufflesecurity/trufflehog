# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2015 Ed Holland <eholland@alertlogic.com>                          #
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
from pprint import pprint


class Release(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        # Do not get self.release here as it casues bad data to be saved in --record mode

    def testAttributes(self):
        self.release = self.g.get_user().get_repo("PyGithub").get_releases()[0]
        self.assertEqual(self.release.tag_name, "v1.25.2")
        self.assertEqual(self.release.upload_url, "https://uploads.github.com/repos/edhollandAL/PyGithub/releases/1210814/assets{?name}")
        self.assertEqual(self.release.body, "Body")
        self.assertEqual(self.release.title, "Test")
        self.assertEqual(self.release.url, "https://api.github.com/repos/edhollandAL/PyGithub/releases/1210814")
        self.assertEqual(self.release.author._rawData['login'], "edhollandAL")
        self.assertEqual(self.release.html_url, "https://github.com/edhollandAL/PyGithub/releases/tag/v1.25.2")

        # test __repr__() based on this attributes
        self.assertEqual(self.release.__repr__(), 'GitRelease(title="Test")')


    def testDelete(self):
        self.release = self.g.get_user().get_repo("PyGithub").get_releases()[0]
        self.assertTrue(self.release.delete_release())

    def testUpdate(self):
        self.release = self.g.get_user().get_repo("PyGithub").get_releases()[0]
        new_release = self.release.update_release("Updated Test", "Updated Body")
        self.assertEqual(new_release.body, "Updated Body")
        self.assertEqual(new_release.title, "Updated Test")

    def testGetRelease(self):
        release_by_id = self.g.get_user().get_repo("PyGithub").get_release('v1.25.2')
        release_by_tag = self.g.get_user().get_repo("PyGithub").get_release(1210837)
        self.assertEqual(release_by_id, release_by_tag)

    def testCreateGitTagAndRelease(self):
        self.repo = self.g.get_user().get_repo("PyGithub")
        self.release = self.repo.create_git_tag_and_release('v3.0.0', 'tag message', 'release title', 'release message', '5a05a5e58f682d315acd2447c87ac5b4d4fc55e8', 'commit')
        self.assertEqual(self.release.tag_name, "v3.0.0")
        self.assertEqual(self.release.body, "release message")
        self.assertEqual(self.release.title, "release title")
        self.assertEqual(self.release.author._rawData['login'], "edhollandAL")
        self.assertEqual(self.release.html_url, "https://github.com/edhollandAL/PyGithub/releases/tag/v3.0.0")
