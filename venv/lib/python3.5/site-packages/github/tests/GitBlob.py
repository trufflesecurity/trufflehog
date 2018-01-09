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


class GitBlob(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.blob = self.g.get_user().get_repo("PyGithub").get_git_blob("53bce9fa919b4544e67275089b3ec5b44be20667")

    def testAttributes(self):
        self.assertTrue(self.blob.content.startswith("IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCgpmcm9tIGRpc3R1dGlscy5jb3JlIGlt\ncG9ydCBzZXR1cAppbXBvcnQgdGV4dHdyYXAKCnNldHVwKAogICAgbmFtZSA9\n"))
        self.assertTrue(self.blob.content.endswith("Z3JhbW1pbmcgTGFuZ3VhZ2UgOjogUHl0aG9uIiwKICAgICAgICAiVG9waWMg\nOjogU29mdHdhcmUgRGV2ZWxvcG1lbnQiLAogICAgXSwKKQo=\n"))
        self.assertEqual(len(self.blob.content), 1757)
        self.assertEqual(self.blob.encoding, "base64")
        self.assertEqual(self.blob.size, 1295)
        self.assertEqual(self.blob.sha, "53bce9fa919b4544e67275089b3ec5b44be20667")
        self.assertEqual(self.blob.url, "https://api.github.com/repos/jacquev6/PyGithub/git/blobs/53bce9fa919b4544e67275089b3ec5b44be20667")

        # test __repr__() based on this attributes
        self.assertEqual(self.blob.__repr__(),
                         'GitBlob(sha="53bce9fa919b4544e67275089b3ec5b44be20667")')