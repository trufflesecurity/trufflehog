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


class IssueComment(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.comment = self.g.get_user().get_repo("PyGithub").get_issue(28).get_comment(5808311)

    def testAttributes(self):
        self.assertEqual(self.comment.body, "Comment created by PyGithub")
        self.assertEqual(self.comment.created_at, datetime.datetime(2012, 5, 20, 11, 46, 42))
        self.assertEqual(self.comment.id, 5808311)
        self.assertEqual(self.comment.updated_at, datetime.datetime(2012, 5, 20, 11, 46, 42))
        self.assertEqual(self.comment.url, "https://api.github.com/repos/jacquev6/PyGithub/issues/comments/5808311")
        self.assertEqual(self.comment.user.login, "jacquev6")
        self.assertEqual(self.comment.html_url, "https://github.com/jacquev6/PyGithub/issues/28#issuecomment-5808311")

        # test __repr__() based on this attributes
        self.assertEqual(self.comment.__repr__(), 'IssueComment(user=NamedUser(login="jacquev6"), id=5808311)')

    def testEdit(self):
        self.comment.edit("Comment edited by PyGithub")
        self.assertEqual(self.comment.body, "Comment edited by PyGithub")
        self.assertEqual(self.comment.updated_at, datetime.datetime(2012, 5, 20, 11, 53, 59))

    def testDelete(self):
        self.comment.delete()
