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

import github
import datetime


class Gist(Framework.TestCase):
    def testAttributes(self):
        gist = self.g.get_gist("6296732")
        self.assertEqual(gist.comments, 0)
        self.assertEqual(gist.created_at, datetime.datetime(2013, 8, 21, 16, 28, 24))
        self.assertEqual(gist.description, "Github API")
        self.assertEqual(list(gist.files.keys()), ["GithubAPI.lua"])
        self.assertEqual(gist.files["GithubAPI.lua"].size, 21229)
        self.assertEqual(gist.files["GithubAPI.lua"].filename, "GithubAPI.lua")
        self.assertEqual(gist.files["GithubAPI.lua"].language, "Lua")
        self.assertEqual(gist.files["GithubAPI.lua"].content[:10], "-- GithubA")
        self.assertEqual(gist.files["GithubAPI.lua"].raw_url, "https://gist.githubusercontent.com/jacquev6/6296732/raw/88aafa25fb28e17013054a117354a37f0d78963c/GithubAPI.lua")
        self.assertEqual(gist.forks, [])
        self.assertEqual(gist.git_pull_url, "https://gist.github.com/6296732.git")
        self.assertEqual(gist.git_push_url, "https://gist.github.com/6296732.git")
        self.assertEqual(len(gist.history), 1)
        self.assertEqual(gist.history[0].change_status.additions, 793)
        self.assertEqual(gist.history[0].change_status.deletions, 0)
        self.assertEqual(gist.history[0].change_status.total, 793)
        self.assertEqual(gist.history[0].committed_at, datetime.datetime(2013, 8, 21, 16, 12, 27))
        self.assertEqual(gist.history[0].url, "https://api.github.com/gists/6296732/c464aecd7fea16684e935607eeea7ae4f8caa0e2")
        self.assertEqual(gist.history[0].user, None)
        self.assertEqual(gist.history[0].owner.login, "jacquev6")
        self.assertEqual(gist.history[0].version, "c464aecd7fea16684e935607eeea7ae4f8caa0e2")
        self.assertEqual(gist.html_url, "https://gist.github.com/6296732")
        self.assertEqual(gist.id, "6296732")
        self.assertTrue(gist.public)
        self.assertEqual(gist.updated_at, datetime.datetime(2013, 8, 21, 16, 28, 24))
        self.assertEqual(gist.url, "https://api.github.com/gists/6296732")
        self.assertEqual(gist.user, None)
        self.assertEqual(gist.owner.login, "jacquev6")
        self.assertEqual(gist.git_pull_url, "https://gist.github.com/6296732.git")
        self.assertEqual(gist.git_push_url, "https://gist.github.com/6296732.git")
        self.assertEqual(gist.html_url, "https://gist.github.com/6296732")
        self.assertEqual(gist.url, "https://api.github.com/gists/6296732")

        # test __repr__() based on this attributes
        self.assertEqual(gist.__repr__(), 'Gist(id="6296732")')

    def testEditWithoutParameters(self):
        gist = self.g.get_gist("2729810")
        gist.edit()
        self.assertEqual(gist.description, "Gist created by PyGithub")
        self.assertEqual(gist.updated_at, datetime.datetime(2012, 5, 19, 7, 0, 58))

    def testEditWithAllParameters(self):
        gist = self.g.get_gist("2729810")
        gist.edit("Description edited by PyGithub", {"barbaz.txt": github.InputFileContent("File also created by PyGithub")})
        self.assertEqual(gist.description, "Description edited by PyGithub")
        self.assertEqual(gist.updated_at, datetime.datetime(2012, 5, 19, 7, 6, 10))
        self.assertEqual(set(gist.files.keys()), set(["foobar.txt", "barbaz.txt"]))

    def testDeleteFile(self):
        gist = self.g.get_gist("5339374")
        self.assertEqual(sorted(gist.files.keys()), ["bar.txt", "foo.txt"])
        gist.edit(files={"foo.txt": None})
        self.assertEqual(list(gist.files.keys()), ["bar.txt"])

    def testRenameFile(self):
        gist = self.g.get_gist("5339374")
        self.assertEqual(list(gist.files.keys()), ["bar.txt"])
        gist.edit(files={"bar.txt": github.InputFileContent(gist.files["bar.txt"].content, new_name="baz.txt")})
        self.assertEqual(list(gist.files.keys()), ["baz.txt"])

    def testCreateComment(self):
        gist = self.g.get_gist("2729810")
        comment = gist.create_comment("Comment created by PyGithub")
        self.assertEqual(comment.id, 323629)

    def testGetComments(self):
        gist = self.g.get_gist("2729810")
        self.assertListKeyEqual(gist.get_comments(), lambda c: c.id, [323637])

    def testStarring(self):
        gist = self.g.get_gist("2729810")
        self.assertFalse(gist.is_starred())
        gist.set_starred()
        self.assertTrue(gist.is_starred())
        gist.reset_starred()
        self.assertFalse(gist.is_starred())

    def testFork(self):
        gist = self.g.get_gist("6296553")  # Random gist
        myGist = gist.create_fork()
        self.assertEqual(myGist.id, "6296732")
        self.assertEqual(myGist.fork_of, None)  # WTF
        sameGist = self.g.get_gist("6296732")
        self.assertEqual(sameGist.fork_of.id, "6296553")

    def testDelete(self):
        gist = self.g.get_gist("2729810")
        gist.delete()
