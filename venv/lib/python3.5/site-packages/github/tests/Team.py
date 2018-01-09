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


class Team(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.org = self.g.get_organization("BeaverSoftware")
        self.team = self.org.get_team(189850)

    def testAttributes(self):
        self.assertEqual(self.team.id, 189850)
        self.assertEqual(self.team.members_count, 0)
        self.assertEqual(self.team.name, "Team created by PyGithub")
        self.assertEqual(self.team.permission, "pull")
        self.assertEqual(self.team.repos_count, 0)
        self.assertEqual(self.team.url, "https://api.github.com/teams/189850")

        # test __repr__() based on this attributes
        self.assertEqual(self.team.__repr__(), 'Team(name="Team created by PyGithub", id=189850)')

    def testMembers(self):
        user = self.g.get_user("jacquev6")
        self.assertListKeyEqual(self.team.get_members(), None, [])
        self.assertFalse(self.team.has_in_members(user))
        self.team.add_to_members(user)
        self.assertListKeyEqual(self.team.get_members(), lambda u: u.login, ["jacquev6"])
        self.assertTrue(self.team.has_in_members(user))
        self.team.remove_from_members(user)
        self.assertListKeyEqual(self.team.get_members(), None, [])
        self.assertFalse(self.team.has_in_members(user))

    def testRepoPermission(self):
        repo = self.org.get_repo("FatherBeaver")
        self.team.set_repo_permission(repo, "admin")

    def testRepos(self):
        repo = self.org.get_repo("FatherBeaver")
        self.assertListKeyEqual(self.team.get_repos(), None, [])
        self.assertFalse(self.team.has_in_repos(repo))
        self.team.add_to_repos(repo)
        self.assertListKeyEqual(self.team.get_repos(), lambda r: r.name, ["FatherBeaver"])
        self.assertTrue(self.team.has_in_repos(repo))
        self.team.remove_from_repos(repo)
        self.assertListKeyEqual(self.team.get_repos(), None, [])
        self.assertFalse(self.team.has_in_repos(repo))

    def testEditWithoutArguments(self):
        self.team.edit("Name edited by PyGithub")
        self.assertEqual(self.team.name, "Name edited by PyGithub")

    def testEditWithAllArguments(self):
        self.team.edit("Name edited twice by PyGithub", "admin")
        self.assertEqual(self.team.name, "Name edited twice by PyGithub")
        self.assertEqual(self.team.permission, "admin")

    def testDelete(self):
        self.team.delete()
