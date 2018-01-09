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


class NamedUser(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.user = self.g.get_user("jacquev6")

    def testAttributesOfOtherUser(self):
        self.user = self.g.get_user("nvie")
        self.assertEqual(self.user.avatar_url, "https://secure.gravatar.com/avatar/c5a7f21b46df698f3db31c37ed0cf55a?d=https://a248.e.akamai.net/assets.github.com%2Fimages%2Fgravatars%2Fgravatar-140.png")
        self.assertEqual(self.user.bio, None)
        self.assertEqual(self.user.blog, "http://nvie.com")
        self.assertEqual(self.user.collaborators, None)
        self.assertEqual(self.user.company, "3rd Cloud")
        self.assertEqual(self.user.created_at, datetime.datetime(2009, 5, 12, 21, 19, 38))
        self.assertEqual(self.user.disk_usage, None)
        self.assertEqual(self.user.email, "vincent@3rdcloud.com")
        self.assertEqual(self.user.followers, 296)
        self.assertEqual(self.user.following, 41)
        self.assertEqual(self.user.gravatar_id, "c5a7f21b46df698f3db31c37ed0cf55a")
        self.assertFalse(self.user.hireable)
        self.assertEqual(self.user.html_url, "https://github.com/nvie")
        self.assertEqual(self.user.id, 83844)
        self.assertEqual(self.user.location, "Netherlands")
        self.assertEqual(self.user.login, "nvie")
        self.assertEqual(self.user.name, "Vincent Driessen")
        self.assertEqual(self.user.owned_private_repos, None)
        self.assertEqual(self.user.plan, None)
        self.assertEqual(self.user.private_gists, None)
        self.assertEqual(self.user.public_gists, 16)
        self.assertEqual(self.user.public_repos, 61)
        self.assertEqual(self.user.total_private_repos, None)
        self.assertEqual(self.user.type, "User")
        self.assertEqual(self.user.url, "https://api.github.com/users/nvie")

        # test __repr__() based on this attributes
        self.assertEqual(self.user.__repr__(), 'NamedUser(login="nvie")')


    def testAttributesOfSelf(self):
        self.assertEqual(self.user.avatar_url, "https://secure.gravatar.com/avatar/b68de5ae38616c296fa345d2b9df2225?d=https://a248.e.akamai.net/assets.github.com%2Fimages%2Fgravatars%2Fgravatar-140.png")
        self.assertEqual(self.user.bio, "")
        self.assertEqual(self.user.blog, "http://vincent-jacques.net")
        self.assertEqual(self.user.collaborators, 0)
        self.assertEqual(self.user.company, "Criteo")
        self.assertEqual(self.user.created_at, datetime.datetime(2010, 7, 9, 6, 10, 6))
        self.assertEqual(self.user.disk_usage, 17080)
        self.assertEqual(self.user.email, "vincent@vincent-jacques.net")
        self.assertEqual(self.user.followers, 13)
        self.assertEqual(self.user.following, 24)
        self.assertEqual(self.user.gravatar_id, "b68de5ae38616c296fa345d2b9df2225")
        self.assertFalse(self.user.hireable)
        self.assertEqual(self.user.html_url, "https://github.com/jacquev6")
        self.assertEqual(self.user.id, 327146)
        self.assertEqual(self.user.location, "Paris, France")
        self.assertEqual(self.user.login, "jacquev6")
        self.assertEqual(self.user.name, "Vincent Jacques")
        self.assertEqual(self.user.owned_private_repos, 5)
        self.assertEqual(self.user.plan.name, "micro")
        self.assertEqual(self.user.plan.collaborators, 1)
        self.assertEqual(self.user.plan.space, 614400)
        self.assertEqual(self.user.plan.private_repos, 5)
        self.assertEqual(self.user.private_gists, 5)
        self.assertEqual(self.user.public_gists, 2)
        self.assertEqual(self.user.public_repos, 11)
        self.assertEqual(self.user.total_private_repos, 5)
        self.assertEqual(self.user.type, "User")
        self.assertEqual(self.user.url, "https://api.github.com/users/jacquev6")

        # test __repr__() based on this attributes
        self.assertEqual(self.user.__repr__(), 'NamedUser(login="jacquev6")')

    def testGetGists(self):
        self.assertListKeyEqual(self.user.get_gists(), lambda g: g.description, ["Gist created by PyGithub", "FairThreadPoolPool.cpp", "How to error 500 Github API v3, as requested by Rick (GitHub Staff)", "Cadfael: order of episodes in French DVD edition"])

    def testGetFollowers(self):
        self.assertListKeyEqual(self.user.get_followers(), lambda f: f.login, ["jnorthrup", "brugidou", "regisb", "walidk", "afzalkhan", "sdanzan", "vineus", "gturri", "fjardon", "cjuniet", "jardon-u", "kamaradclimber", "L42y"])

    def testGetFollowing(self):
        self.assertListKeyEqual(self.user.get_following(), lambda f: f.login, ["nvie", "schacon", "jamis", "chad", "unclebob", "dabrahams", "jnorthrup", "brugidou", "regisb", "walidk", "tanzilli", "fjardon", "r3c", "sdanzan", "vineus", "cjuniet", "gturri", "ant9000", "asquini", "claudyus", "jardon-u", "s-bernard", "kamaradclimber", "Lyloa"])

    def testHasInFollowing(self):
        nvie = self.g.get_user("nvie")
        self.assertTrue(self.user.has_in_following(nvie))

    def testGetOrgs(self):
        self.assertListKeyEqual(self.user.get_orgs(), lambda o: o.login, ["BeaverSoftware"])

    def testGetRepo(self):
        self.assertEqual(self.user.get_repo("PyGithub").description, "Python library implementing the full Github API v3")

    def testGetRepos(self):
        self.assertListKeyEqual(self.user.get_repos(), lambda r: r.name, ["TestPyGithub", "django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])

    def testGetReposWithType(self):
        self.assertListKeyEqual(self.user.get_repos("owner"), lambda r: r.name, ["django", "PyGithub", "developer.github.com", "acme-public-website", "C4Planner", "DrawTurksHead", "DrawSyntax", "QuadProgMm", "Boost.HierarchicalEnum", "ViDE"])

    def testGetWatched(self):
        self.assertListKeyEqual(self.user.get_watched(), lambda r: r.name, ["git", "boost.php", "capistrano", "boost.perl", "git-subtree", "git-hg", "homebrew", "celtic_knot", "twisted-intro", "markup", "hub", "gitflow", "murder", "boto", "agit", "d3", "pygit2", "git-pulls", "django_mathlatex", "scrumblr", "developer.github.com", "python-github3", "PlantUML", "bootstrap", "drawnby", "django-socketio", "django-realtime", "playground", "BozoCrack", "FatherBeaver", "PyGithub", "django", "django", "TestPyGithub"])

    def testGetStarred(self):
        self.assertListKeyEqual(self.user.get_starred(), lambda r: r.name, ["git", "boost.php", "capistrano", "boost.perl", "git-subtree", "git-hg", "homebrew", "celtic_knot", "twisted-intro", "markup", "hub", "gitflow", "murder", "boto", "agit", "d3", "pygit2", "git-pulls", "django_mathlatex", "scrumblr", "developer.github.com", "python-github3", "PlantUML", "bootstrap", "drawnby", "django-socketio", "django-realtime", "playground", "BozoCrack", "FatherBeaver", "amaunet", "django", "django", "moviePlanning", "folly"])

    def testGetSubscriptions(self):
        self.assertListKeyEqual(self.user.get_subscriptions(), lambda r: r.name, ["ViDE", "Boost.HierarchicalEnum", "QuadProgMm", "DrawSyntax", "DrawTurksHead", "PrivateStuff", "vincent-jacques.net", "Hacking", "C4Planner", "developer.github.com", "PyGithub", "PyGithub", "django", "CinePlanning", "PyGithub", "PyGithub", "PyGithub", "IpMap", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub", "PyGithub"])

    def testGetEvents(self):
        self.assertListKeyBegin(self.user.get_events(), lambda e: e.type, ["GistEvent", "IssueCommentEvent", "PushEvent", "IssuesEvent"])

    def testGetPublicEvents(self):
        self.assertListKeyBegin(self.user.get_public_events(), lambda e: e.type, ["PushEvent", "CreateEvent", "GistEvent", "IssuesEvent"])

    def testGetPublicReceivedEvents(self):
        self.assertListKeyBegin(self.user.get_public_received_events(), lambda e: e.type, ["IssueCommentEvent", "IssueCommentEvent", "IssueCommentEvent", "IssueCommentEvent"])

    def testGetReceivedEvents(self):
        self.assertListKeyBegin(self.user.get_received_events(), lambda e: e.type, ["IssueCommentEvent", "IssueCommentEvent", "IssueCommentEvent", "IssueCommentEvent"])

    def testGetKeys(self):
        self.assertListKeyEqual(self.user.get_keys(), lambda k: k.id, [3557894, 3791954, 3937333, 4051357, 4051492])
