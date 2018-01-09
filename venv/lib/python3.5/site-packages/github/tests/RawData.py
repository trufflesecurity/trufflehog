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

import github.NamedUser


class RawData(Framework.TestCase):
    jacquev6RawData = {
        'disk_usage': 13812,
        'private_gists': 5,
        'public_repos': 21,
        'subscriptions_url': 'https://api.github.com/users/jacquev6/subscriptions',
        'gravatar_id': 'b68de5ae38616c296fa345d2b9df2225',
        'hireable': False,
        'id': 327146,
        'followers_url': 'https://api.github.com/users/jacquev6/followers',
        'following_url': 'https://api.github.com/users/jacquev6/following',
        'collaborators': 1,
        'total_private_repos': 4,
        'blog': 'http://vincent-jacques.net',
        'followers': 22,
        'location': 'Paris, France',
        'type': 'User',
        'email': 'vincent@vincent-jacques.net',
        'bio': '',
        'gists_url': 'https://api.github.com/users/jacquev6/gists{/gist_id}',
        'owned_private_repos': 4,
        'company': 'Criteo',
        'events_url': 'https://api.github.com/users/jacquev6/events{/privacy}',
        'html_url': 'https://github.com/jacquev6',
        'updated_at': '2013-03-12T22:13:32Z',
        'plan': {
            'collaborators': 1,
            'name': 'micro',
            'private_repos': 5,
            'space': 614400,
        },
        'received_events_url': 'https://api.github.com/users/jacquev6/received_events',
        'starred_url': 'https://api.github.com/users/jacquev6/starred{/owner}{/repo}',
        'public_gists': 2,
        'name': 'Vincent Jacques',
        'organizations_url': 'https://api.github.com/users/jacquev6/orgs',
        'url': 'https://api.github.com/users/jacquev6',
        'created_at': '2010-07-09T06:10:06Z',
        'avatar_url': 'https://secure.gravatar.com/avatar/b68de5ae38616c296fa345d2b9df2225?d=https://a248.e.akamai.net/assets.github.com%2Fimages%2Fgravatars%2Fgravatar-user-420.png',
        'repos_url': 'https://api.github.com/users/jacquev6/repos',
        'following': 38,
        'login': 'jacquev6',
    }

    planRawData = {
        'collaborators': 1,
        'name': 'micro',
        'private_repos': 5,
        'space': 614400,
    }

    def testCompletedObject(self):
        user = self.g.get_user("jacquev6")
        self.assertTrue(user._CompletableGithubObject__completed)
        self.assertEqual(user.raw_data, RawData.jacquev6RawData)

    def testNotYetCompletedObject(self):
        user = self.g.get_user().get_repo("PyGithub").owner
        self.assertFalse(user._CompletableGithubObject__completed)
        self.assertEqual(user.raw_data, RawData.jacquev6RawData)
        self.assertTrue(user._CompletableGithubObject__completed)

    def testNonCompletableObject(self):
        plan = self.g.get_user().plan
        self.assertEqual(plan.raw_data, RawData.planRawData)

    def testCreateObjectFromRawData(self):
        user = self.g.create_from_raw_data(github.NamedUser.NamedUser, RawData.jacquev6RawData)
        self.assertEqual(user._CompletableGithubObject__completed, True)
        self.assertEqual(user.name, "Vincent Jacques")
