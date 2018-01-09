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

import datetime

from . import Framework
import github


# Replay data is forged to simulate bad things returned by Github
class BadAttributes(Framework.TestCase):
    def testBadSimpleAttribute(self):
        user = self.g.get_user("klmitch")
        self.assertEqual(user.created_at, datetime.datetime(2011, 3, 23, 15, 42, 9))

        raised = False
        try:
            user.name
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, 42)
            self.assertEqual(e.expected_type, (str, str))
            self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)

    def testBadAttributeTransformation(self):
        user = self.g.get_user("klmitch")
        self.assertEqual(user.name, "Kevin L. Mitchell")

        raised = False
        try:
            user.created_at
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, "foobar")
            self.assertEqual(e.expected_type, (str, str))
            self.assertEqual(e.transformation_exception.__class__, ValueError)
            if Framework.atLeastPython26:
                self.assertEqual(e.transformation_exception.args, ("time data 'foobar' does not match format '%Y-%m-%dT%H:%M:%SZ'",))
            else:
                self.assertEqual(e.transformation_exception.args, ('time data did not match format:  data=foobar  fmt=%Y-%m-%dT%H:%M:%SZ',))
        self.assertTrue(raised)

    def testBadTransformedAttribute(self):
        user = self.g.get_user("klmitch")
        self.assertEqual(user.name, "Kevin L. Mitchell")

        raised = False
        try:
            user.updated_at
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, 42)
            self.assertEqual(e.expected_type, (str, str))
            self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)

    def testBadSimpleAttributeInList(self):
        hook = self.g.get_hook("activecollab")
        self.assertEqual(hook.name, "activecollab")

        raised = False
        try:
            hook.events
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, ["push", 42])
            self.assertEqual(e.expected_type, [(str, str)])
            self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)

    def testBadAttributeInClassAttribute(self):
        repo = self.g.get_repo("klmitch/turnstile")
        owner = repo.owner
        self.assertEqual(owner.id, 686398)

        raised = False
        try:
            owner.avatar_url
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, 42)
        self.assertTrue(raised)

    def testBadTransformedAttributeInList(self):
        commit = self.g.get_repo("klmitch/turnstile").get_commit("38d9082a898d0822b5ccdfd78f3a536e2efa6c26")

        raised = False
        try:
            commit.files
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, [42])
            self.assertEqual(e.expected_type, [dict])
            self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)

    def testBadTransformedAttributeInDict(self):
        gist = self.g.get_gist("6437766")

        raised = False
        try:
            gist.files
        except github.BadAttributeException as e:
            raised = True
            self.assertEqual(e.actual_value, {"test.py": 42})
            self.assertEqual(e.expected_type, {(str, str): dict})
            self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)

    def testIssue195(self):
        hooks = self.g.get_hooks()
        # We can loop on all hooks as long as we don't access circleci's events attribute
        self.assertListKeyEqual(hooks, lambda h: h.name, ['activecollab', 'acunote', 'agilebench', 'agilezen', 'amazonsns', 'apiary', 'apoio', 'appharbor', 'apropos', 'asana', 'backlog', 'bamboo', 'basecamp', 'bcx', 'blimp', 'boxcar', 'buddycloud', 'bugherd', 'bugly', 'bugzilla', 'campfire', 'cia', 'circleci', 'codeclimate', 'codeportingcsharp2java', 'codeship', 'coffeedocinfo', 'conductor', 'coop', 'copperegg', 'cube', 'depending', 'deployhq', 'devaria', 'docker', 'ducksboard', 'email', 'firebase', 'fisheye', 'flowdock', 'fogbugz', 'freckle', 'friendfeed', 'gemini', 'gemnasium', 'geocommit', 'getlocalization', 'gitlive', 'grmble', 'grouptalent', 'grove', 'habitualist', 'hakiri', 'hall', 'harvest', 'hipchat', 'hostedgraphite', 'hubcap', 'hubci', 'humbug', 'icescrum', 'irc', 'irker', 'ironmq', 'ironworker', 'jabber', 'jaconda', 'jeapie', 'jenkins', 'jenkinsgit', 'jira', 'jqueryplugins', 'kanbanery', 'kickoff', 'leanto', 'lechat', 'lighthouse', 'lingohub', 'loggly', 'mantisbt', 'masterbranch', 'mqttpub', 'nma', 'nodejitsu', 'notifo', 'ontime', 'pachube', 'packagist', 'phraseapp', 'pivotaltracker', 'planbox', 'planio', 'prowl', 'puppetlinter', 'pushalot', 'pushover', 'pythonpackages', 'railsbp', 'railsbrakeman', 'rally', 'rapidpush', 'rationaljazzhub', 'rationalteamconcert', 'rdocinfo', 'readthedocs', 'redmine', 'rubyforge', 'scrumdo', 'shiningpanda', 'sifter', 'simperium', 'slatebox', 'snowyevening', 'socialcast', 'softlayermessaging', 'sourcemint', 'splendidbacon', 'sprintly', 'sqsqueue', 'stackmob', 'statusnet', 'talker', 'targetprocess', 'tddium', 'teamcity', 'tender', 'tenxer', 'testpilot', 'toggl', 'trac', 'trajectory', 'travis', 'trello', 'twilio', 'twitter', 'unfuddle', 'web', 'weblate', 'webtranslateit', 'yammer', 'youtrack', 'zendesk', 'zohoprojects'])
        for hook in hooks:
            if hook.name != "circleci":
                hook.events

        raised = False
        for hook in hooks:
            if hook.name == "circleci":
                try:
                    hook.events
                except github.BadAttributeException as e:
                    raised = True
                    self.assertEqual(e.actual_value, [["commit_comment", "create", "delete", "download", "follow", "fork", "fork_apply", "gist", "gollum", "issue_comment", "issues", "member", "public", "pull_request", "pull_request_review_comment", "push", "status", "team_add", "watch"]])
                    self.assertEqual(e.expected_type, [(str, str)])
                    self.assertEqual(e.transformation_exception, None)
        self.assertTrue(raised)
