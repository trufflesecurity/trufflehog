import copy
import json
import random
import string
import unittest
import os
from pprint import pprint
from unittest import skip, TestCase
from urlparse import urlparse

import github
from github import UnknownObjectException, Github, BadCredentialsException

from truffleHog import truffleHog
import os

from truffleHog.searchOrg import gather_repos, analyze_org_repos, analyze, analyze, Helper, build_repo_auth_clone_url, \
    Options


class TestSearchOrg(TestCase):

    @skip('')
    def test_gather_repos(self):
        options = Options(orgname=os.environ['GM_ORGNAME'], private_token=os.environ['GM_PRIV_TOKEN'],
                          repo=os.environ['GM_REPO_NAME'])
        repos_number = os.environ['GM_REPO_NUMBER']

        failed_opts = copy.deepcopy(options)
        # negative test, no org
        try:
            failed_opts.orgname = ''
            no_org = gather_repos(failed_opts)
            self.fail("Exception not thrown if called without an organization")
        except UnknownObjectException as e:
            self.assertIn(404, e)

        # negative test, no private token
        try:
            failed_opts = copy.deepcopy(options)

            failed_opts.private_token = ''
            no_token = gather_repos(failed_opts)
            self.fail("Exception not thrown if called without a private token")
        except BadCredentialsException as e:
            self.assertIn(401, e)

        # negative test invalid repo
        try:
            failed_opts = copy.deepcopy(options)

            failed_opts.repo = ''.join(random.choice(string.lowercase) for i in range(10))
            inv_repo = gather_repos(failed_opts)
            self.fail("Exception not thrown if called with an invalid repository")
        except UnknownObjectException as e:
            self.assertIn(404, e)

        # positive test, check that all repos are returned and every repo is of the correct type
        no_repo = copy.deepcopy(options)
        no_repo.repo = None
        all_repos = gather_repos(no_repo)
        self.assertEqual(int(len(all_repos)), int(repos_number))
        for repo in all_repos:
            self.assertNotEquals(repo.url, None)
            self.assertNotEquals(repo.repo_url, None)

        # positive test, check that only one repo is returned and its of the correct  type
        single_repo = gather_repos(options)
        self.assertEqual(int(len(single_repo)), 1)
        for repo in single_repo:
            self.assertNotEquals(repo.url, None)
            self.assertNotEquals(repo.repo_url, None)

    def test_analyze_org_repos(self):
        entropy = False
        regex = True
        print_str = 1
        delay = 0
        options = Options(orgname=os.environ['GM_ORGNAME'], private_token=os.environ['GM_PRIV_TOKEN'],
                          repo=os.environ['GM_REPO_NAME'], entropy=entropy, regex=regex, print_str=print_str,
                          delay=delay,branch='master')

        try:
            # options.repo=None
            analyze_org_repos(33, options=options)
        except Exception as e:
            self.fail()

    @skip("")
    def test_helper(self):
        dictionary_keys = ['commitHash',
                           'reason',
                           'commit',
                           'printDiff',
                           'stringsFound',
                           'branch',
                           'diff',
                           'date',
                           'path']

        repo_url = urlparse('https://github.com/northdpole/gitSecretsMonitoringTestRepo')

        url = 'https://github.com/northdpole/gitSecretsMonitoringTestRepo'
        entropy = False
        regex = True
        print_str = 1
        delay = 0
        options = Options(orgname=os.environ['GM_ORGNAME'], private_token=os.environ['GM_PRIV_TOKEN'],
                          repo=os.environ['GM_REPO_NAME'], entropy=entropy, regex=regex, print_str=print_str,
                          delay=delay)
        urls = Helper(url=url, repo_url=repo_url, options=options)

        res_url, issues = analyze(urls)
        # structure assertions
        self.assertEqual(len(issues), 3)

        for dictionary in issues['entropicDiffs']:
            self.assertListEqual(dictionary_keys, dictionary.keys())

        for dictionary in issues['found_regexes']:
            self.assertListEqual(dictionary_keys, dictionary.keys())

        if entropy is not False and regex is not False:
            self.assertNotIn('[]', json.dumps(issues))
            self.assertNotIn('None', json.dumps(issues))

        # org assertions, This is very slow depending on the repo and the ammount of branches
        options.do_entropy = True
        options.repo = None
        repo = gather_repos(options)

        for r in repo:
            res_url, issues = analyze(r)
            # if regex is True:
            #     self.assertTrue(len(issues['found_regexes']) > 0)
            # if options.do_entropy is True:
            #     self.assertTrue(len(issues['entropicDiffs']) > 0)
            #     if options.do_regex is True:
            #         self.assertNotIn('[]', json.dumps(issues))
            #         self.assertNotIn('None', json.dumps(issues))
            pprint(issues)


if __name__ == '__main__':
    unittest.main()
