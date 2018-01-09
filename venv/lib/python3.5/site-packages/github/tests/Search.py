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
import sys

atLeastPython3 = sys.hexversion >= 0x03000000


class Search(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)

    def testSearchUsers(self):
        users = self.g.search_users("vincent", sort="followers", order="desc")
        self.assertEqual(users.totalCount, 2781)
        self.assertEqual(users[0].login, "nvie")
        self.assertEqual(users[14].login, "Vayn")

    def testPaginateSearchUsers(self):
        users = self.g.search_users("", location="Berlin")
        self.assertListKeyBegin(users, lambda u: u.login, ['cloudhead', 'felixge', 'sferik', 'rkh', 'jezdez', 'janl', 'marijnh', 'nikic', 'igorw', 'froschi', 'svenfuchs', 'omz', 'chad', 'bergie', 'roidrage', 'pcalcado', 'durran', 'hukl', 'mttkay', 'aFarkas', 'ole', 'hagenburger', 'jberkel', 'naderman', 'joshk', 'pudo', 'robb', 'josephwilk', 'hanshuebner', 'txus', 'paulasmuth', 'splitbrain', 'langalex', 'bendiken', 'stefanw'])
        self.assertEqual(users.totalCount, 6038)

    def testGetPageOnSearchUsers(self):
        users = self.g.search_users("", location="Berlin")
        self.assertEqual([u.login for u in users.get_page(7)], ['ursachec', 'bitboxer', 'fs111', 'michenriksen', 'witsch', 'booo', 'mortice', 'r0man', 'MikeBild', 'mhagger', 'bkw', 'fwbrasil', 'mschneider', 'lydiapintscher', 'asksven', 'iamtimm', 'sneak', 'kr1sp1n', 'Feh', 'GordonLesti', 'annismckenzie', 'eskimoblood', 'tsujigiri', 'riethmayer', 'lauritzthamsen', 'scotchi', 'peritor', 'toto', 'hwaxxer', 'lukaszklis'])

    def testSearchRepos(self):
        repos = self.g.search_repositories("github", sort="stars", order="desc", language="Python")
        self.assertListKeyBegin(repos, lambda r: r.full_name, ['kennethreitz/legit', 'RuudBurger/CouchPotatoV1', 'gelstudios/gitfiti', 'gpjt/webgl-lessons', 'jacquev6/PyGithub', 'aaasen/github_globe', 'hmason/gitmarks', 'dnerdy/factory_boy', 'binaryage/drydrop', 'bgreenlee/sublime-github', 'karan/HackerNewsAPI', 'mfenniak/pyPdf', 'skazhy/github-decorator', 'llvmpy/llvmpy', 'lexrupy/gmate', 'ask/python-github2', 'audreyr/cookiecutter-pypackage', 'tabo/django-treebeard', 'dbr/tvdb_api', 'jchris/couchapp', 'joeyespo/grip', 'nigelsmall/py2neo', 'ask/chishop', 'sigmavirus24/github3.py', 'jsmits/github-cli', 'lincolnloop/django-layout', 'amccloud/django-project-skel', 'Stiivi/brewery', 'webpy/webpy.github.com', 'dustin/py-github', 'logsol/Github-Auto-Deploy', 'cloudkick/libcloud', 'berkerpeksag/github-badge', 'bitprophet/ssh', 'azavea/OpenTreeMap'])

    def testSearchIssues(self):
        issues = self.g.search_issues("compile", sort="comments", order="desc", language="C++")
        self.assertListKeyBegin(issues, lambda i: i.id, [12068673, 23250111, 14371957, 9423897, 24277400, 2408877, 11338741, 13980502, 27697165, 23102422])

    def testSearchCode(self):
        files = self.g.search_code("toto", sort="indexed", order="asc", user="jacquev6")
        self.assertListKeyEqual(files, lambda f: f.name, ['Commit.setUp.txt', 'PullRequest.testGetFiles.txt', 'NamedUser.testGetEvents.txt', 'PullRequest.testCreateComment.txt', 'PullRequestFile.setUp.txt', 'Repository.testGetIssuesWithWildcards.txt', 'Repository.testGetIssuesWithArguments.txt', 'test_ebnf.cpp', 'test_abnf.cpp', 'PullRequestFile.py', 'SystemCalls.py', 'tests.py', 'LexerTestCase.py', 'ParserTestCase.py'])
        self.assertEqual(files[0].repository.full_name, "jacquev6/PyGithub")
        if atLeastPython3:
            self.assertEqual(files[0].decoded_content[:30], b'https\nGET\napi.github.com\nNone\n')
        else:
            self.assertEqual(files[0].decoded_content[:30], "https\nGET\napi.github.com\nNone\n")

    def testUrlquotingOfQualifiers(self):
        # Example taken from #236
        issues = self.g.search_issues("repo:saltstack/salt-api type:Issues", updated=">2014-03-04T18:28:11Z")
        self.assertEqual(issues[0].id, 29138794)

    def testUrlquotingOfQuery(self):
        # Example taken from #236
        issues = self.g.search_issues("repo:saltstack/salt-api type:Issues updated:>2014-03-04T18:28:11Z")
        self.assertEqual(issues[0].id, 29138794)
