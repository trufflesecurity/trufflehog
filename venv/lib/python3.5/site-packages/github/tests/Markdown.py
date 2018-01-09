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


class Markdown(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.text = "MyTitle\n=======\n\nIssue #1"
        self.repo = self.g.get_user().get_repo("PyGithub")

    def testRenderMarkdown(self):
        self.assertEqual(self.g.render_markdown(self.text), '<h1><a name="mytitle" class="anchor" href="#mytitle"><span class="mini-icon mini-icon-link"></span></a>MyTitle</h1><p>Issue #1</p>')

    def testRenderGithubFlavoredMarkdown(self):
        self.assertEqual(self.g.render_markdown(self.text, self.repo), '<h1>MyTitle</h1><p>Issue <a href="https://github.com/jacquev6/PyGithub/issues/1" class="issue-link" title="Gitub -&gt; Github everywhere">#1</a></p>')
