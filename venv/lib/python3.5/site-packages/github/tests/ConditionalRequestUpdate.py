# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
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

# #193: Line endings should be linux style

from . import Framework
import github


class ConditionalRequestUpdate(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_repo("akfish/PyGithub", lazy=False)

    def testDidNotUpdate(self):
        self.assertFalse(self.repo.update(), msg="The repo is not changed. But update() != False")

    def testDidUpdate(self):
        self.assertTrue(self.repo.update(), msg="The repo should be changed by now. But update() != True")

    def testUpdateObjectWithoutEtag(self):
        r = self.g.get_repo("jacquev6/PyGithub", lazy=False)
        self.assertTrue(r.update())
