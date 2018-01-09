# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2013 davidbrai <davidbrai@gmail.com>                               #
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
from github.PaginatedList import PaginatedList as PaginatedListImpl


class PaginatedList(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.repo = self.g.get_user("openframeworks").get_repo("openFrameworks")
        self.list = self.repo.get_issues()

    def testIteration(self):
        self.assertEqual(len(list(self.list)), 333)

    def testSeveralIterations(self):
        self.assertEqual(len(list(self.list)), 333)
        self.assertEqual(len(list(self.list)), 333)
        self.assertEqual(len(list(self.list)), 333)
        self.assertEqual(len(list(self.list)), 333)

    def testIntIndexingInFirstPage(self):
        self.assertEqual(self.list[0].id, 4772349)
        self.assertEqual(self.list[24].id, 4286936)

    def testReversedIterationWithSinglePage(self):
        r = self.list.reversed
        self.assertEqual(r[0].id, 4286936)
        self.assertEqual(r[1].id, 4317009)

    def testReversedIterationWithMultiplePages(self):
        r = self.list.reversed
        self.assertEqual(r[0].id, 94898)
        self.assertEqual(r[1].id, 104702)
        self.assertEqual(r[13].id, 166211)
        self.assertEqual(r[14].id, 166212)
        self.assertEqual(r[15].id, 166214)

    def testReversedIterationSupportsIterator(self):
        r = self.list.reversed
        for i in r:
            self.assertEqual(i.id, 4286936)
            return
        self.fail("empty iterator")

    def testGettingTheReversedListDoesNotModifyTheOriginalList(self):
        self.assertEqual(self.list[0].id, 18345408)
        self.assertEqual(self.list[30].id, 17916118)
        r = self.list.reversed
        self.assertEqual(self.list[0].id, 18345408)
        self.assertEqual(self.list[30].id, 17916118)
        self.assertEqual(r[0].id, 132373)
        self.assertEqual(r[30].id, 543694)

    def testIntIndexingInThirdPage(self):
        self.assertEqual(self.list[50].id, 3911629)
        self.assertEqual(self.list[74].id, 3605277)

    def testGetFirstPage(self):
        self.assertListKeyEqual(self.list.get_page(0), lambda i: i.id, [4772349, 4767675, 4758608, 4700182, 4662873, 4608132, 4604661, 4588997, 4557803, 4554058, 4539985, 4507572, 4507492, 4507416, 4447561, 4406584, 4384548, 4383465, 4373361, 4373201, 4370619, 4356530, 4352401, 4317009, 4286936])

    def testGetThirdPage(self):
        self.assertListKeyEqual(self.list.get_page(2), lambda i: i.id, [3911629, 3911537, 3910580, 3910555, 3910549, 3897090, 3883598, 3856005, 3850655, 3825582, 3813852, 3812318, 3812275, 3807459, 3799872, 3799653, 3795495, 3754055, 3710293, 3662214, 3647640, 3631618, 3627067, 3614231, 3605277])

    def testIntIndexingAfterIteration(self):
        self.assertEqual(len(list(self.list)), 333)
        self.assertEqual(self.list[11].id, 4507572)
        self.assertEqual(self.list[73].id, 3614231)
        self.assertEqual(self.list[332].id, 94898)

    def testSliceIndexingInFirstPage(self):
        self.assertListKeyEqual(self.list[:13], lambda i: i.id, [4772349, 4767675, 4758608, 4700182, 4662873, 4608132, 4604661, 4588997, 4557803, 4554058, 4539985, 4507572, 4507492])
        self.assertListKeyEqual(self.list[:13:3], lambda i: i.id, [4772349, 4700182, 4604661, 4554058, 4507492])
        self.assertListKeyEqual(self.list[10:13], lambda i: i.id, [4539985, 4507572, 4507492])
        self.assertListKeyEqual(self.list[5:13:3], lambda i: i.id, [4608132, 4557803, 4507572])

    def testSliceIndexingUntilFourthPage(self):
        self.assertListKeyEqual(self.list[:99:10], lambda i: i.id, [4772349, 4539985, 4370619, 4207350, 4063366, 3911629, 3813852, 3647640, 3528378, 3438233])
        self.assertListKeyEqual(self.list[73:78], lambda i: i.id, [3614231, 3605277, 3596240, 3594731, 3593619])
        self.assertListKeyEqual(self.list[70:80:2], lambda i: i.id, [3647640, 3627067, 3605277, 3594731, 3593430])

    def testSliceIndexingUntilEnd(self):
        self.assertListKeyEqual(self.list[310::3], lambda i: i.id, [268332, 204247, 169176, 166211, 165898, 163959, 132373, 104702])
        self.assertListKeyEqual(self.list[310:], lambda i: i.id, [268332, 211418, 205935, 204247, 172424, 171615, 169176, 166214, 166212, 166211, 166209, 166208, 165898, 165537, 165409, 163959, 132671, 132377, 132373, 130269, 111018, 104702, 94898])

    def testInterruptedIteration(self):
        # No asserts, but checks that only three pages are fetched
        l = 0
        for element in self.list:  # pragma no branch (exits only by break)
            l += 1
            if l == 75:
                break

    def testInterruptedIterationInSlice(self):
        # No asserts, but checks that only three pages are fetched
        l = 0
        for element in self.list[:100]:  # pragma no branch (exits only by break)
            l += 1
            if l == 75:
                break

    def testCustomPerPage(self):
        self.assertEqual(self.g.per_page, 30)
        self.g.per_page = 100
        self.assertEqual(self.g.per_page, 100)
        self.assertEqual(len(list(self.repo.get_issues())), 456)

    def testCustomPerPageWithNoUrlParams(self):
        from . import CommitComment  # Don't polute github.tests namespace, it would conflict with github.tests.CommitComment
        self.g.per_page = 100
        paginated_list = PaginatedListImpl(
            CommitComment.CommitComment,
            self.repo._requester,
            self.repo.url + "/comments",
            None
        )

    def testCustomPerPageWithNoUrlParams2(self):
        # This test is redountant and less unitary than testCustomPerPageWithNoUrlParams
        # but I hope it will be more robust if we refactor PaginatedList,
        # because testCustomPerPageWithNoUrlParams only tests the constructor
        self.g.per_page = 100
        self.assertEqual(len(list(self.repo.get_comments())), 325)

    def testCustomPerPageWithGetPage(self):
        self.g.per_page = 100
        self.assertEqual(len(self.repo.get_issues().get_page(2)), 100)

    def testNoFirstPage(self):
        self.assertFalse(next(iter(self.list), None))
