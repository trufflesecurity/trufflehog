# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
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

import github.GithubObject

import github.Commit
import github.File


class Comparison(github.GithubObject.CompletableGithubObject):
    """
    This class represents Comparisons as returned for example by http://developer.github.com/v3/todo
    """

    @property
    def ahead_by(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._ahead_by)
        return self._ahead_by.value

    @property
    def base_commit(self):
        """
        :type: :class:`github.Commit.Commit`
        """
        self._completeIfNotSet(self._base_commit)
        return self._base_commit.value

    @property
    def behind_by(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._behind_by)
        return self._behind_by.value

    @property
    def commits(self):
        """
        :type: list of :class:`github.Commit.Commit`
        """
        self._completeIfNotSet(self._commits)
        return self._commits.value

    @property
    def diff_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._diff_url)
        return self._diff_url.value

    @property
    def files(self):
        """
        :type: list of :class:`github.File.File`
        """
        self._completeIfNotSet(self._files)
        return self._files.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    @property
    def merge_base_commit(self):
        """
        :type: :class:`github.Commit.Commit`
        """
        self._completeIfNotSet(self._merge_base_commit)
        return self._merge_base_commit.value

    @property
    def patch_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._patch_url)
        return self._patch_url.value

    @property
    def permalink_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._permalink_url)
        return self._permalink_url.value

    @property
    def status(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._status)
        return self._status.value

    @property
    def total_commits(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._total_commits)
        return self._total_commits.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def _initAttributes(self):
        self._ahead_by = github.GithubObject.NotSet
        self._base_commit = github.GithubObject.NotSet
        self._behind_by = github.GithubObject.NotSet
        self._commits = github.GithubObject.NotSet
        self._diff_url = github.GithubObject.NotSet
        self._files = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._merge_base_commit = github.GithubObject.NotSet
        self._patch_url = github.GithubObject.NotSet
        self._permalink_url = github.GithubObject.NotSet
        self._status = github.GithubObject.NotSet
        self._total_commits = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "ahead_by" in attributes:  # pragma no branch
            self._ahead_by = self._makeIntAttribute(attributes["ahead_by"])
        if "base_commit" in attributes:  # pragma no branch
            self._base_commit = self._makeClassAttribute(github.Commit.Commit, attributes["base_commit"])
        if "behind_by" in attributes:  # pragma no branch
            self._behind_by = self._makeIntAttribute(attributes["behind_by"])
        if "commits" in attributes:  # pragma no branch
            self._commits = self._makeListOfClassesAttribute(github.Commit.Commit, attributes["commits"])
        if "diff_url" in attributes:  # pragma no branch
            self._diff_url = self._makeStringAttribute(attributes["diff_url"])
        if "files" in attributes:  # pragma no branch
            self._files = self._makeListOfClassesAttribute(github.File.File, attributes["files"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "merge_base_commit" in attributes:  # pragma no branch
            self._merge_base_commit = self._makeClassAttribute(github.Commit.Commit, attributes["merge_base_commit"])
        if "patch_url" in attributes:  # pragma no branch
            self._patch_url = self._makeStringAttribute(attributes["patch_url"])
        if "permalink_url" in attributes:  # pragma no branch
            self._permalink_url = self._makeStringAttribute(attributes["permalink_url"])
        if "status" in attributes:  # pragma no branch
            self._status = self._makeStringAttribute(attributes["status"])
        if "total_commits" in attributes:  # pragma no branch
            self._total_commits = self._makeIntAttribute(attributes["total_commits"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
