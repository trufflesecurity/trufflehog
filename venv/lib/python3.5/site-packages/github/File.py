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


class File(github.GithubObject.NonCompletableGithubObject):
    """
    This class represents Files as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"sha": self._sha.value, "filename": self._filename.value})

    @property
    def additions(self):
        """
        :type: integer
        """
        return self._additions.value

    @property
    def blob_url(self):
        """
        :type: string
        """
        return self._blob_url.value

    @property
    def changes(self):
        """
        :type: integer
        """
        return self._changes.value

    @property
    def contents_url(self):
        """
        :type: string
        """
        return self._contents_url.value

    @property
    def deletions(self):
        """
        :type: integer
        """
        return self._deletions.value

    @property
    def filename(self):
        """
        :type: string
        """
        return self._filename.value

    @property
    def patch(self):
        """
        :type: string
        """
        return self._patch.value

    @property
    def previous_filename(self):
        """
        :type: string
        """
        return self._previous_filename.value

    @property
    def raw_url(self):
        """
        :type: string
        """
        return self._raw_url.value

    @property
    def sha(self):
        """
        :type: string
        """
        return self._sha.value

    @property
    def status(self):
        """
        :type: string
        """
        return self._status.value

    def _initAttributes(self):
        self._additions = github.GithubObject.NotSet
        self._blob_url = github.GithubObject.NotSet
        self._changes = github.GithubObject.NotSet
        self._contents_url = github.GithubObject.NotSet
        self._deletions = github.GithubObject.NotSet
        self._filename = github.GithubObject.NotSet
        self._patch = github.GithubObject.NotSet
        self._previous_filename = github.GithubObject.NotSet
        self._raw_url = github.GithubObject.NotSet
        self._sha = github.GithubObject.NotSet
        self._status = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "additions" in attributes:  # pragma no branch
            self._additions = self._makeIntAttribute(attributes["additions"])
        if "blob_url" in attributes:  # pragma no branch
            self._blob_url = self._makeStringAttribute(attributes["blob_url"])
        if "changes" in attributes:  # pragma no branch
            self._changes = self._makeIntAttribute(attributes["changes"])
        if "contents_url" in attributes:  # pragma no branch
            self._contents_url = self._makeStringAttribute(attributes["contents_url"])
        if "deletions" in attributes:  # pragma no branch
            self._deletions = self._makeIntAttribute(attributes["deletions"])
        if "filename" in attributes:  # pragma no branch
            self._filename = self._makeStringAttribute(attributes["filename"])
        if "patch" in attributes:  # pragma no branch
            self._patch = self._makeStringAttribute(attributes["patch"])
        if "previous_filename" in attributes: # pragma no branch
            self._previous_filename = self._makeStringAttribute(attributes["previous_filename"])
        if "raw_url" in attributes:  # pragma no branch
            self._raw_url = self._makeStringAttribute(attributes["raw_url"])
        if "sha" in attributes:  # pragma no branch
            self._sha = self._makeStringAttribute(attributes["sha"])
        if "status" in attributes:  # pragma no branch
            self._status = self._makeStringAttribute(attributes["status"])
