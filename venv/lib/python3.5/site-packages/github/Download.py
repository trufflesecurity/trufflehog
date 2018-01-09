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


class Download(github.GithubObject.CompletableGithubObject):
    """
    This class represents Downloads as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value})

    @property
    def accesskeyid(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._accesskeyid)
        return self._accesskeyid.value

    @property
    def acl(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._acl)
        return self._acl.value

    @property
    def bucket(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._bucket)
        return self._bucket.value

    @property
    def content_type(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._content_type)
        return self._content_type.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def description(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._description)
        return self._description.value

    @property
    def download_count(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._download_count)
        return self._download_count.value

    @property
    def expirationdate(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._expirationdate)
        return self._expirationdate.value

    @property
    def html_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._html_url)
        return self._html_url.value

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def mime_type(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._mime_type)
        return self._mime_type.value

    @property
    def name(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._name)
        return self._name.value

    @property
    def path(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._path)
        return self._path.value

    @property
    def policy(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._policy)
        return self._policy.value

    @property
    def prefix(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._prefix)
        return self._prefix.value

    @property
    def redirect(self):
        """
        :type: bool
        """
        self._completeIfNotSet(self._redirect)
        return self._redirect.value

    @property
    def s3_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._s3_url)
        return self._s3_url.value

    @property
    def signature(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._signature)
        return self._signature.value

    @property
    def size(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._size)
        return self._size.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def delete(self):
        """
        :calls: `DELETE /repos/:owner/:repo/downloads/:id <http://developer.github.com/v3/repos/downloads>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def _initAttributes(self):
        self._accesskeyid = github.GithubObject.NotSet
        self._acl = github.GithubObject.NotSet
        self._bucket = github.GithubObject.NotSet
        self._content_type = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._description = github.GithubObject.NotSet
        self._download_count = github.GithubObject.NotSet
        self._expirationdate = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._mime_type = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._path = github.GithubObject.NotSet
        self._policy = github.GithubObject.NotSet
        self._prefix = github.GithubObject.NotSet
        self._redirect = github.GithubObject.NotSet
        self._s3_url = github.GithubObject.NotSet
        self._signature = github.GithubObject.NotSet
        self._size = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "accesskeyid" in attributes:  # pragma no branch
            self._accesskeyid = self._makeStringAttribute(attributes["accesskeyid"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "acl" in attributes:  # pragma no branch
            self._acl = self._makeStringAttribute(attributes["acl"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "bucket" in attributes:  # pragma no branch
            self._bucket = self._makeStringAttribute(attributes["bucket"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "content_type" in attributes:  # pragma no branch
            self._content_type = self._makeStringAttribute(attributes["content_type"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "description" in attributes:  # pragma no branch
            self._description = self._makeStringAttribute(attributes["description"])
        if "download_count" in attributes:  # pragma no branch
            self._download_count = self._makeIntAttribute(attributes["download_count"])
        if "expirationdate" in attributes:  # pragma no branch
            self._expirationdate = self._makeDatetimeAttribute(attributes["expirationdate"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "mime_type" in attributes:  # pragma no branch
            self._mime_type = self._makeStringAttribute(attributes["mime_type"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "path" in attributes:  # pragma no branch
            self._path = self._makeStringAttribute(attributes["path"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "policy" in attributes:  # pragma no branch
            self._policy = self._makeStringAttribute(attributes["policy"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "prefix" in attributes:  # pragma no branch
            self._prefix = self._makeStringAttribute(attributes["prefix"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "redirect" in attributes:  # pragma no branch
            self._redirect = self._makeBoolAttribute(attributes["redirect"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "s3_url" in attributes:  # pragma no branch
            self._s3_url = self._makeStringAttribute(attributes["s3_url"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "signature" in attributes:  # pragma no branch
            self._signature = self._makeStringAttribute(attributes["signature"])  # pragma no cover (was covered only by create_download, which has been removed)
        if "size" in attributes:  # pragma no branch
            self._size = self._makeIntAttribute(attributes["size"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
