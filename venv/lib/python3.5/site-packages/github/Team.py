# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2013 martinqt <m.ki2@laposte.net>                                  #
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
import github.PaginatedList

import github.Repository
import github.NamedUser


class Team(github.GithubObject.CompletableGithubObject):
    """
    This class represents Teams. The reference can be found here http://developer.github.com/v3/orgs/teams/
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "name": self._name.value})

    @property
    def id(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._id)
        return self._id.value

    @property
    def members_count(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._members_count)
        return self._members_count.value

    @property
    def members_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._members_url)
        return self._members_url.value

    @property
    def name(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._name)
        return self._name.value

    @property
    def permission(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._permission)
        return self._permission.value

    @property
    def repos_count(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._repos_count)
        return self._repos_count.value

    @property
    def repositories_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._repositories_url)
        return self._repositories_url.value

    @property
    def slug(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._slug)
        return self._slug.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def add_to_members(self, member):
        """
        :calls: `PUT /teams/:id/members/:user <http://developer.github.com/v3/orgs/teams>`_
        :param member: :class:`github.NamedUser.NamedUser`
        :rtype: None
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/members/" + member._identity
        )

    def add_membership(self, member):
        """
        :calls: `PUT /teams/:id/memberships/:user <http://developer.github.com/v3/orgs/teams>`_
        :param member: :class:`github.Nameduser.NamedUser`
        :rtype: None
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/memberships/" + member._identity
        )

    def add_to_repos(self, repo):
        """
        :calls: `PUT /teams/:id/repos/:org/:repo <http://developer.github.com/v3/orgs/teams>`_
        :param repo: :class:`github.Repository.Repository`
        :rtype: None
        """
        assert isinstance(repo, github.Repository.Repository), repo
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/repos/" + repo._identity
        )

    def set_repo_permission(self, repo, permission):
        """
        :calls: `PUT /teams/:id/repos/:org/:repo <http://developer.github.com/v3/orgs/teams>`_
        :param repo: :class:`github.Repository.Repository`
        :param permission: string
        :rtype: None
        """
        assert isinstance(repo, github.Repository.Repository), repo
        put_parameters = {
            "permission": permission,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/repos/" + repo._identity,
            input=put_parameters
        )

    def delete(self):
        """
        :calls: `DELETE /teams/:id <http://developer.github.com/v3/orgs/teams>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url
        )

    def edit(self, name, permission=github.GithubObject.NotSet):
        """
        :calls: `PATCH /teams/:id <http://developer.github.com/v3/orgs/teams>`_
        :param name: string
        :param permission: string
        :rtype: None
        """
        assert isinstance(name, str), name
        assert permission is github.GithubObject.NotSet or isinstance(permission, str), permission
        post_parameters = {
            "name": name,
        }
        if permission is not github.GithubObject.NotSet:
            post_parameters["permission"] = permission
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def get_members(self):
        """
        :calls: `GET /teams/:id/members <http://developer.github.com/v3/orgs/teams>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.NamedUser.NamedUser`
        """
        return github.PaginatedList.PaginatedList(
            github.NamedUser.NamedUser,
            self._requester,
            self.url + "/members",
            None
        )

    def get_repos(self):
        """
        :calls: `GET /teams/:id/repos <http://developer.github.com/v3/orgs/teams>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Repository.Repository`
        """
        return github.PaginatedList.PaginatedList(
            github.Repository.Repository,
            self._requester,
            self.url + "/repos",
            None
        )

    def has_in_members(self, member):
        """
        :calls: `GET /teams/:id/members/:user <http://developer.github.com/v3/orgs/teams>`_
        :param member: :class:`github.NamedUser.NamedUser`
        :rtype: bool
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        status, headers, data = self._requester.requestJson(
            "GET",
            self.url + "/members/" + member._identity
        )
        return status == 204

    def has_in_repos(self, repo):
        """
        :calls: `GET /teams/:id/repos/:owner/:repo <http://developer.github.com/v3/orgs/teams>`_
        :param repo: :class:`github.Repository.Repository`
        :rtype: bool
        """
        assert isinstance(repo, github.Repository.Repository), repo
        status, headers, data = self._requester.requestJson(
            "GET",
            self.url + "/repos/" + repo._identity
        )
        return status == 204

    def remove_from_members(self, member):
        """
        :calls: `DELETE /teams/:id/members/:user <http://developer.github.com/v3/orgs/teams>`_
        :param member: :class:`github.NamedUser.NamedUser`
        :rtype: None
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/members/" + member._identity
        )

    def remove_from_repos(self, repo):
        """
        :calls: `DELETE /teams/:id/repos/:owner/:repo <http://developer.github.com/v3/orgs/teams>`_
        :param repo: :class:`github.Repository.Repository`
        :rtype: None
        """
        assert isinstance(repo, github.Repository.Repository), repo
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/repos/" + repo._identity
        )

    @property
    def _identity(self):
        return self.id

    def _initAttributes(self):
        self._id = github.GithubObject.NotSet
        self._members_count = github.GithubObject.NotSet
        self._members_url = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._permission = github.GithubObject.NotSet
        self._repos_count = github.GithubObject.NotSet
        self._repositories_url = github.GithubObject.NotSet
        self._slug = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "members_count" in attributes:  # pragma no branch
            self._members_count = self._makeIntAttribute(attributes["members_count"])
        if "members_url" in attributes:  # pragma no branch
            self._members_url = self._makeStringAttribute(attributes["members_url"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "permission" in attributes:  # pragma no branch
            self._permission = self._makeStringAttribute(attributes["permission"])
        if "repos_count" in attributes:  # pragma no branch
            self._repos_count = self._makeIntAttribute(attributes["repos_count"])
        if "repositories_url" in attributes:  # pragma no branch
            self._repositories_url = self._makeStringAttribute(attributes["repositories_url"])
        if "slug" in attributes:  # pragma no branch
            self._slug = self._makeStringAttribute(attributes["slug"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
