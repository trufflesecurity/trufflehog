# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Steve English <steve.english@navetas.com>                     #
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

import datetime

import github.GithubObject
import github.PaginatedList

import github.Plan
import github.Team
import github.Event
import github.Repository
import github.NamedUser


class Organization(github.GithubObject.CompletableGithubObject):
    """
    This class represents Organizations. The reference can be found here http://developer.github.com/v3/orgs/
    """

    def __repr__(self):
        return self.get__repr__({"id": self._id.value, "name": self._name.value})

    @property
    def avatar_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._avatar_url)
        return self._avatar_url.value

    @property
    def billing_email(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._billing_email)
        return self._billing_email.value

    @property
    def blog(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._blog)
        return self._blog.value

    @property
    def collaborators(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._collaborators)
        return self._collaborators.value

    @property
    def company(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._company)
        return self._company.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def disk_usage(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._disk_usage)
        return self._disk_usage.value

    @property
    def email(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._email)
        return self._email.value

    @property
    def events_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._events_url)
        return self._events_url.value

    @property
    def followers(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._followers)
        return self._followers.value

    @property
    def following(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._following)
        return self._following.value

    @property
    def gravatar_id(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._gravatar_id)
        return self._gravatar_id.value

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
    def location(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._location)
        return self._location.value

    @property
    def login(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._login)
        return self._login.value

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
    def owned_private_repos(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._owned_private_repos)
        return self._owned_private_repos.value

    @property
    def plan(self):
        """
        :type: :class:`github.Plan.Plan`
        """
        self._completeIfNotSet(self._plan)
        return self._plan.value

    @property
    def private_gists(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._private_gists)
        return self._private_gists.value

    @property
    def public_gists(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._public_gists)
        return self._public_gists.value

    @property
    def public_members_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._public_members_url)
        return self._public_members_url.value

    @property
    def public_repos(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._public_repos)
        return self._public_repos.value

    @property
    def repos_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._repos_url)
        return self._repos_url.value

    @property
    def total_private_repos(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._total_private_repos)
        return self._total_private_repos.value

    @property
    def type(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._type)
        return self._type.value

    @property
    def updated_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._updated_at)
        return self._updated_at.value

    @property
    def url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._url)
        return self._url.value

    def add_to_public_members(self, public_member):
        """
        :calls: `PUT /orgs/:org/public_members/:user <http://developer.github.com/v3/orgs/members>`_
        :param public_member: :class:`github.NamedUser.NamedUser`
        :rtype: None
        """
        assert isinstance(public_member, github.NamedUser.NamedUser), public_member
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/public_members/" + public_member._identity
        )

    def create_fork(self, repo):
        """
        :calls: `POST /repos/:owner/:repo/forks <http://developer.github.com/v3/repos/forks>`_
        :param repo: :class:`github.Repository.Repository`
        :rtype: :class:`github.Repository.Repository`
        """
        assert isinstance(repo, github.Repository.Repository), repo
        url_parameters = {
            "org": self.login,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            "/repos/" + repo.owner.login + "/" + repo.name + "/forks",
            parameters=url_parameters
        )
        return github.Repository.Repository(self._requester, headers, data, completed=True)

    def create_repo(self, name, description=github.GithubObject.NotSet, homepage=github.GithubObject.NotSet, private=github.GithubObject.NotSet, has_issues=github.GithubObject.NotSet, has_wiki=github.GithubObject.NotSet, has_downloads=github.GithubObject.NotSet, team_id=github.GithubObject.NotSet, auto_init=github.GithubObject.NotSet, gitignore_template=github.GithubObject.NotSet):
        """
        :calls: `POST /orgs/:org/repos <http://developer.github.com/v3/repos>`_
        :param name: string
        :param description: string
        :param homepage: string
        :param private: bool
        :param has_issues: bool
        :param has_wiki: bool
        :param has_downloads: bool
        :param team_id: :class:`github.Team.Team`
        :param auto_init: bool
        :param gitignore_template: string
        :rtype: :class:`github.Repository.Repository`
        """
        assert isinstance(name, str), name
        assert description is github.GithubObject.NotSet or isinstance(description, str), description
        assert homepage is github.GithubObject.NotSet or isinstance(homepage, str), homepage
        assert private is github.GithubObject.NotSet or isinstance(private, bool), private
        assert has_issues is github.GithubObject.NotSet or isinstance(has_issues, bool), has_issues
        assert has_wiki is github.GithubObject.NotSet or isinstance(has_wiki, bool), has_wiki
        assert has_downloads is github.GithubObject.NotSet or isinstance(has_downloads, bool), has_downloads
        assert team_id is github.GithubObject.NotSet or isinstance(team_id, github.Team.Team), team_id
        assert auto_init is github.GithubObject.NotSet or isinstance(auto_init, bool), auto_init
        assert gitignore_template is github.GithubObject.NotSet or isinstance(gitignore_template, str), gitignore_template
        post_parameters = {
            "name": name,
        }
        if description is not github.GithubObject.NotSet:
            post_parameters["description"] = description
        if homepage is not github.GithubObject.NotSet:
            post_parameters["homepage"] = homepage
        if private is not github.GithubObject.NotSet:
            post_parameters["private"] = private
        if has_issues is not github.GithubObject.NotSet:
            post_parameters["has_issues"] = has_issues
        if has_wiki is not github.GithubObject.NotSet:
            post_parameters["has_wiki"] = has_wiki
        if has_downloads is not github.GithubObject.NotSet:
            post_parameters["has_downloads"] = has_downloads
        if team_id is not github.GithubObject.NotSet:
            post_parameters["team_id"] = team_id._identity
        if auto_init is not github.GithubObject.NotSet:
            post_parameters["auto_init"] = auto_init
        if gitignore_template is not github.GithubObject.NotSet:
            post_parameters["gitignore_template"] = gitignore_template
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/repos",
            input=post_parameters
        )
        return github.Repository.Repository(self._requester, headers, data, completed=True)

    def create_team(self, name, repo_names=github.GithubObject.NotSet, permission=github.GithubObject.NotSet):
        """
        :calls: `POST /orgs/:org/teams <http://developer.github.com/v3/orgs/teams>`_
        :param name: string
        :param repo_names: list of :class:`github.Repository.Repository`
        :param permission: string
        :rtype: :class:`github.Team.Team`
        """
        assert isinstance(name, str), name
        assert repo_names is github.GithubObject.NotSet or all(isinstance(element, github.Repository.Repository) for element in repo_names), repo_names
        assert permission is github.GithubObject.NotSet or isinstance(permission, str), permission
        post_parameters = {
            "name": name,
        }
        if repo_names is not github.GithubObject.NotSet:
            post_parameters["repo_names"] = [element._identity for element in repo_names]
        if permission is not github.GithubObject.NotSet:
            post_parameters["permission"] = permission
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/teams",
            input=post_parameters
        )
        return github.Team.Team(self._requester, headers, data, completed=True)

    def edit(self, billing_email=github.GithubObject.NotSet, blog=github.GithubObject.NotSet, company=github.GithubObject.NotSet, email=github.GithubObject.NotSet, location=github.GithubObject.NotSet, name=github.GithubObject.NotSet):
        """
        :calls: `PATCH /orgs/:org <http://developer.github.com/v3/orgs>`_
        :param billing_email: string
        :param blog: string
        :param company: string
        :param email: string
        :param location: string
        :param name: string
        :rtype: None
        """
        assert billing_email is github.GithubObject.NotSet or isinstance(billing_email, str), billing_email
        assert blog is github.GithubObject.NotSet or isinstance(blog, str), blog
        assert company is github.GithubObject.NotSet or isinstance(company, str), company
        assert email is github.GithubObject.NotSet or isinstance(email, str), email
        assert location is github.GithubObject.NotSet or isinstance(location, str), location
        assert name is github.GithubObject.NotSet or isinstance(name, str), name
        post_parameters = dict()
        if billing_email is not github.GithubObject.NotSet:
            post_parameters["billing_email"] = billing_email
        if blog is not github.GithubObject.NotSet:
            post_parameters["blog"] = blog
        if company is not github.GithubObject.NotSet:
            post_parameters["company"] = company
        if email is not github.GithubObject.NotSet:
            post_parameters["email"] = email
        if location is not github.GithubObject.NotSet:
            post_parameters["location"] = location
        if name is not github.GithubObject.NotSet:
            post_parameters["name"] = name
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def get_events(self):
        """
        :calls: `GET /orgs/:org/events <http://developer.github.com/v3/activity/events>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Event.Event`
        """
        return github.PaginatedList.PaginatedList(
            github.Event.Event,
            self._requester,
            self.url + "/events",
            None
        )

    def get_issues(self, filter=github.GithubObject.NotSet, state=github.GithubObject.NotSet, labels=github.GithubObject.NotSet, sort=github.GithubObject.NotSet, direction=github.GithubObject.NotSet, since=github.GithubObject.NotSet):
        """
        :calls: `GET /orgs/:org/issues <http://developer.github.com/v3/issues>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Issue.Issue`
        :param filter: string
        :param state: string
        :param labels: list of :class:`github.Label.Label`
        :param sort: string
        :param direction: string
        :param since: datetime.datetime
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Issue.Issue`
        """
        assert filter is github.GithubObject.NotSet or isinstance(filter, str), filter
        assert state is github.GithubObject.NotSet or isinstance(state, str), state
        assert labels is github.GithubObject.NotSet or all(isinstance(element, github.Label.Label) for element in labels), labels
        assert sort is github.GithubObject.NotSet or isinstance(sort, str), sort
        assert direction is github.GithubObject.NotSet or isinstance(direction, str), direction
        assert since is github.GithubObject.NotSet or isinstance(since, datetime.datetime), since
        url_parameters = dict()
        if filter is not github.GithubObject.NotSet:
            url_parameters["filter"] = filter
        if state is not github.GithubObject.NotSet:
            url_parameters["state"] = state
        if labels is not github.GithubObject.NotSet:
            url_parameters["labels"] = ",".join(label.name for label in labels)
        if sort is not github.GithubObject.NotSet:
            url_parameters["sort"] = sort
        if direction is not github.GithubObject.NotSet:
            url_parameters["direction"] = direction
        if since is not github.GithubObject.NotSet:
            url_parameters["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        return github.PaginatedList.PaginatedList(
            github.Issue.Issue,
            self._requester,
            self.url + "/issues",
            url_parameters
        )

    def get_members(self, filter_=github.GithubObject.NotSet,
                    role=github.GithubObject.NotSet):
        """
        :calls: `GET /orgs/:org/members <http://developer.github.com/v3/orgs/members>`_
        :param filter_: string
        :param role: string
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.NamedUser.NamedUser`
        """
        assert (filter_ is github.GithubObject.NotSet or
                isinstance(filter_, str)), filter_
        assert (role is github.GithubObject.NotSet or
                isinstance(role, str)), role

        url_parameters = {}
        if filter_ is not github.GithubObject.NotSet:
            url_parameters["filter"] = filter_
        if role is not github.GithubObject.NotSet:
            url_parameters["role"] = role
        return github.PaginatedList.PaginatedList(
            github.NamedUser.NamedUser,
            self._requester,
            self.url + "/members",
            url_parameters
        )

    def get_public_members(self):
        """
        :calls: `GET /orgs/:org/public_members <http://developer.github.com/v3/orgs/members>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.NamedUser.NamedUser`
        """
        return github.PaginatedList.PaginatedList(
            github.NamedUser.NamedUser,
            self._requester,
            self.url + "/public_members",
            None
        )

    def get_repo(self, name):
        """
        :calls: `GET /repos/:owner/:repo <http://developer.github.com/v3/repos>`_
        :param name: string
        :rtype: :class:`github.Repository.Repository`
        """
        assert isinstance(name, str), name
        headers, data = self._requester.requestJsonAndCheck(
            "GET",
            "/repos/" + self.login + "/" + name
        )
        return github.Repository.Repository(self._requester, headers, data, completed=True)

    def get_repos(self, type=github.GithubObject.NotSet):
        """
        :calls: `GET /orgs/:org/repos <http://developer.github.com/v3/repos>`_
        :param type: string ('all', 'public', 'private', 'forks', 'sources', 'member')
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Repository.Repository`
        """
        assert type is github.GithubObject.NotSet or isinstance(type, str), type
        url_parameters = dict()
        if type is not github.GithubObject.NotSet:
            url_parameters["type"] = type
        return github.PaginatedList.PaginatedList(
            github.Repository.Repository,
            self._requester,
            self.url + "/repos",
            url_parameters
        )

    def get_team(self, id):
        """
        :calls: `GET /teams/:id <http://developer.github.com/v3/orgs/teams>`_
        :param id: integer
        :rtype: :class:`github.Team.Team`
        """
        assert isinstance(id, int), id
        headers, data = self._requester.requestJsonAndCheck(
            "GET",
            "/teams/" + str(id)
        )
        return github.Team.Team(self._requester, headers, data, completed=True)

    def get_teams(self):
        """
        :calls: `GET /orgs/:org/teams <http://developer.github.com/v3/orgs/teams>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Team.Team`
        """
        return github.PaginatedList.PaginatedList(
            github.Team.Team,
            self._requester,
            self.url + "/teams",
            None
        )

    def has_in_members(self, member):
        """
        :calls: `GET /orgs/:org/members/:user <http://developer.github.com/v3/orgs/members>`_
        :param member: :class:`github.NamedUser.NamedUser`
        :rtype: bool
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        status, headers, data = self._requester.requestJson(
            "GET",
            self.url + "/members/" + member._identity
        )
        if status == 302:
            status, headers, data = self._requester.requestJson(
                "GET",
                headers['location']
            )
        return status == 204

    def has_in_public_members(self, public_member):
        """
        :calls: `GET /orgs/:org/public_members/:user <http://developer.github.com/v3/orgs/members>`_
        :param public_member: :class:`github.NamedUser.NamedUser`
        :rtype: bool
        """
        assert isinstance(public_member, github.NamedUser.NamedUser), public_member
        status, headers, data = self._requester.requestJson(
            "GET",
            self.url + "/public_members/" + public_member._identity
        )
        return status == 204

    def remove_from_members(self, member):
        """
        :calls: `DELETE /orgs/:org/members/:user <http://developer.github.com/v3/orgs/members>`_
        :param member: :class:`github.NamedUser.NamedUser`
        :rtype: None
        """
        assert isinstance(member, github.NamedUser.NamedUser), member
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/members/" + member._identity
        )

    def remove_from_public_members(self, public_member):
        """
        :calls: `DELETE /orgs/:org/public_members/:user <http://developer.github.com/v3/orgs/members>`_
        :param public_member: :class:`github.NamedUser.NamedUser`
        :rtype: None
        """
        assert isinstance(public_member, github.NamedUser.NamedUser), public_member
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/public_members/" + public_member._identity
        )

    def _initAttributes(self):
        self._avatar_url = github.GithubObject.NotSet
        self._billing_email = github.GithubObject.NotSet
        self._blog = github.GithubObject.NotSet
        self._collaborators = github.GithubObject.NotSet
        self._company = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._disk_usage = github.GithubObject.NotSet
        self._email = github.GithubObject.NotSet
        self._events_url = github.GithubObject.NotSet
        self._followers = github.GithubObject.NotSet
        self._following = github.GithubObject.NotSet
        self._gravatar_id = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._location = github.GithubObject.NotSet
        self._login = github.GithubObject.NotSet
        self._members_url = github.GithubObject.NotSet
        self._name = github.GithubObject.NotSet
        self._owned_private_repos = github.GithubObject.NotSet
        self._plan = github.GithubObject.NotSet
        self._private_gists = github.GithubObject.NotSet
        self._public_gists = github.GithubObject.NotSet
        self._public_members_url = github.GithubObject.NotSet
        self._public_repos = github.GithubObject.NotSet
        self._repos_url = github.GithubObject.NotSet
        self._total_private_repos = github.GithubObject.NotSet
        self._type = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "avatar_url" in attributes:  # pragma no branch
            self._avatar_url = self._makeStringAttribute(attributes["avatar_url"])
        if "billing_email" in attributes:  # pragma no branch
            self._billing_email = self._makeStringAttribute(attributes["billing_email"])
        if "blog" in attributes:  # pragma no branch
            self._blog = self._makeStringAttribute(attributes["blog"])
        if "collaborators" in attributes:  # pragma no branch
            self._collaborators = self._makeIntAttribute(attributes["collaborators"])
        if "company" in attributes:  # pragma no branch
            self._company = self._makeStringAttribute(attributes["company"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "disk_usage" in attributes:  # pragma no branch
            self._disk_usage = self._makeIntAttribute(attributes["disk_usage"])
        if "email" in attributes:  # pragma no branch
            self._email = self._makeStringAttribute(attributes["email"])
        if "events_url" in attributes:  # pragma no branch
            self._events_url = self._makeStringAttribute(attributes["events_url"])
        if "followers" in attributes:  # pragma no branch
            self._followers = self._makeIntAttribute(attributes["followers"])
        if "following" in attributes:  # pragma no branch
            self._following = self._makeIntAttribute(attributes["following"])
        if "gravatar_id" in attributes:  # pragma no branch
            self._gravatar_id = self._makeStringAttribute(attributes["gravatar_id"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "location" in attributes:  # pragma no branch
            self._location = self._makeStringAttribute(attributes["location"])
        if "login" in attributes:  # pragma no branch
            self._login = self._makeStringAttribute(attributes["login"])
        if "members_url" in attributes:  # pragma no branch
            self._members_url = self._makeStringAttribute(attributes["members_url"])
        if "name" in attributes:  # pragma no branch
            self._name = self._makeStringAttribute(attributes["name"])
        if "owned_private_repos" in attributes:  # pragma no branch
            self._owned_private_repos = self._makeIntAttribute(attributes["owned_private_repos"])
        if "plan" in attributes:  # pragma no branch
            self._plan = self._makeClassAttribute(github.Plan.Plan, attributes["plan"])
        if "private_gists" in attributes:  # pragma no branch
            self._private_gists = self._makeIntAttribute(attributes["private_gists"])
        if "public_gists" in attributes:  # pragma no branch
            self._public_gists = self._makeIntAttribute(attributes["public_gists"])
        if "public_members_url" in attributes:  # pragma no branch
            self._public_members_url = self._makeStringAttribute(attributes["public_members_url"])
        if "public_repos" in attributes:  # pragma no branch
            self._public_repos = self._makeIntAttribute(attributes["public_repos"])
        if "repos_url" in attributes:  # pragma no branch
            self._repos_url = self._makeStringAttribute(attributes["repos_url"])
        if "total_private_repos" in attributes:  # pragma no branch
            self._total_private_repos = self._makeIntAttribute(attributes["total_private_repos"])
        if "type" in attributes:  # pragma no branch
            self._type = self._makeStringAttribute(attributes["type"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
