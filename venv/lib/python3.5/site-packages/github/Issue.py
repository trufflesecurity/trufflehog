# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Andrew Bettison <andrewb@zip.com.au>                          #
# Copyright 2012 Philip Kimmey <philip@rover.com>                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 AKFish <akfish@gmail.com>                                     #
# Copyright 2013 Stuart Glaser <stuglaser@gmail.com>                           #
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

import urllib.request, urllib.parse, urllib.error
import datetime
import github.GithubObject
import github.PaginatedList

import github.Repository
import github.IssueEvent
import github.Label
import github.NamedUser
import github.Milestone
import github.IssueComment
import github.IssuePullRequest


class Issue(github.GithubObject.CompletableGithubObject):
    """
    This class represents Issues as returned for example by http://developer.github.com/v3/todo
    """

    def __repr__(self):
        return self.get__repr__({"number": self._number.value, "title": self._title.value})

    @property
    def assignee(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._assignee)
        return self._assignee.value

    @property
    def assignees(self):
        """
        :type: list of :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._assignees)
        return self._assignees.value

    @property
    def body(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._body)
        return self._body.value

    @property
    def closed_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._closed_at)
        return self._closed_at.value

    @property
    def closed_by(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._closed_by)
        return self._closed_by.value

    @property
    def comments(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._comments)
        return self._comments.value

    @property
    def comments_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._comments_url)
        return self._comments_url.value

    @property
    def created_at(self):
        """
        :type: datetime.datetime
        """
        self._completeIfNotSet(self._created_at)
        return self._created_at.value

    @property
    def events_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._events_url)
        return self._events_url.value

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
    def labels(self):
        """
        :type: list of :class:`github.Label.Label`
        """
        self._completeIfNotSet(self._labels)
        return self._labels.value

    @property
    def labels_url(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._labels_url)
        return self._labels_url.value

    @property
    def milestone(self):
        """
        :type: :class:`github.Milestone.Milestone`
        """
        self._completeIfNotSet(self._milestone)
        return self._milestone.value

    @property
    def number(self):
        """
        :type: integer
        """
        self._completeIfNotSet(self._number)
        return self._number.value

    @property
    def pull_request(self):
        """
        :type: :class:`github.IssuePullRequest.IssuePullRequest`
        """
        self._completeIfNotSet(self._pull_request)
        return self._pull_request.value

    @property
    def repository(self):
        """
        :type: :class:`github.Repository.Repository`
        """
        self._completeIfNotSet(self._repository)
        if self._repository is github.GithubObject.NotSet:
            # The repository was not set automatically, so it must be looked up by url.
            repo_url = "/".join(self.url.split("/")[:-2])
            self._repository = github.GithubObject._ValuedAttribute(github.Repository.Repository(self._requester, self._headers, {'url': repo_url}, completed=False))
        return self._repository.value

    @property
    def state(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._state)
        return self._state.value

    @property
    def title(self):
        """
        :type: string
        """
        self._completeIfNotSet(self._title)
        return self._title.value

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

    @property
    def user(self):
        """
        :type: :class:`github.NamedUser.NamedUser`
        """
        self._completeIfNotSet(self._user)
        return self._user.value

    def add_to_assignees(self, *assignees):
        """
        :calls: `POST /repos/:owner/:repo/issues/:number/assignees <https://developer.github.com/v3/issues/assignees>`_
        :param assignee: :class:`github.NamedUser.NamedUser` or string
        :rtype: None
        """
        assert all(isinstance(element, (github.NamedUser.NamedUser, str)) for element in assignees), assignees
        post_parameters = {"assignees": [assignee.login if isinstance(assignee, github.NamedUser.NamedUser) else assignee for assignee in assignees]}
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/assignees",
            input=post_parameters
        )
        self._useAttributes(data)

    def add_to_labels(self, *labels):
        """
        :calls: `POST /repos/:owner/:repo/issues/:number/labels <http://developer.github.com/v3/issues/labels>`_
        :param label: :class:`github.Label.Label` or string
        :rtype: None
        """
        assert all(isinstance(element, (github.Label.Label, str)) for element in labels), labels
        post_parameters = [label.name if isinstance(label, github.Label.Label) else label for label in labels]
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/labels",
            input=post_parameters
        )

    def create_comment(self, body):
        """
        :calls: `POST /repos/:owner/:repo/issues/:number/comments <http://developer.github.com/v3/issues/comments>`_
        :param body: string
        :rtype: :class:`github.IssueComment.IssueComment`
        """
        assert isinstance(body, str), body
        post_parameters = {
            "body": body,
        }
        headers, data = self._requester.requestJsonAndCheck(
            "POST",
            self.url + "/comments",
            input=post_parameters
        )
        return github.IssueComment.IssueComment(self._requester, headers, data, completed=True)

    def delete_labels(self):
        """
        :calls: `DELETE /repos/:owner/:repo/issues/:number/labels <http://developer.github.com/v3/issues/labels>`_
        :rtype: None
        """
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/labels"
        )

    def edit(self, title=github.GithubObject.NotSet, body=github.GithubObject.NotSet, assignee=github.GithubObject.NotSet, state=github.GithubObject.NotSet, milestone=github.GithubObject.NotSet, labels=github.GithubObject.NotSet, assignees=github.GithubObject.NotSet):
        """
        :calls: `PATCH /repos/:owner/:repo/issues/:number <http://developer.github.com/v3/issues>`_
        :param title: string
        :param body: string
        :param assignee: string or :class:`github.NamedUser.NamedUser` or None
        :param assignees: list (of string or :class:`github.NamedUser.NamedUser`)
        :param state: string
        :param milestone: :class:`github.Milestone.Milestone` or None
        :param labels: list of string
        :rtype: None
        """
        assert title is github.GithubObject.NotSet or isinstance(title, str), title
        assert body is github.GithubObject.NotSet or isinstance(body, str), body
        assert assignee is github.GithubObject.NotSet or assignee is None or isinstance(assignee, github.NamedUser.NamedUser) or isinstance(assignee, str), assignee
        assert assignees is github.GithubObject.NotSet or all(isinstance(element, github.NamedUser.NamedUser) or isinstance(element, str) for element in assignees), assignees
        assert state is github.GithubObject.NotSet or isinstance(state, str), state
        assert milestone is github.GithubObject.NotSet or milestone is None or isinstance(milestone, github.Milestone.Milestone), milestone
        assert labels is github.GithubObject.NotSet or all(isinstance(element, str) for element in labels), labels
        post_parameters = dict()
        if title is not github.GithubObject.NotSet:
            post_parameters["title"] = title
        if body is not github.GithubObject.NotSet:
            post_parameters["body"] = body
        if assignee is not github.GithubObject.NotSet:
            if isinstance(assignee, str):
                post_parameters["assignee"] = assignee
            else:
                post_parameters["assignee"] = assignee._identity if assignee else ''
        if assignees is not github.GithubObject.NotSet:
            post_parameters["assignees"] = [element._identity if isinstance(element, github.NamedUser.NamedUser) else element for element in assignees]
        if state is not github.GithubObject.NotSet:
            post_parameters["state"] = state
        if milestone is not github.GithubObject.NotSet:
            post_parameters["milestone"] = milestone._identity if milestone else ''
        if labels is not github.GithubObject.NotSet:
            post_parameters["labels"] = labels
        headers, data = self._requester.requestJsonAndCheck(
            "PATCH",
            self.url,
            input=post_parameters
        )
        self._useAttributes(data)

    def get_comment(self, id):
        """
        :calls: `GET /repos/:owner/:repo/issues/comments/:id <http://developer.github.com/v3/issues/comments>`_
        :param id: integer
        :rtype: :class:`github.IssueComment.IssueComment`
        """
        assert isinstance(id, int), id
        headers, data = self._requester.requestJsonAndCheck(
            "GET",
            self._parentUrl(self.url) + "/comments/" + str(id)
        )
        return github.IssueComment.IssueComment(self._requester, headers, data, completed=True)

    def get_comments(self, since=github.GithubObject.NotSet):
        """
        :calls: `GET /repos/:owner/:repo/issues/:number/comments <http://developer.github.com/v3/issues/comments>`_
        :param since: datetime.datetime format YYYY-MM-DDTHH:MM:SSZ
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.IssueComment.IssueComment`
        """
        assert since is github.GithubObject.NotSet or isinstance(since, datetime.datetime), since
        url_parameters = dict()
        if since is not github.GithubObject.NotSet:
            url_parameters["since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        return github.PaginatedList.PaginatedList(
            github.IssueComment.IssueComment,
            self._requester,
            self.url + "/comments",
            url_parameters
        )

    def get_events(self):
        """
        :calls: `GET /repos/:owner/:repo/issues/:issue_number/events <http://developer.github.com/v3/issues/events>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.IssueEvent.IssueEvent`
        """
        return github.PaginatedList.PaginatedList(
            github.IssueEvent.IssueEvent,
            self._requester,
            self.url + "/events",
            None
        )

    def get_labels(self):
        """
        :calls: `GET /repos/:owner/:repo/issues/:number/labels <http://developer.github.com/v3/issues/labels>`_
        :rtype: :class:`github.PaginatedList.PaginatedList` of :class:`github.Label.Label`
        """
        return github.PaginatedList.PaginatedList(
            github.Label.Label,
            self._requester,
            self.url + "/labels",
            None
        )

    def remove_from_assignees(self, *assignees):
        """
        :calls: `DELETE /repos/:owner/:repo/issues/:number/assignees <https://developer.github.com/v3/issues/assignees>`_
        :param assignee: :class:`github.NamedUser.NamedUser` or string
        :rtype: None
        """
        assert all(isinstance(element, (github.NamedUser.NamedUser, str)) for element in assignees), assignees
        post_parameters = {"assignees": [assignee.login if isinstance(assignee, github.NamedUser.NamedUser) else assignee for assignee in assignees]}
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/assignees",
            input=post_parameters
        )
        self._useAttributes(data)

    def remove_from_labels(self, label):
        """
        :calls: `DELETE /repos/:owner/:repo/issues/:number/labels/:name <http://developer.github.com/v3/issues/labels>`_
        :param label: :class:`github.Label.Label` or string
        :rtype: None
        """
        assert isinstance(label, (github.Label.Label, str)), label
        if isinstance(label, github.Label.Label):
            label = label._identity
        else:
            label = urllib.parse.quote(label)
        headers, data = self._requester.requestJsonAndCheck(
            "DELETE",
            self.url + "/labels/" + label
        )

    def set_labels(self, *labels):
        """
        :calls: `PUT /repos/:owner/:repo/issues/:number/labels <http://developer.github.com/v3/issues/labels>`_
        :param label: :class:`github.Label.Label`
        :rtype: None
        """
        assert all(isinstance(element, (github.Label.Label, str)) for element in labels), labels
        post_parameters = [label.name if isinstance(label, github.Label.Label) else label for label in labels]
        headers, data = self._requester.requestJsonAndCheck(
            "PUT",
            self.url + "/labels",
            input=post_parameters
        )

    @property
    def _identity(self):
        return self.number

    def _initAttributes(self):
        self._assignee = github.GithubObject.NotSet
        self._assignees = github.GithubObject.NotSet
        self._body = github.GithubObject.NotSet
        self._closed_at = github.GithubObject.NotSet
        self._closed_by = github.GithubObject.NotSet
        self._comments = github.GithubObject.NotSet
        self._comments_url = github.GithubObject.NotSet
        self._created_at = github.GithubObject.NotSet
        self._events_url = github.GithubObject.NotSet
        self._html_url = github.GithubObject.NotSet
        self._id = github.GithubObject.NotSet
        self._labels = github.GithubObject.NotSet
        self._labels_url = github.GithubObject.NotSet
        self._milestone = github.GithubObject.NotSet
        self._number = github.GithubObject.NotSet
        self._pull_request = github.GithubObject.NotSet
        self._repository = github.GithubObject.NotSet
        self._state = github.GithubObject.NotSet
        self._title = github.GithubObject.NotSet
        self._updated_at = github.GithubObject.NotSet
        self._url = github.GithubObject.NotSet
        self._user = github.GithubObject.NotSet

    def _useAttributes(self, attributes):
        if "assignee" in attributes:  # pragma no branch
            self._assignee = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["assignee"])
        if "assignees" in attributes:  # pragma no branch
            self._assignees = self._makeListOfClassesAttribute(github.NamedUser.NamedUser, attributes["assignees"])
        elif "assignee" in attributes:
            if attributes["assignee"] is not None:
                self._assignees = self._makeListOfClassesAttribute(github.NamedUser.NamedUser, [attributes["assignee"]])
            else:
                self._assignees = self._makeListOfClassesAttribute(github.NamedUser.NamedUser, [])
        if "body" in attributes:  # pragma no branch
            self._body = self._makeStringAttribute(attributes["body"])
        if "closed_at" in attributes:  # pragma no branch
            self._closed_at = self._makeDatetimeAttribute(attributes["closed_at"])
        if "closed_by" in attributes:  # pragma no branch
            self._closed_by = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["closed_by"])
        if "comments" in attributes:  # pragma no branch
            self._comments = self._makeIntAttribute(attributes["comments"])
        if "comments_url" in attributes:  # pragma no branch
            self._comments_url = self._makeStringAttribute(attributes["comments_url"])
        if "created_at" in attributes:  # pragma no branch
            self._created_at = self._makeDatetimeAttribute(attributes["created_at"])
        if "events_url" in attributes:  # pragma no branch
            self._events_url = self._makeStringAttribute(attributes["events_url"])
        if "html_url" in attributes:  # pragma no branch
            self._html_url = self._makeStringAttribute(attributes["html_url"])
        if "id" in attributes:  # pragma no branch
            self._id = self._makeIntAttribute(attributes["id"])
        if "labels" in attributes:  # pragma no branch
            self._labels = self._makeListOfClassesAttribute(github.Label.Label, attributes["labels"])
        if "labels_url" in attributes:  # pragma no branch
            self._labels_url = self._makeStringAttribute(attributes["labels_url"])
        if "milestone" in attributes:  # pragma no branch
            self._milestone = self._makeClassAttribute(github.Milestone.Milestone, attributes["milestone"])
        if "number" in attributes:  # pragma no branch
            self._number = self._makeIntAttribute(attributes["number"])
        if "pull_request" in attributes:  # pragma no branch
            self._pull_request = self._makeClassAttribute(github.IssuePullRequest.IssuePullRequest, attributes["pull_request"])
        if "repository" in attributes:  # pragma no branch
            self._repository = self._makeClassAttribute(github.Repository.Repository, attributes["repository"])
        if "state" in attributes:  # pragma no branch
            self._state = self._makeStringAttribute(attributes["state"])
        if "title" in attributes:  # pragma no branch
            self._title = self._makeStringAttribute(attributes["title"])
        if "updated_at" in attributes:  # pragma no branch
            self._updated_at = self._makeDatetimeAttribute(attributes["updated_at"])
        if "url" in attributes:  # pragma no branch
            self._url = self._makeStringAttribute(attributes["url"])
        if "user" in attributes:  # pragma no branch
            self._user = self._makeClassAttribute(github.NamedUser.NamedUser, attributes["user"])
