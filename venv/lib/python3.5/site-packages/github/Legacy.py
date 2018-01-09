# -*- coding: utf-8 -*-

# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Steve English <steve.english@navetas.com>                     #
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

import urllib.parse

import github.PaginatedList


class PaginatedList(github.PaginatedList.PaginatedListBase):
    def __init__(self, url, args, requester, key, convert, contentClass):
        github.PaginatedList.PaginatedListBase.__init__(self)
        self.__url = url
        self.__args = args
        self.__requester = requester
        self.__key = key
        self.__convert = convert
        self.__contentClass = contentClass
        self.__nextPage = 0
        self.__continue = True

    def _couldGrow(self):
        return self.__continue

    def _fetchNextPage(self):
        page = self.__nextPage
        self.__nextPage += 1
        return self.get_page(page)

    def get_page(self, page):
        assert isinstance(page, int), page
        args = dict(self.__args)
        if page != 0:
            args["start_page"] = page + 1
        headers, data = self.__requester.requestJsonAndCheck(
            "GET",
            self.__url,
            parameters=args
        )
        self.__continue = len(data[self.__key]) > 0

        return [
            self.__contentClass(self.__requester, headers, self.__convert(element), completed=False)
            for element in data[self.__key]
        ]


def convertUser(attributes):
    convertedAttributes = {
        "login": attributes["login"],
        "url": "/users/" + attributes["login"],
    }
    if "gravatar_id" in attributes:  # pragma no branch
        convertedAttributes["gravatar_id"] = attributes["gravatar_id"]
    if "followers" in attributes:  # pragma no branch
        convertedAttributes["followers"] = attributes["followers"]
    if "repos" in attributes:  # pragma no branch
        convertedAttributes["public_repos"] = attributes["repos"]
    if "name" in attributes:  # pragma no branch
        convertedAttributes["name"] = attributes["name"]
    if "created_at" in attributes:  # pragma no branch
        convertedAttributes["created_at"] = attributes["created_at"]
    if "location" in attributes:  # pragma no branch
        convertedAttributes["location"] = attributes["location"]
    return convertedAttributes


def convertRepo(attributes):
    convertedAttributes = {
        "owner": {"login": attributes["owner"], "url": "/users/" + attributes["owner"]},
        "url": "/repos/" + attributes["owner"] + "/" + attributes["name"],
    }
    if "pushed_at" in attributes:  # pragma no branch
        convertedAttributes["pushed_at"] = attributes["pushed_at"]
    if "homepage" in attributes:  # pragma no branch
        convertedAttributes["homepage"] = attributes["homepage"]
    if "created_at" in attributes:  # pragma no branch
        convertedAttributes["created_at"] = attributes["created_at"]
    if "watchers" in attributes:  # pragma no branch
        convertedAttributes["watchers"] = attributes["watchers"]
    if "has_downloads" in attributes:  # pragma no branch
        convertedAttributes["has_downloads"] = attributes["has_downloads"]
    if "fork" in attributes:  # pragma no branch
        convertedAttributes["fork"] = attributes["fork"]
    if "has_issues" in attributes:  # pragma no branch
        convertedAttributes["has_issues"] = attributes["has_issues"]
    if "has_wiki" in attributes:  # pragma no branch
        convertedAttributes["has_wiki"] = attributes["has_wiki"]
    if "forks" in attributes:  # pragma no branch
        convertedAttributes["forks"] = attributes["forks"]
    if "size" in attributes:  # pragma no branch
        convertedAttributes["size"] = attributes["size"]
    if "private" in attributes:  # pragma no branch
        convertedAttributes["private"] = attributes["private"]
    if "open_issues" in attributes:  # pragma no branch
        convertedAttributes["open_issues"] = attributes["open_issues"]
    if "description" in attributes:  # pragma no branch
        convertedAttributes["description"] = attributes["description"]
    if "language" in attributes:  # pragma no branch
        convertedAttributes["language"] = attributes["language"]
    if "name" in attributes:  # pragma no branch
        convertedAttributes["name"] = attributes["name"]
    return convertedAttributes


def convertIssue(attributes):
    convertedAttributes = {
        "number": attributes["number"],
        "url": "/repos" + urllib.parse.urlparse(attributes["html_url"]).path,
        "user": {"login": attributes["user"], "url": "/users/" + attributes["user"]},
    }
    if "labels" in attributes:  # pragma no branch
        convertedAttributes["labels"] = [{"name": label} for label in attributes["labels"]]
    if "title" in attributes:  # pragma no branch
        convertedAttributes["title"] = attributes["title"]
    if "created_at" in attributes:  # pragma no branch
        convertedAttributes["created_at"] = attributes["created_at"]
    if "comments" in attributes:  # pragma no branch
        convertedAttributes["comments"] = attributes["comments"]
    if "body" in attributes:  # pragma no branch
        convertedAttributes["body"] = attributes["body"]
    if "updated_at" in attributes:  # pragma no branch
        convertedAttributes["updated_at"] = attributes["updated_at"]
    if "state" in attributes:  # pragma no branch
        convertedAttributes["state"] = attributes["state"]
    return convertedAttributes
