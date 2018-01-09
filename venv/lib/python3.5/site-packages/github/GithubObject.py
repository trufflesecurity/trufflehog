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
import sys
import datetime
from operator import itemgetter

from . import GithubException
from . import Consts

atLeastPython3 = sys.hexversion >= 0x03000000


class _NotSetType:
    def __repr__(self):
        return "NotSet"

    value = None
NotSet = _NotSetType()


class _ValuedAttribute:
    def __init__(self, value):
        self.value = value


class _BadAttribute:
    def __init__(self, value, expectedType, exception=None):
        self.__value = value
        self.__expectedType = expectedType
        self.__exception = exception

    @property
    def value(self):
        raise GithubException.BadAttributeException(self.__value, self.__expectedType, self.__exception)


class GithubObject(object):
    """
    Base class for all classes representing objects returned by the API.
    """

    '''
    A global debug flag to enable header validation by requester for all objects
    '''
    CHECK_AFTER_INIT_FLAG = False

    @classmethod
    def setCheckAfterInitFlag(cls, flag):
        cls.CHECK_AFTER_INIT_FLAG = flag

    def __init__(self, requester, headers, attributes, completed):
        self._requester = requester
        self._initAttributes()
        self._storeAndUseAttributes(headers, attributes)

        # Ask requester to do some checking, for debug and test purpose
        # Since it's most handy to access and kinda all-knowing
        if self.CHECK_AFTER_INIT_FLAG:  # pragma no branch (Flag always set in tests)
            requester.check_me(self)

    def _storeAndUseAttributes(self, headers, attributes):
        # Make sure headers are assigned before calling _useAttributes
        # (Some derived classes will use headers in _useAttributes)
        self._headers = headers
        self._rawData = attributes
        self._useAttributes(attributes)

    @property
    def raw_data(self):
        """
        :type: dict
        """
        self._completeIfNeeded()
        return self._rawData

    @property
    def raw_headers(self):
        """
        :type: dict
        """
        self._completeIfNeeded()
        return self._headers

    @staticmethod
    def _parentUrl(url):
        return "/".join(url.split("/")[: -1])

    @staticmethod
    def __makeSimpleAttribute(value, type):
        if value is None or isinstance(value, type):
            return _ValuedAttribute(value)
        else:
            return _BadAttribute(value, type)

    @staticmethod
    def __makeSimpleListAttribute(value, type):
        if isinstance(value, list) and all(isinstance(element, type) for element in value):
            return _ValuedAttribute(value)
        else:
            return _BadAttribute(value, [type])

    @staticmethod
    def __makeTransformedAttribute(value, type, transform):
        if value is None:
            return _ValuedAttribute(None)
        elif isinstance(value, type):
            try:
                return _ValuedAttribute(transform(value))
            except Exception as e:
                return _BadAttribute(value, type, e)
        else:
            return _BadAttribute(value, type)

    @staticmethod
    def _makeStringAttribute(value):
        return GithubObject.__makeSimpleAttribute(value, (str, str))

    @staticmethod
    def _makeIntAttribute(value):
        return GithubObject.__makeSimpleAttribute(value, (int, int))

    @staticmethod
    def _makeBoolAttribute(value):
        return GithubObject.__makeSimpleAttribute(value, bool)

    @staticmethod
    def _makeDictAttribute(value):
        return GithubObject.__makeSimpleAttribute(value, dict)

    @staticmethod
    def _makeTimestampAttribute(value):
        return GithubObject.__makeTransformedAttribute(value, (int, int), datetime.datetime.utcfromtimestamp)

    @staticmethod
    def _makeDatetimeAttribute(value):
        def parseDatetime(s):
            if len(s) == 24:  # pragma no branch (This branch was used only when creating a download)
                # The Downloads API has been removed. I'm keeping this branch because I have no mean
                # to check if it's really useless now.
                return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.000Z")  # pragma no cover (This branch was used only when creating a download)
            elif len(s) == 25:
                return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S") + (1 if s[19] == '-' else -1) * datetime.timedelta(hours=int(s[20:22]), minutes=int(s[23:25]))
            else:
                return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")

        return GithubObject.__makeTransformedAttribute(value, (str, str), parseDatetime)

    def _makeClassAttribute(self, klass, value):
        return GithubObject.__makeTransformedAttribute(value, dict, lambda value: klass(self._requester, self._headers, value, completed=False))

    @staticmethod
    def _makeListOfStringsAttribute(value):
        return GithubObject.__makeSimpleListAttribute(value, (str, str))

    @staticmethod
    def _makeListOfIntsAttribute(value):
        return GithubObject.__makeSimpleListAttribute(value, int)

    @staticmethod
    def _makeListOfListOfStringsAttribute(value):
        return GithubObject.__makeSimpleListAttribute(value, list)

    def _makeListOfClassesAttribute(self, klass, value):
        if isinstance(value, list) and all(isinstance(element, dict) for element in value):
            return _ValuedAttribute([klass(self._requester, self._headers, element, completed=False) for element in value])
        else:
            return _BadAttribute(value, [dict])

    def _makeDictOfStringsToClassesAttribute(self, klass, value):
        if isinstance(value, dict) and all(isinstance(key, str) and isinstance(element, dict) for key, element in value.items()):
            return _ValuedAttribute(dict((key, klass(self._requester, self._headers, element, completed=False)) for key, element in value.items()))
        else:
            return _BadAttribute(value, {(str, str): dict})

    @property
    def etag(self):
        '''
        :type: str
        '''
        return self._headers.get(Consts.RES_ETAG)

    @property
    def last_modified(self):
        '''
        :type: str
        '''
        return self._headers.get(Consts.RES_LAST_MODIFIED)

    def get__repr__(self, params):
        """
        Converts the object to a nicely printable string.
        """
        def format_params(params):
            if atLeastPython3:
                items = list(params.items())
            else:
                items = list(params.items())
            for k, v in sorted(items, key=itemgetter(0), reverse=True):
                isText = isinstance(v, str)
                if isText and not atLeastPython3:
                    v = v.encode('utf-8')
                yield '{k}="{v}"'.format(k=k, v=v) if isText else '{k}={v}'.format(k=k, v=v)
        return '{class_name}({params})'.format(
            class_name=self.__class__.__name__,
            params=", ".join(list(format_params(params)))
        )


class NonCompletableGithubObject(GithubObject):
    def _completeIfNeeded(self):
        pass


class CompletableGithubObject(GithubObject):
    def __init__(self, requester, headers, attributes, completed):
        GithubObject.__init__(self, requester, headers, attributes, completed)
        self.__completed = completed

    def __eq__(self, other):
        return other.__class__ is self.__class__ and other._url.value == self._url.value

    def __ne__(self, other):
        return not self == other

    def _completeIfNotSet(self, value):
        if value is NotSet:
            self._completeIfNeeded()

    def _completeIfNeeded(self):
        if not self.__completed:
            self.__complete()

    def __complete(self):
        headers, data = self._requester.requestJsonAndCheck(
            "GET",
            self._url.value
        )
        self._storeAndUseAttributes(headers, data)
        self.__completed = True

    def update(self):
        '''
        Check and update the object with conditional request
        :rtype: Boolean value indicating whether the object is changed
        '''
        conditionalRequestHeader = dict()
        if self.etag is not None:
            conditionalRequestHeader[Consts.REQ_IF_NONE_MATCH] = self.etag
        if self.last_modified is not None:
            conditionalRequestHeader[Consts.REQ_IF_MODIFIED_SINCE] = self.last_modified

        status, responseHeaders, output = self._requester.requestJson(
            "GET",
            self._url.value,
            headers=conditionalRequestHeader
        )
        if status == 304:
            return False
        else:
            headers, data = self._requester._Requester__check(status, responseHeaders, output)
            self._storeAndUseAttributes(headers, data)
            self.__completed = True
            return True
