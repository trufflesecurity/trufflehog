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

import os
import sys
import unittest
import http.client
import traceback

import github

atLeastPython26 = sys.hexversion >= 0x02060000
atLeastPython3 = sys.hexversion >= 0x03000000
atMostPython32 = sys.hexversion < 0x03030000

if atLeastPython26:
    import json
else:  # pragma no cover (Covered by all tests with Python 2.5)
    import simplejson as json  # pragma no cover (Covered by all tests with Python 2.5)


def readLine(file):
    if atLeastPython3:
        return file.readline().decode("utf-8").strip()
    else:
        return file.readline().strip()


class FakeHttpResponse:
    def __init__(self, status, headers, output):
        self.status = status
        self.__headers = headers
        self.__output = output

    def getheaders(self):
        return self.__headers

    def read(self):
        return self.__output


def fixAuthorizationHeader(headers):
    if "Authorization" in headers:
        if headers["Authorization"].endswith("ZmFrZV9sb2dpbjpmYWtlX3Bhc3N3b3Jk"):
            # This special case is here to test the real Authorization header
            # sent by PyGithub. It would have avoided issue https://github.com/jacquev6/PyGithub/issues/153
            # because we would have seen that Python 3 was not generating the same
            # header as Python 2
            pass
        elif headers["Authorization"].startswith("token "):
            headers["Authorization"] = "token private_token_removed"
        elif headers["Authorization"].startswith("Basic "):
            headers["Authorization"] = "Basic login_and_password_removed"


class RecordingConnection:  # pragma no cover (Class useful only when recording new tests, not used during automated tests)
    def __init__(self, file, protocol, host, port, *args, **kwds):
        self.__file = file
        self.__protocol = protocol
        self.__host = host
        self.__port = str(port)
        self.__cnx = self._realConnection(host, port, *args, **kwds)

    def request(self, verb, url, input, headers):
        print(verb, url, input, headers, end=' ')
        self.__cnx.request(verb, url, input, headers)
        fixAuthorizationHeader(headers)
        self.__writeLine(self.__protocol)
        self.__writeLine(verb)
        self.__writeLine(self.__host)
        self.__writeLine(self.__port)
        self.__writeLine(url)
        self.__writeLine(str(headers))
        self.__writeLine(input.replace('\n', '').replace('\r', ''))

    def getresponse(self):
        res = self.__cnx.getresponse()

        status = res.status
        print("=>", status)
        headers = res.getheaders()
        output = res.read()

        self.__writeLine(str(status))
        self.__writeLine(str(headers))
        self.__writeLine(str(output))

        return FakeHttpResponse(status, headers, output)

    def close(self):
        self.__writeLine("")
        return self.__cnx.close()

    def __writeLine(self, line):
        self.__file.write(line + "\n")


class RecordingHttpConnection(RecordingConnection):  # pragma no cover (Class useful only when recording new tests, not used during automated tests)
    _realConnection = http.client.HTTPConnection

    def __init__(self, file, *args, **kwds):
        RecordingConnection.__init__(self, file, "http", *args, **kwds)


class RecordingHttpsConnection(RecordingConnection):  # pragma no cover (Class useful only when recording new tests, not used during automated tests)
    _realConnection = http.client.HTTPSConnection

    def __init__(self, file, *args, **kwds):
        RecordingConnection.__init__(self, file, "https", *args, **kwds)


class ReplayingConnection:
    def __init__(self, testCase, file, protocol, host, port, *args, **kwds):
        self.__testCase = testCase
        self.__file = file
        self.__protocol = protocol
        self.__host = host
        self.__port = str(port)

    def request(self, verb, url, input, headers):
        fixAuthorizationHeader(headers)
        self.__testCase.assertEqual(self.__protocol, readLine(self.__file))
        self.__testCase.assertEqual(verb, readLine(self.__file))
        self.__testCase.assertEqual(self.__host, readLine(self.__file))
        self.__testCase.assertEqual(self.__port, readLine(self.__file))
        self.__testCase.assertEqual(self.__splitUrl(url), self.__splitUrl(readLine(self.__file)))
        self.__testCase.assertEqual(headers, eval(readLine(self.__file)))
        expectedInput = readLine(self.__file)
        if input.startswith("{"):
            self.__testCase.assertEqual(json.loads(input.replace('\n', '').replace('\r', '')), json.loads(expectedInput))
        elif atMostPython32:  # @todo Test in all cases, including Python 3.3
            # In Python 3.3, dicts are not output in the same order as in Python 2.5 -> 3.2.
            # So, form-data encoding is not deterministic and is difficult to test.
            self.__testCase.assertEqual(input.replace('\n', '').replace('\r', ''), expectedInput)

    def __splitUrl(self, url):
        splitedUrl = url.split("?")
        if len(splitedUrl) == 1:
            return splitedUrl
        self.__testCase.assertEqual(len(splitedUrl), 2)
        base, qs = splitedUrl
        return (base, sorted(qs.split("&")))

    def getresponse(self):
        status = int(readLine(self.__file))
        headers = eval(readLine(self.__file))
        output = readLine(self.__file)

        return FakeHttpResponse(status, headers, output)

    def close(self):
        readLine(self.__file)


def ReplayingHttpConnection(testCase, file, *args, **kwds):
    return ReplayingConnection(testCase, file, "http", *args, **kwds)


def ReplayingHttpsConnection(testCase, file, *args, **kwds):
    return ReplayingConnection(testCase, file, "https", *args, **kwds)


class BasicTestCase(unittest.TestCase):
    recordMode = False
    tokenAuthMode = False

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.__fileName = ""
        self.__file = None
        if self.recordMode:  # pragma no cover (Branch useful only when recording new tests, not used during automated tests)
            github.Requester.Requester.injectConnectionClasses(
                lambda ignored, *args, **kwds: RecordingHttpConnection(self.__openFile("wb"), *args, **kwds),
                lambda ignored, *args, **kwds: RecordingHttpsConnection(self.__openFile("wb"), *args, **kwds)
            )
            import GithubCredentials
            self.login = GithubCredentials.login
            self.password = GithubCredentials.password
            self.oauth_token = GithubCredentials.oauth_token
            # @todo Remove client_id and client_secret from ReplayData (as we already remove login, password and oauth_token)
            # self.client_id = GithubCredentials.client_id
            # self.client_secret = GithubCredentials.client_secret
        else:
            github.Requester.Requester.injectConnectionClasses(
                lambda ignored, *args, **kwds: ReplayingHttpConnection(self, self.__openFile("rb"), *args, **kwds),
                lambda ignored, *args, **kwds: ReplayingHttpsConnection(self, self.__openFile("rb"), *args, **kwds)
            )
            self.login = "login"
            self.password = "password"
            self.oauth_token = "oauth_token"
            self.client_id = "client_id"
            self.client_secret = "client_secret"

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        self.__closeReplayFileIfNeeded()
        github.Requester.Requester.resetConnectionClasses()

    def __openFile(self, mode):
        for (_, _, functionName, _) in traceback.extract_stack():
            if functionName.startswith("test") or functionName == "setUp" or functionName == "tearDown":
                if functionName != "test":  # because in class Hook(Framework.TestCase), method testTest calls Hook.test
                    fileName = os.path.join(os.path.dirname(__file__), "ReplayData", self.__class__.__name__ + "." + functionName + ".txt")
        if fileName != self.__fileName:
            self.__closeReplayFileIfNeeded()
            self.__fileName = fileName
            self.__file = open(self.__fileName, mode)
        return self.__file

    def __closeReplayFileIfNeeded(self):
        if self.__file is not None:
            if not self.recordMode:  # pragma no branch (Branch useful only when recording new tests, not used during automated tests)
                self.assertEqual(readLine(self.__file), "")
            self.__file.close()

    def assertListKeyEqual(self, elements, key, expectedKeys):
        realKeys = [key(element) for element in elements]
        self.assertEqual(realKeys, expectedKeys)

    def assertListKeyBegin(self, elements, key, expectedKeys):
        realKeys = [key(element) for element in elements[: len(expectedKeys)]]
        self.assertEqual(realKeys, expectedKeys)


class TestCase(BasicTestCase):
    def doCheckFrame(self, obj, frame):
        if obj._headers == {} and frame is None:
            return
        if obj._headers is None and frame == {}:
            return
        self.assertEqual(obj._headers, frame[2])

    def getFrameChecker(self):
        return lambda requester, obj, frame: self.doCheckFrame(obj, frame)

    def setUp(self):
        BasicTestCase.setUp(self)

        # Set up frame debugging
        github.GithubObject.GithubObject.setCheckAfterInitFlag(True)
        github.Requester.Requester.setDebugFlag(True)
        github.Requester.Requester.setOnCheckMe(self.getFrameChecker())

        if self.tokenAuthMode:
            self.g = github.Github(self.oauth_token)
        else:
            self.g = github.Github(self.login, self.password)


def activateRecordMode():  # pragma no cover (Function useful only when recording new tests, not used during automated tests)
    BasicTestCase.recordMode = True


def activateTokenAuthMode():  # pragma no cover (Function useful only when recording new tests, not used during automated tests)
    BasicTestCase.tokenAuthMode = True
