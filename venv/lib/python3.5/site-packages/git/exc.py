# exc.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
""" Module containing all exceptions thrown throughout the git package, """

from gitdb.exc import *     # NOQA @UnusedWildImport
from git.compat import UnicodeMixin, safe_decode, string_types


class GitError(Exception):
    """ Base class for all package exceptions """


class InvalidGitRepositoryError(GitError):
    """ Thrown if the given repository appears to have an invalid format.  """


class WorkTreeRepositoryUnsupported(InvalidGitRepositoryError):
    """ Thrown to indicate we can't handle work tree repositories """


class NoSuchPathError(GitError, OSError):
    """ Thrown if a path could not be access by the system. """


class CommandError(UnicodeMixin, GitError):
    """Base class for exceptions thrown at every stage of `Popen()` execution.

    :param command:
        A non-empty list of argv comprising the command-line.
    """

    #: A unicode print-format with 2 `%s for `<cmdline>` and the rest,
    #:  e.g.
    #:     u"'%s' failed%s"
    _msg = u"Cmd('%s') failed%s"

    def __init__(self, command, status=None, stderr=None, stdout=None):
        if not isinstance(command, (tuple, list)):
            command = command.split()
        self.command = command
        self.status = status
        if status:
            if isinstance(status, Exception):
                status = u"%s('%s')" % (type(status).__name__, safe_decode(str(status)))
            else:
                try:
                    status = u'exit code(%s)' % int(status)
                except (ValueError, TypeError):
                    s = safe_decode(str(status))
                    status = u"'%s'" % s if isinstance(status, string_types) else s

        self._cmd = safe_decode(command[0])
        self._cmdline = u' '.join(safe_decode(i) for i in command)
        self._cause = status and u" due to: %s" % status or "!"
        self.stdout = stdout and u"\n  stdout: '%s'" % safe_decode(stdout) or ''
        self.stderr = stderr and u"\n  stderr: '%s'" % safe_decode(stderr) or ''

    def __unicode__(self):
        return (self._msg + "\n  cmdline: %s%s%s") % (
            self._cmd, self._cause, self._cmdline, self.stdout, self.stderr)


class GitCommandNotFound(CommandError):
    """Thrown if we cannot find the `git` executable in the PATH or at the path given by
    the GIT_PYTHON_GIT_EXECUTABLE environment variable"""
    def __init__(self, command, cause):
        super(GitCommandNotFound, self).__init__(command, cause)
        self._msg = u"Cmd('%s') not found%s"


class GitCommandError(CommandError):
    """ Thrown if execution of the git command fails with non-zero status code. """

    def __init__(self, command, status, stderr=None, stdout=None):
        super(GitCommandError, self).__init__(command, status, stderr, stdout)


class CheckoutError(GitError):
    """Thrown if a file could not be checked out from the index as it contained
    changes.

    The .failed_files attribute contains a list of relative paths that failed
    to be checked out as they contained changes that did not exist in the index.

    The .failed_reasons attribute contains a string informing about the actual
    cause of the issue.

    The .valid_files attribute contains a list of relative paths to files that
    were checked out successfully and hence match the version stored in the
    index"""

    def __init__(self, message, failed_files, valid_files, failed_reasons):
        Exception.__init__(self, message)
        self.failed_files = failed_files
        self.failed_reasons = failed_reasons
        self.valid_files = valid_files

    def __str__(self):
        return Exception.__str__(self) + ":%s" % self.failed_files


class CacheError(GitError):

    """Base for all errors related to the git index, which is called cache internally"""


class UnmergedEntriesError(CacheError):
    """Thrown if an operation cannot proceed as there are still unmerged
    entries in the cache"""


class HookExecutionError(CommandError):
    """Thrown if a hook exits with a non-zero exit code. It provides access to the exit code and the string returned
    via standard output"""

    def __init__(self, command, status, stderr=None, stdout=None):
        super(HookExecutionError, self).__init__(command, status, stderr, stdout)
        self._msg = u"Hook('%s') failed%s"


class RepositoryDirtyError(GitError):
    """Thrown whenever an operation on a repository fails as it has uncommitted changes that would be overwritten"""

    def __init__(self, repo, message):
        self.repo = repo
        self.message = message

    def __str__(self):
        return "Operation cannot be performed on %r: %s" % (self.repo, self.message)
