# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import contextlib
from functools import wraps
import getpass
import logging
import os
import platform
import subprocess
import re
import shutil
import stat
import time
try:
    from unittest import SkipTest
except ImportError:
    from unittest2 import SkipTest

from gitdb.util import (# NOQA @IgnorePep8
    make_sha,
    LockedFD,               # @UnusedImport
    file_contents_ro,       # @UnusedImport
    file_contents_ro_filepath,       # @UnusedImport
    LazyMixin,              # @UnusedImport
    to_hex_sha,             # @UnusedImport
    to_bin_sha,             # @UnusedImport
    bin_to_hex,             # @UnusedImport
    hex_to_bin,             # @UnusedImport
)

from git.compat import is_win
import os.path as osp

from .compat import (
    MAXSIZE,
    defenc,
    PY3
)
from .exc import InvalidGitRepositoryError


# NOTE:  Some of the unused imports might be used/imported by others.
# Handle once test-cases are back up and running.
# Most of these are unused here, but are for use by git-python modules so these
# don't see gitdb all the time. Flake of course doesn't like it.
__all__ = ("stream_copy", "join_path", "to_native_path_windows", "to_native_path_linux",
           "join_path_native", "Stats", "IndexFileSHA1Writer", "Iterable", "IterableList",
           "BlockingLockFile", "LockFile", 'Actor', 'get_user_id', 'assure_directory_exists',
           'RemoteProgress', 'CallableRemoteProgress', 'rmtree', 'unbare_repo',
           'HIDE_WINDOWS_KNOWN_ERRORS')

log = logging.getLogger(__name__)

#: We need an easy way to see if Appveyor TCs start failing,
#: so the errors marked with this var are considered "acknowledged" ones, awaiting remedy,
#: till then, we wish to hide them.
HIDE_WINDOWS_KNOWN_ERRORS = is_win and os.environ.get('HIDE_WINDOWS_KNOWN_ERRORS', True)
HIDE_WINDOWS_FREEZE_ERRORS = is_win and os.environ.get('HIDE_WINDOWS_FREEZE_ERRORS', True)

#{ Utility Methods


def unbare_repo(func):
    """Methods with this decorator raise InvalidGitRepositoryError if they
    encounter a bare repository"""

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.repo.bare:
            raise InvalidGitRepositoryError("Method '%s' cannot operate on bare repositories" % func.__name__)
        # END bare method
        return func(self, *args, **kwargs)
    # END wrapper
    return wrapper


@contextlib.contextmanager
def cwd(new_dir):
    old_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield new_dir
    finally:
        os.chdir(old_dir)


def rmtree(path):
    """Remove the given recursively.

    :note: we use shutil rmtree but adjust its behaviour to see whether files that
        couldn't be deleted are read-only. Windows will not remove them in that case"""

    def onerror(func, path, exc_info):
        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)

        try:
            func(path)  # Will scream if still not possible to delete.
        except Exception as ex:
            if HIDE_WINDOWS_KNOWN_ERRORS:
                raise SkipTest("FIXME: fails with: PermissionError\n  %s", ex)
            else:
                raise

    return shutil.rmtree(path, False, onerror)


def rmfile(path):
    """Ensure file deleted also on *Windows* where read-only files need special treatment."""
    if osp.isfile(path):
        if is_win:
            os.chmod(path, 0o777)
        os.remove(path)


def stream_copy(source, destination, chunk_size=512 * 1024):
    """Copy all data from the source stream into the destination stream in chunks
    of size chunk_size

    :return: amount of bytes written"""
    br = 0
    while True:
        chunk = source.read(chunk_size)
        destination.write(chunk)
        br += len(chunk)
        if len(chunk) < chunk_size:
            break
    # END reading output stream
    return br


def join_path(a, *p):
    """Join path tokens together similar to osp.join, but always use
    '/' instead of possibly '\' on windows."""
    path = a
    for b in p:
        if len(b) == 0:
            continue
        if b.startswith('/'):
            path += b[1:]
        elif path == '' or path.endswith('/'):
            path += b
        else:
            path += '/' + b
    # END for each path token to add
    return path


if is_win:
    def to_native_path_windows(path):
        return path.replace('/', '\\')

    def to_native_path_linux(path):
        return path.replace('\\', '/')

    to_native_path = to_native_path_windows
else:
    # no need for any work on linux
    def to_native_path_linux(path):
        return path
    to_native_path = to_native_path_linux


def join_path_native(a, *p):
    """
    As join path, but makes sure an OS native path is returned. This is only
        needed to play it safe on my dear windows and to assure nice paths that only
        use '\'"""
    return to_native_path(join_path(a, *p))


def assure_directory_exists(path, is_file=False):
    """Assure that the directory pointed to by path exists.

    :param is_file: If True, path is assumed to be a file and handled correctly.
        Otherwise it must be a directory
    :return: True if the directory was created, False if it already existed"""
    if is_file:
        path = osp.dirname(path)
    # END handle file
    if not osp.isdir(path):
        os.makedirs(path)
        return True
    return False


def _get_exe_extensions():
    PATHEXT = os.environ.get('PATHEXT', None)
    return tuple(p.upper() for p in PATHEXT.split(os.pathsep)) \
        if PATHEXT \
        else (('.BAT', 'COM', '.EXE') if is_win else ())


def py_where(program, path=None):
    # From: http://stackoverflow.com/a/377028/548792
    winprog_exts = _get_exe_extensions()

    def is_exec(fpath):
        return osp.isfile(fpath) and os.access(fpath, os.X_OK) and (
            os.name != 'nt' or not winprog_exts or any(fpath.upper().endswith(ext)
                                                       for ext in winprog_exts))

    progs = []
    if not path:
        path = os.environ["PATH"]
    for folder in path.split(os.pathsep):
        folder = folder.strip('"')
        if folder:
            exe_path = osp.join(folder, program)
            for f in [exe_path] + ['%s%s' % (exe_path, e) for e in winprog_exts]:
                if is_exec(f):
                    progs.append(f)
    return progs


def _cygexpath(drive, path):
    if osp.isabs(path) and not drive:
        ## Invoked from `cygpath()` directly with `D:Apps\123`?
        #  It's an error, leave it alone just slashes)
        p = path
    else:
        p = path and osp.normpath(osp.expandvars(osp.expanduser(path)))
        if osp.isabs(p):
            if drive:
                # Confusing, maybe a remote system should expand vars.
                p = path
            else:
                p = cygpath(p)
        elif drive:
            p = '/cygdrive/%s/%s' % (drive.lower(), p)

    return p.replace('\\', '/')


_cygpath_parsers = (
    ## See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
    ## and: https://www.cygwin.com/cygwin-ug-net/using.html#unc-paths
    (re.compile(r"\\\\\?\\UNC\\([^\\]+)\\([^\\]+)(?:\\(.*))?"),
     (lambda server, share, rest_path: '//%s/%s/%s' % (server, share, rest_path.replace('\\', '/'))),
     False
     ),

    (re.compile(r"\\\\\?\\(\w):[/\\](.*)"),
     _cygexpath,
     False
     ),

    (re.compile(r"(\w):[/\\](.*)"),
     _cygexpath,
     False
     ),

    (re.compile(r"file:(.*)", re.I),
     (lambda rest_path: rest_path),
     True),

    (re.compile(r"(\w{2,}:.*)"),  # remote URL, do nothing
     (lambda url: url),
     False),
)


def cygpath(path):
    """Use :meth:`git.cmd.Git.polish_url()` instead, that works on any environment."""
    if not path.startswith(('/cygdrive', '//')):
        for regex, parser, recurse in _cygpath_parsers:
            match = regex.match(path)
            if match:
                path = parser(*match.groups())
                if recurse:
                    path = cygpath(path)
                break
        else:
            path = _cygexpath(None, path)

    return path


_decygpath_regex = re.compile(r"/cygdrive/(\w)(/.*)?")


def decygpath(path):
    m = _decygpath_regex.match(path)
    if m:
        drive, rest_path = m.groups()
        path = '%s:%s' % (drive.upper(), rest_path or '')

    return path.replace('/', '\\')


#: Store boolean flags denoting if a specific Git executable
#: is from a Cygwin installation (since `cache_lru()` unsupported on PY2).
_is_cygwin_cache = {}


def is_cygwin_git(git_executable):
    if not is_win:
        return False

    #from subprocess import check_output

    is_cygwin = _is_cygwin_cache.get(git_executable)
    if is_cygwin is None:
        is_cygwin = False
        try:
            git_dir = osp.dirname(git_executable)
            if not git_dir:
                res = py_where(git_executable)
                git_dir = osp.dirname(res[0]) if res else None

            ## Just a name given, not a real path.
            uname_cmd = osp.join(git_dir, 'uname')
            process = subprocess.Popen([uname_cmd], stdout=subprocess.PIPE,
                                       universal_newlines=True)
            uname_out, _ = process.communicate()
            #retcode = process.poll()
            is_cygwin = 'CYGWIN' in uname_out
        except Exception as ex:
            log.debug('Failed checking if running in CYGWIN due to: %r', ex)
        _is_cygwin_cache[git_executable] = is_cygwin

    return is_cygwin


def get_user_id():
    """:return: string identifying the currently active system user as name@node"""
    return "%s@%s" % (getpass.getuser(), platform.node())


def finalize_process(proc, **kwargs):
    """Wait for the process (clone, fetch, pull or push) and handle its errors accordingly"""
    ## TODO: No close proc-streams??
    proc.wait(**kwargs)


def expand_path(p, expand_vars=True):
    try:
        p = osp.expanduser(p)
        if expand_vars:
            p = osp.expandvars(p)
        return osp.normpath(osp.abspath(p))
    except Exception:
        return None

#} END utilities

#{ Classes


class RemoteProgress(object):
    """
    Handler providing an interface to parse progress information emitted by git-push
    and git-fetch and to dispatch callbacks allowing subclasses to react to the progress.
    """
    _num_op_codes = 9
    BEGIN, END, COUNTING, COMPRESSING, WRITING, RECEIVING, RESOLVING, FINDING_SOURCES, CHECKING_OUT = \
        [1 << x for x in range(_num_op_codes)]
    STAGE_MASK = BEGIN | END
    OP_MASK = ~STAGE_MASK

    DONE_TOKEN = 'done.'
    TOKEN_SEPARATOR = ', '

    __slots__ = ('_cur_line',
                 '_seen_ops',
                 'error_lines',  # Lines that started with 'error:' or 'fatal:'.
                 'other_lines')  # Lines not denoting progress (i.e.g. push-infos).
    re_op_absolute = re.compile(r"(remote: )?([\w\s]+):\s+()(\d+)()(.*)")
    re_op_relative = re.compile(r"(remote: )?([\w\s]+):\s+(\d+)% \((\d+)/(\d+)\)(.*)")

    def __init__(self):
        self._seen_ops = list()
        self._cur_line = None
        self.error_lines = []
        self.other_lines = []

    def _parse_progress_line(self, line):
        """Parse progress information from the given line as retrieved by git-push
        or git-fetch.

        - Lines that do not contain progress info are stored in :attr:`other_lines`.
        - Lines that seem to contain an error (i.e. start with error: or fatal:) are stored
        in :attr:`error_lines`.

        :return: list(line, ...) list of lines that could not be processed"""
        # handle
        # Counting objects: 4, done.
        # Compressing objects:  50% (1/2)   \rCompressing objects: 100% (2/2)   \rCompressing objects: 100% (2/2), done.
        self._cur_line = line
        if len(self.error_lines) > 0 or self._cur_line.startswith(('error:', 'fatal:')):
            self.error_lines.append(self._cur_line)
            return []

        sub_lines = line.split('\r')
        failed_lines = list()
        for sline in sub_lines:
            # find escape characters and cut them away - regex will not work with
            # them as they are non-ascii. As git might expect a tty, it will send them
            last_valid_index = None
            for i, c in enumerate(reversed(sline)):
                if ord(c) < 32:
                    # its a slice index
                    last_valid_index = -i - 1
                # END character was non-ascii
            # END for each character in sline
            if last_valid_index is not None:
                sline = sline[:last_valid_index]
            # END cut away invalid part
            sline = sline.rstrip()

            cur_count, max_count = None, None
            match = self.re_op_relative.match(sline)
            if match is None:
                match = self.re_op_absolute.match(sline)

            if not match:
                self.line_dropped(sline)
                failed_lines.append(sline)
                continue
            # END could not get match

            op_code = 0
            remote, op_name, percent, cur_count, max_count, message = match.groups()  # @UnusedVariable

            # get operation id
            if op_name == "Counting objects":
                op_code |= self.COUNTING
            elif op_name == "Compressing objects":
                op_code |= self.COMPRESSING
            elif op_name == "Writing objects":
                op_code |= self.WRITING
            elif op_name == 'Receiving objects':
                op_code |= self.RECEIVING
            elif op_name == 'Resolving deltas':
                op_code |= self.RESOLVING
            elif op_name == 'Finding sources':
                op_code |= self.FINDING_SOURCES
            elif op_name == 'Checking out files':
                op_code |= self.CHECKING_OUT
            else:
                # Note: On windows it can happen that partial lines are sent
                # Hence we get something like "CompreReceiving objects", which is
                # a blend of "Compressing objects" and "Receiving objects".
                # This can't really be prevented, so we drop the line verbosely
                # to make sure we get informed in case the process spits out new
                # commands at some point.
                self.line_dropped(sline)
                # Note: Don't add this line to the failed lines, as we have to silently
                # drop it
                self.other_lines.extend(failed_lines)
                return failed_lines
            # END handle op code

            # figure out stage
            if op_code not in self._seen_ops:
                self._seen_ops.append(op_code)
                op_code |= self.BEGIN
            # END begin opcode

            if message is None:
                message = ''
            # END message handling

            message = message.strip()
            if message.endswith(self.DONE_TOKEN):
                op_code |= self.END
                message = message[:-len(self.DONE_TOKEN)]
            # END end message handling
            message = message.strip(self.TOKEN_SEPARATOR)

            self.update(op_code,
                        cur_count and float(cur_count),
                        max_count and float(max_count),
                        message)
        # END for each sub line
        self.other_lines.extend(failed_lines)
        return failed_lines

    def new_message_handler(self):
        """
        :return:
            a progress handler suitable for handle_process_output(), passing lines on to this Progress
            handler in a suitable format"""
        def handler(line):
            return self._parse_progress_line(line.rstrip())
        # end
        return handler

    def line_dropped(self, line):
        """Called whenever a line could not be understood and was therefore dropped."""
        pass

    def update(self, op_code, cur_count, max_count=None, message=''):
        """Called whenever the progress changes

        :param op_code:
            Integer allowing to be compared against Operation IDs and stage IDs.

            Stage IDs are BEGIN and END. BEGIN will only be set once for each Operation
            ID as well as END. It may be that BEGIN and END are set at once in case only
            one progress message was emitted due to the speed of the operation.
            Between BEGIN and END, none of these flags will be set

            Operation IDs are all held within the OP_MASK. Only one Operation ID will
            be active per call.
        :param cur_count: Current absolute count of items

        :param max_count:
            The maximum count of items we expect. It may be None in case there is
            no maximum number of items or if it is (yet) unknown.

        :param message:
            In case of the 'WRITING' operation, it contains the amount of bytes
            transferred. It may possibly be used for other purposes as well.

        You may read the contents of the current line in self._cur_line"""
        pass


class CallableRemoteProgress(RemoteProgress):
    """An implementation forwarding updates to any callable"""
    __slots__ = ('_callable')

    def __init__(self, fn):
        self._callable = fn
        super(CallableRemoteProgress, self).__init__()

    def update(self, *args, **kwargs):
        self._callable(*args, **kwargs)


class Actor(object):
    """Actors hold information about a person acting on the repository. They
    can be committers and authors or anything with a name and an email as
    mentioned in the git log entries."""
    # PRECOMPILED REGEX
    name_only_regex = re.compile(r'<(.+)>')
    name_email_regex = re.compile(r'(.*) <(.+?)>')

    # ENVIRONMENT VARIABLES
    # read when creating new commits
    env_author_name = "GIT_AUTHOR_NAME"
    env_author_email = "GIT_AUTHOR_EMAIL"
    env_committer_name = "GIT_COMMITTER_NAME"
    env_committer_email = "GIT_COMMITTER_EMAIL"

    # CONFIGURATION KEYS
    conf_name = 'name'
    conf_email = 'email'

    __slots__ = ('name', 'email')

    def __init__(self, name, email):
        self.name = name
        self.email = email

    def __eq__(self, other):
        return self.name == other.name and self.email == other.email

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.name, self.email))

    def __str__(self):
        return self.name

    def __repr__(self):
        return u'<git.Actor "%s <%s>">' % (self.name, self.email)

    @classmethod
    def _from_string(cls, string):
        """Create an Actor from a string.
        :param string: is the string, which is expected to be in regular git format

                John Doe <jdoe@example.com>

        :return: Actor """
        m = cls.name_email_regex.search(string)
        if m:
            name, email = m.groups()
            return Actor(name, email)
        else:
            m = cls.name_only_regex.search(string)
            if m:
                return Actor(m.group(1), None)
            else:
                # assume best and use the whole string as name
                return Actor(string, None)
            # END special case name
        # END handle name/email matching

    @classmethod
    def _main_actor(cls, env_name, env_email, config_reader=None):
        actor = Actor('', '')
        default_email = get_user_id()
        default_name = default_email.split('@')[0]

        for attr, evar, cvar, default in (('name', env_name, cls.conf_name, default_name),
                                          ('email', env_email, cls.conf_email, default_email)):
            try:
                val = os.environ[evar]
                if not PY3:
                    val = val.decode(defenc)
                # end assure we don't get 'invalid strings'
                setattr(actor, attr, val)
            except KeyError:
                if config_reader is not None:
                    setattr(actor, attr, config_reader.get_value('user', cvar, default))
                # END config-reader handling
                if not getattr(actor, attr):
                    setattr(actor, attr, default)
            # END handle name
        # END for each item to retrieve
        return actor

    @classmethod
    def committer(cls, config_reader=None):
        """
        :return: Actor instance corresponding to the configured committer. It behaves
            similar to the git implementation, such that the environment will override
            configuration values of config_reader. If no value is set at all, it will be
            generated
        :param config_reader: ConfigReader to use to retrieve the values from in case
            they are not set in the environment"""
        return cls._main_actor(cls.env_committer_name, cls.env_committer_email, config_reader)

    @classmethod
    def author(cls, config_reader=None):
        """Same as committer(), but defines the main author. It may be specified in the environment,
        but defaults to the committer"""
        return cls._main_actor(cls.env_author_name, cls.env_author_email, config_reader)


class Stats(object):

    """
    Represents stat information as presented by git at the end of a merge. It is
    created from the output of a diff operation.

    ``Example``::

     c = Commit( sha1 )
     s = c.stats
     s.total         # full-stat-dict
     s.files         # dict( filepath : stat-dict )

    ``stat-dict``

    A dictionary with the following keys and values::

      deletions = number of deleted lines as int
      insertions = number of inserted lines as int
      lines = total number of lines changed as int, or deletions + insertions

    ``full-stat-dict``

    In addition to the items in the stat-dict, it features additional information::

     files = number of changed files as int"""
    __slots__ = ("total", "files")

    def __init__(self, total, files):
        self.total = total
        self.files = files

    @classmethod
    def _list_from_string(cls, repo, text):
        """Create a Stat object from output retrieved by git-diff.

        :return: git.Stat"""
        hsh = {'total': {'insertions': 0, 'deletions': 0, 'lines': 0, 'files': 0}, 'files': dict()}
        for line in text.splitlines():
            (raw_insertions, raw_deletions, filename) = line.split("\t")
            insertions = raw_insertions != '-' and int(raw_insertions) or 0
            deletions = raw_deletions != '-' and int(raw_deletions) or 0
            hsh['total']['insertions'] += insertions
            hsh['total']['deletions'] += deletions
            hsh['total']['lines'] += insertions + deletions
            hsh['total']['files'] += 1
            hsh['files'][filename.strip()] = {'insertions': insertions,
                                              'deletions': deletions,
                                              'lines': insertions + deletions}
        return Stats(hsh['total'], hsh['files'])


class IndexFileSHA1Writer(object):

    """Wrapper around a file-like object that remembers the SHA1 of
    the data written to it. It will write a sha when the stream is closed
    or if the asked for explicitly using write_sha.

    Only useful to the indexfile

    :note: Based on the dulwich project"""
    __slots__ = ("f", "sha1")

    def __init__(self, f):
        self.f = f
        self.sha1 = make_sha(b"")

    def write(self, data):
        self.sha1.update(data)
        return self.f.write(data)

    def write_sha(self):
        sha = self.sha1.digest()
        self.f.write(sha)
        return sha

    def close(self):
        sha = self.write_sha()
        self.f.close()
        return sha

    def tell(self):
        return self.f.tell()


class LockFile(object):

    """Provides methods to obtain, check for, and release a file based lock which
    should be used to handle concurrent access to the same file.

    As we are a utility class to be derived from, we only use protected methods.

    Locks will automatically be released on destruction"""
    __slots__ = ("_file_path", "_owns_lock")

    def __init__(self, file_path):
        self._file_path = file_path
        self._owns_lock = False

    def __del__(self):
        self._release_lock()

    def _lock_file_path(self):
        """:return: Path to lockfile"""
        return "%s.lock" % (self._file_path)

    def _has_lock(self):
        """:return: True if we have a lock and if the lockfile still exists
        :raise AssertionError: if our lock-file does not exist"""
        return self._owns_lock

    def _obtain_lock_or_raise(self):
        """Create a lock file as flag for other instances, mark our instance as lock-holder

        :raise IOError: if a lock was already present or a lock file could not be written"""
        if self._has_lock():
            return
        lock_file = self._lock_file_path()
        if osp.isfile(lock_file):
            raise IOError("Lock for file %r did already exist, delete %r in case the lock is illegal" %
                          (self._file_path, lock_file))

        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if is_win:
                flags |= os.O_SHORT_LIVED
            fd = os.open(lock_file, flags, 0)
            os.close(fd)
        except OSError as e:
            raise IOError(str(e))

        self._owns_lock = True

    def _obtain_lock(self):
        """The default implementation will raise if a lock cannot be obtained.
        Subclasses may override this method to provide a different implementation"""
        return self._obtain_lock_or_raise()

    def _release_lock(self):
        """Release our lock if we have one"""
        if not self._has_lock():
            return

        # if someone removed our file beforhand, lets just flag this issue
        # instead of failing, to make it more usable.
        lfp = self._lock_file_path()
        try:
            rmfile(lfp)
        except OSError:
            pass
        self._owns_lock = False


class BlockingLockFile(LockFile):

    """The lock file will block until a lock could be obtained, or fail after
    a specified timeout.

    :note: If the directory containing the lock was removed, an exception will
        be raised during the blocking period, preventing hangs as the lock
        can never be obtained."""
    __slots__ = ("_check_interval", "_max_block_time")

    def __init__(self, file_path, check_interval_s=0.3, max_block_time_s=MAXSIZE):
        """Configure the instance

        :parm check_interval_s:
            Period of time to sleep until the lock is checked the next time.
            By default, it waits a nearly unlimited time

        :parm max_block_time_s: Maximum amount of seconds we may lock"""
        super(BlockingLockFile, self).__init__(file_path)
        self._check_interval = check_interval_s
        self._max_block_time = max_block_time_s

    def _obtain_lock(self):
        """This method blocks until it obtained the lock, or raises IOError if
        it ran out of time or if the parent directory was not available anymore.
        If this method returns, you are guaranteed to own the lock"""
        starttime = time.time()
        maxtime = starttime + float(self._max_block_time)
        while True:
            try:
                super(BlockingLockFile, self)._obtain_lock()
            except IOError:
                # synity check: if the directory leading to the lockfile is not
                # readable anymore, raise an exception
                curtime = time.time()
                if not osp.isdir(osp.dirname(self._lock_file_path())):
                    msg = "Directory containing the lockfile %r was not readable anymore after waiting %g seconds" % (
                        self._lock_file_path(), curtime - starttime)
                    raise IOError(msg)
                # END handle missing directory

                if curtime >= maxtime:
                    msg = "Waited %g seconds for lock at %r" % (maxtime - starttime, self._lock_file_path())
                    raise IOError(msg)
                # END abort if we wait too long
                time.sleep(self._check_interval)
            else:
                break
        # END endless loop


class IterableList(list):

    """
    List of iterable objects allowing to query an object by id or by named index::

     heads = repo.heads
     heads.master
     heads['master']
     heads[0]

    It requires an id_attribute name to be set which will be queried from its
    contained items to have a means for comparison.

    A prefix can be specified which is to be used in case the id returned by the
    items always contains a prefix that does not matter to the user, so it
    can be left out."""
    __slots__ = ('_id_attr', '_prefix')

    def __new__(cls, id_attr, prefix=''):
        return super(IterableList, cls).__new__(cls)

    def __init__(self, id_attr, prefix=''):
        self._id_attr = id_attr
        self._prefix = prefix

    def __contains__(self, attr):
        # first try identity match for performance
        rval = list.__contains__(self, attr)
        if rval:
            return rval
        # END handle match

        # otherwise make a full name search
        try:
            getattr(self, attr)
            return True
        except (AttributeError, TypeError):
            return False
        # END handle membership

    def __getattr__(self, attr):
        attr = self._prefix + attr
        for item in self:
            if getattr(item, self._id_attr) == attr:
                return item
        # END for each item
        return list.__getattribute__(self, attr)

    def __getitem__(self, index):
        if isinstance(index, int):
            return list.__getitem__(self, index)

        try:
            return getattr(self, index)
        except AttributeError:
            raise IndexError("No item found with id %r" % (self._prefix + index))
        # END handle getattr

    def __delitem__(self, index):
        delindex = index
        if not isinstance(index, int):
            delindex = -1
            name = self._prefix + index
            for i, item in enumerate(self):
                if getattr(item, self._id_attr) == name:
                    delindex = i
                    break
                # END search index
            # END for each item
            if delindex == -1:
                raise IndexError("Item with name %s not found" % name)
            # END handle error
        # END get index to delete
        list.__delitem__(self, delindex)


class Iterable(object):

    """Defines an interface for iterable items which is to assure a uniform
    way to retrieve and iterate items within the git repository"""
    __slots__ = tuple()
    _id_attribute_ = "attribute that most suitably identifies your instance"

    @classmethod
    def list_items(cls, repo, *args, **kwargs):
        """
        Find all items of this type - subclasses can specify args and kwargs differently.
        If no args are given, subclasses are obliged to return all items if no additional
        arguments arg given.

        :note: Favor the iter_items method as it will

        :return:list(Item,...) list of item instances"""
        out_list = IterableList(cls._id_attribute_)
        out_list.extend(cls.iter_items(repo, *args, **kwargs))
        return out_list

    @classmethod
    def iter_items(cls, repo, *args, **kwargs):
        """For more information about the arguments, see list_items
        :return:  iterator yielding Items"""
        raise NotImplementedError("To be implemented by Subclass")

#} END classes


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


# In Python 2.6, there is no NullHandler yet. Let's monkey-patch it for a workaround.
if not hasattr(logging, 'NullHandler'):
    logging.NullHandler = NullHandler
