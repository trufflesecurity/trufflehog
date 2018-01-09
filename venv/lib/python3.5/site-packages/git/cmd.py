# cmd.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from contextlib import contextmanager
import io
import logging
import os
import signal
from subprocess import (
    call,
    Popen,
    PIPE
)
import subprocess
import sys
import threading
from textwrap import dedent

from git.compat import (
    string_types,
    defenc,
    force_bytes,
    PY3,
    # just to satisfy flake8 on py3
    unicode,
    safe_decode,
    is_posix,
    is_win,
)
from git.exc import CommandError
from git.odict import OrderedDict
from git.util import is_cygwin_git, cygpath, expand_path

from .exc import (
    GitCommandError,
    GitCommandNotFound
)
from .util import (
    LazyMixin,
    stream_copy,
)


execute_kwargs = set(('istream', 'with_extended_output',
                      'with_exceptions', 'as_process', 'stdout_as_string',
                      'output_stream', 'with_stdout', 'kill_after_timeout',
                      'universal_newlines', 'shell', 'env'))

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

__all__ = ('Git',)


# ==============================================================================
## @name Utilities
# ------------------------------------------------------------------------------
# Documentation
## @{

def handle_process_output(process, stdout_handler, stderr_handler,
                          finalizer=None, decode_streams=True):
    """Registers for notifications to lean that process output is ready to read, and dispatches lines to
    the respective line handlers.
    This function returns once the finalizer returns

    :return: result of finalizer
    :param process: subprocess.Popen instance
    :param stdout_handler: f(stdout_line_string), or None
    :param stderr_handler: f(stderr_line_string), or None
    :param finalizer: f(proc) - wait for proc to finish
    :param decode_streams:
        Assume stdout/stderr streams are binary and decode them before pushing \
        their contents to handlers.
        Set it to False if `universal_newline == True` (then streams are in text-mode)
        or if decoding must happen later (i.e. for Diffs).
    """
    # Use 2 "pupm" threads and wait for both to finish.
    def pump_stream(cmdline, name, stream, is_decode, handler):
        try:
            for line in stream:
                if handler:
                    if is_decode:
                        line = line.decode(defenc)
                    handler(line)
        except Exception as ex:
            log.error("Pumping %r of cmd(%s) failed due to: %r", name, cmdline, ex)
            raise CommandError(['<%s-pump>' % name] + cmdline, ex)
        finally:
            stream.close()

    cmdline = getattr(process, 'args', '')  # PY3+ only
    if not isinstance(cmdline, (tuple, list)):
        cmdline = cmdline.split()

    pumps = []
    if process.stdout:
        pumps.append(('stdout', process.stdout, stdout_handler))
    if process.stderr:
        pumps.append(('stderr', process.stderr, stderr_handler))

    threads = []

    for name, stream, handler in pumps:
        t = threading.Thread(target=pump_stream,
                             args=(cmdline, name, stream, decode_streams, handler))
        t.setDaemon(True)
        t.start()
        threads.append(t)

    ## FIXME: Why Join??  Will block if `stdin` needs feeding...
    #
    for t in threads:
        t.join()

    if finalizer:
        return finalizer(process)


def dashify(string):
    return string.replace('_', '-')


def slots_to_dict(self, exclude=()):
    return dict((s, getattr(self, s)) for s in self.__slots__ if s not in exclude)


def dict_to_slots_and__excluded_are_none(self, d, excluded=()):
    for k, v in d.items():
        setattr(self, k, v)
    for k in excluded:
        setattr(self, k, None)

## -- End Utilities -- @}


# value of Windows process creation flag taken from MSDN
CREATE_NO_WINDOW = 0x08000000

## CREATE_NEW_PROCESS_GROUP is needed to allow killing it afterwards,
# see https://docs.python.org/3/library/subprocess.html#subprocess.Popen.send_signal
PROC_CREATIONFLAGS = (CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                      if is_win and sys.version_info >= (2, 7)
                      else 0)


class Git(LazyMixin):

    """
    The Git class manages communication with the Git binary.

    It provides a convenient interface to calling the Git binary, such as in::

     g = Git( git_dir )
     g.init()                   # calls 'git init' program
     rval = g.ls_files()        # calls 'git ls-files' program

    ``Debugging``
        Set the GIT_PYTHON_TRACE environment variable print each invocation
        of the command to stdout.
        Set its value to 'full' to see details about the returned values.
    """
    __slots__ = ("_working_dir", "cat_file_all", "cat_file_header", "_version_info",
                 "_git_options", "_persistent_git_options", "_environment")

    _excluded_ = ('cat_file_all', 'cat_file_header', '_version_info')

    def __getstate__(self):
        return slots_to_dict(self, exclude=self._excluded_)

    def __setstate__(self, d):
        dict_to_slots_and__excluded_are_none(self, d, excluded=self._excluded_)

    # CONFIGURATION
    # The size in bytes read from stdout when copying git's output to another stream
    max_chunk_size = io.DEFAULT_BUFFER_SIZE

    git_exec_name = "git"           # default that should work on linux and windows

    # Enables debugging of GitPython's git commands
    GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

    # If True, a shell will be used when executing git commands.
    # This should only be desirable on Windows, see https://github.com/gitpython-developers/GitPython/pull/126
    # and check `git/test_repo.py:TestRepo.test_untracked_files()` TC for an example where it is required.
    # Override this value using `Git.USE_SHELL = True`
    USE_SHELL = False

    # Provide the full path to the git executable. Otherwise it assumes git is in the path
    _git_exec_env_var = "GIT_PYTHON_GIT_EXECUTABLE"
    _refresh_env_var = "GIT_PYTHON_REFRESH"
    GIT_PYTHON_GIT_EXECUTABLE = None
    # note that the git executable is actually found during the refresh step in
    # the top level __init__

    @classmethod
    def refresh(cls, path=None):
        """This gets called by the refresh function (see the top level
        __init__).
        """
        # discern which path to refresh with
        if path is not None:
            new_git = os.path.expanduser(path)
            new_git = os.path.abspath(new_git)
        else:
            new_git = os.environ.get(cls._git_exec_env_var, cls.git_exec_name)

        # keep track of the old and new git executable path
        old_git = cls.GIT_PYTHON_GIT_EXECUTABLE
        cls.GIT_PYTHON_GIT_EXECUTABLE = new_git

        # test if the new git executable path is valid

        if sys.version_info < (3,):
            # - a GitCommandNotFound error is spawned by ourselves
            # - a OSError is spawned if the git executable provided
            #   cannot be executed for whatever reason
            exceptions = (GitCommandNotFound, OSError)
        else:
            # - a GitCommandNotFound error is spawned by ourselves
            # - a PermissionError is spawned if the git executable provided
            #   cannot be executed for whatever reason
            exceptions = (GitCommandNotFound, PermissionError)

        has_git = False
        try:
            cls().version()
            has_git = True
        except exceptions:
            pass

        # warn or raise exception if test failed
        if not has_git:
            err = dedent("""\
                Bad git executable.
                The git executable must be specified in one of the following ways:
                    - be included in your $PATH
                    - be set via $%s
                    - explicitly set via git.refresh()
                """) % cls._git_exec_env_var

            # revert to whatever the old_git was
            cls.GIT_PYTHON_GIT_EXECUTABLE = old_git

            if old_git is None:
                # on the first refresh (when GIT_PYTHON_GIT_EXECUTABLE is
                # None) we only are quiet, warn, or error depending on the
                # GIT_PYTHON_REFRESH value

                # determine what the user wants to happen during the initial
                # refresh we expect GIT_PYTHON_REFRESH to either be unset or
                # be one of the following values:
                #   0|q|quiet|s|silence
                #   1|w|warn|warning
                #   2|r|raise|e|error

                mode = os.environ.get(cls._refresh_env_var, "raise").lower()

                quiet = ["quiet", "q", "silence", "s", "none", "n", "0"]
                warn = ["warn", "w", "warning", "1"]
                error = ["error", "e", "raise", "r", "2"]

                if mode in quiet:
                    pass
                elif mode in warn or mode in error:
                    err = dedent("""\
                        %s
                        All git commands will error until this is rectified.

                        This initial warning can be silenced or aggravated in the future by setting the
                        $%s environment variable. Use one of the following values:
                            - %s: for no warning or exception
                            - %s: for a printed warning
                            - %s: for a raised exception

                        Example:
                            export %s=%s
                        """) % (
                        err,
                        cls._refresh_env_var,
                        "|".join(quiet),
                        "|".join(warn),
                        "|".join(error),
                        cls._refresh_env_var,
                        quiet[0])

                    if mode in warn:
                        print("WARNING: %s" % err)
                    else:
                        raise ImportError(err)
                else:
                    err = dedent("""\
                        %s environment variable has been set but it has been set with an invalid value.

                        Use only the following values:
                            - %s: for no warning or exception
                            - %s: for a printed warning
                            - %s: for a raised exception
                        """) % (
                        cls._refresh_env_var,
                        "|".join(quiet),
                        "|".join(warn),
                        "|".join(error))
                    raise ImportError(err)

                # we get here if this was the init refresh and the refresh mode
                # was not error, go ahead and set the GIT_PYTHON_GIT_EXECUTABLE
                # such that we discern the difference between a first import
                # and a second import
                cls.GIT_PYTHON_GIT_EXECUTABLE = cls.git_exec_name
            else:
                # after the first refresh (when GIT_PYTHON_GIT_EXECUTABLE
                # is no longer None) we raise an exception
                raise GitCommandNotFound("git", err)

        return has_git

    @classmethod
    def is_cygwin(cls):
        return is_cygwin_git(cls.GIT_PYTHON_GIT_EXECUTABLE)

    @classmethod
    def polish_url(cls, url, is_cygwin=None):
        if is_cygwin is None:
            is_cygwin = cls.is_cygwin()

        if is_cygwin:
            url = cygpath(url)
        else:
            """Remove any backslahes from urls to be written in config files.

            Windows might create config-files containing paths with backslashed,
            but git stops liking them as it will escape the backslashes.
            Hence we undo the escaping just to be sure.
            """
            url = url.replace("\\\\", "\\").replace("\\", "/")

        return url

    class AutoInterrupt(object):
        """Kill/Interrupt the stored process instance once this instance goes out of scope. It is
        used to prevent processes piling up in case iterators stop reading.
        Besides all attributes are wired through to the contained process object.

        The wait method was overridden to perform automatic status code checking
        and possibly raise."""

        __slots__ = ("proc", "args")

        def __init__(self, proc, args):
            self.proc = proc
            self.args = args

        def __del__(self):
            if self.proc is None:
                return

            proc = self.proc
            self.proc = None
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

            # did the process finish already so we have a return code ?
            if proc.poll() is not None:
                return

            # can be that nothing really exists anymore ...
            if os is None or getattr(os, 'kill', None) is None:
                return

            # try to kill it
            try:
                proc.terminate()
                proc.wait()    # ensure process goes away
            except OSError as ex:
                log.info("Ignored error after process had died: %r", ex)
                pass  # ignore error when process already died
            except AttributeError:
                # try windows
                # for some reason, providing None for stdout/stderr still prints something. This is why
                # we simply use the shell and redirect to nul. Its slower than CreateProcess, question
                # is whether we really want to see all these messages. Its annoying no matter what.
                if is_win:
                    call(("TASKKILL /F /T /PID %s 2>nul 1>nul" % str(proc.pid)), shell=True)
            # END exception handling

        def __getattr__(self, attr):
            return getattr(self.proc, attr)

        def wait(self, stderr=b''):  # TODO: Bad choice to mimic `proc.wait()` but with different args.
            """Wait for the process and return its status code.

            :param stderr: Previously read value of stderr, in case stderr is already closed.
            :warn: may deadlock if output or error pipes are used and not handled separately.
            :raise GitCommandError: if the return status is not 0"""
            if stderr is None:
                stderr = b''
            stderr = force_bytes(stderr)

            status = self.proc.wait()

            def read_all_from_possibly_closed_stream(stream):
                try:
                    return stderr + force_bytes(stream.read())
                except ValueError:
                    return stderr or b''

            if status != 0:
                errstr = read_all_from_possibly_closed_stream(self.proc.stderr)
                log.debug('AutoInterrupt wait stderr: %r' % (errstr,))
                raise GitCommandError(self.args, status, errstr)
            # END status handling
            return status
    # END auto interrupt

    class CatFileContentStream(object):

        """Object representing a sized read-only stream returning the contents of
        an object.
        It behaves like a stream, but counts the data read and simulates an empty
        stream once our sized content region is empty.
        If not all data is read to the end of the objects's lifetime, we read the
        rest to assure the underlying stream continues to work"""

        __slots__ = ('_stream', '_nbr', '_size')

        def __init__(self, size, stream):
            self._stream = stream
            self._size = size
            self._nbr = 0           # num bytes read

            # special case: if the object is empty, has null bytes, get the
            # final newline right away.
            if size == 0:
                stream.read(1)
            # END handle empty streams

        def read(self, size=-1):
            bytes_left = self._size - self._nbr
            if bytes_left == 0:
                return b''
            if size > -1:
                # assure we don't try to read past our limit
                size = min(bytes_left, size)
            else:
                # they try to read all, make sure its not more than what remains
                size = bytes_left
            # END check early depletion
            data = self._stream.read(size)
            self._nbr += len(data)

            # check for depletion, read our final byte to make the stream usable by others
            if self._size - self._nbr == 0:
                self._stream.read(1)    # final newline
            # END finish reading
            return data

        def readline(self, size=-1):
            if self._nbr == self._size:
                return b''

            # clamp size to lowest allowed value
            bytes_left = self._size - self._nbr
            if size > -1:
                size = min(bytes_left, size)
            else:
                size = bytes_left
            # END handle size

            data = self._stream.readline(size)
            self._nbr += len(data)

            # handle final byte
            if self._size - self._nbr == 0:
                self._stream.read(1)
            # END finish reading

            return data

        def readlines(self, size=-1):
            if self._nbr == self._size:
                return list()

            # leave all additional logic to our readline method, we just check the size
            out = list()
            nbr = 0
            while True:
                line = self.readline()
                if not line:
                    break
                out.append(line)
                if size > -1:
                    nbr += len(line)
                    if nbr > size:
                        break
                # END handle size constraint
            # END readline loop
            return out

        def __iter__(self):
            return self

        def next(self):
            line = self.readline()
            if not line:
                raise StopIteration

            return line

        def __del__(self):
            bytes_left = self._size - self._nbr
            if bytes_left:
                # read and discard - seeking is impossible within a stream
                # includes terminating newline
                self._stream.read(bytes_left + 1)
            # END handle incomplete read

    def __init__(self, working_dir=None):
        """Initialize this instance with:

        :param working_dir:
           Git directory we should work in. If None, we always work in the current
           directory as returned by os.getcwd().
           It is meant to be the working tree directory if available, or the
           .git directory in case of bare repositories."""
        super(Git, self).__init__()
        self._working_dir = expand_path(working_dir)
        self._git_options = ()
        self._persistent_git_options = []

        # Extra environment variables to pass to git commands
        self._environment = {}

        # cached command slots
        self.cat_file_header = None
        self.cat_file_all = None

    def __getattr__(self, name):
        """A convenience method as it allows to call the command as if it was
        an object.
        :return: Callable object that will execute call _call_process with your arguments."""
        if name[0] == '_':
            return LazyMixin.__getattr__(self, name)
        return lambda *args, **kwargs: self._call_process(name, *args, **kwargs)

    def set_persistent_git_options(self, **kwargs):
        """Specify command line options to the git executable
        for subsequent subcommand calls

        :param kwargs:
            is a dict of keyword arguments.
            these arguments are passed as in _call_process
            but will be passed to the git command rather than
            the subcommand.
        """

        self._persistent_git_options = self.transform_kwargs(
            split_single_char_options=True, **kwargs)

    def _set_cache_(self, attr):
        if attr == '_version_info':
            # We only use the first 4 numbers, as everything else could be strings in fact (on windows)
            version_numbers = self._call_process('version').split(' ')[2]
            self._version_info = tuple(int(n) for n in version_numbers.split('.')[:4] if n.isdigit())
        else:
            super(Git, self)._set_cache_(attr)
        # END handle version info

    @property
    def working_dir(self):
        """:return: Git directory we are working on"""
        return self._working_dir

    @property
    def version_info(self):
        """
        :return: tuple(int, int, int, int) tuple with integers representing the major, minor
            and additional version numbers as parsed from git version.
            This value is generated on demand and is cached"""
        return self._version_info

    def execute(self, command,
                istream=None,
                with_extended_output=False,
                with_exceptions=True,
                as_process=False,
                output_stream=None,
                stdout_as_string=True,
                kill_after_timeout=None,
                with_stdout=True,
                universal_newlines=False,
                shell=None,
                env=None,
                **subprocess_kwargs
                ):
        """Handles executing the command on the shell and consumes and returns
        the returned information (stdout)

        :param command:
            The command argument list to execute.
            It should be a string, or a sequence of program arguments. The
            program to execute is the first item in the args sequence or string.

        :param istream:
            Standard input filehandle passed to subprocess.Popen.

        :param with_extended_output:
            Whether to return a (status, stdout, stderr) tuple.

        :param with_exceptions:
            Whether to raise an exception when git returns a non-zero status.

        :param as_process:
            Whether to return the created process instance directly from which
            streams can be read on demand. This will render with_extended_output and
            with_exceptions ineffective - the caller will have
            to deal with the details himself.
            It is important to note that the process will be placed into an AutoInterrupt
            wrapper that will interrupt the process once it goes out of scope. If you
            use the command in iterators, you should pass the whole process instance
            instead of a single stream.

        :param output_stream:
            If set to a file-like object, data produced by the git command will be
            output to the given stream directly.
            This feature only has any effect if as_process is False. Processes will
            always be created with a pipe due to issues with subprocess.
            This merely is a workaround as data will be copied from the
            output pipe to the given output stream directly.
            Judging from the implementation, you shouldn't use this flag !

        :param stdout_as_string:
            if False, the commands standard output will be bytes. Otherwise, it will be
            decoded into a string using the default encoding (usually utf-8).
            The latter can fail, if the output contains binary data.

        :param env:
            A dictionary of environment variables to be passed to `subprocess.Popen`.

        :param subprocess_kwargs:
            Keyword arguments to be passed to subprocess.Popen. Please note that
            some of the valid kwargs are already set by this method, the ones you
            specify may not be the same ones.

        :param with_stdout: If True, default True, we open stdout on the created process
        :param universal_newlines:
            if True, pipes will be opened as text, and lines are split at
            all known line endings.
        :param shell:
            Whether to invoke commands through a shell (see `Popen(..., shell=True)`).
            It overrides :attr:`USE_SHELL` if it is not `None`.
        :param kill_after_timeout:
            To specify a timeout in seconds for the git command, after which the process
            should be killed. This will have no effect if as_process is set to True. It is
            set to None by default and will let the process run until the timeout is
            explicitly specified. This feature is not supported on Windows. It's also worth
            noting that kill_after_timeout uses SIGKILL, which can have negative side
            effects on a repository. For example, stale locks in case of git gc could
            render the repository incapable of accepting changes until the lock is manually
            removed.

        :return:
            * str(output) if extended_output = False (Default)
            * tuple(int(status), str(stdout), str(stderr)) if extended_output = True

            if output_stream is True, the stdout value will be your output stream:
            * output_stream if extended_output = False
            * tuple(int(status), output_stream, str(stderr)) if extended_output = True

            Note git is executed with LC_MESSAGES="C" to ensure consistent
            output regardless of system language.

        :raise GitCommandError:

        :note:
           If you add additional keyword arguments to the signature of this method,
           you must update the execute_kwargs tuple housed in this module."""
        if self.GIT_PYTHON_TRACE and (self.GIT_PYTHON_TRACE != 'full' or as_process):
            log.info(' '.join(command))

        # Allow the user to have the command executed in their working dir.
        cwd = self._working_dir or os.getcwd()

        # Start the process
        inline_env = env
        env = os.environ.copy()
        # Attempt to force all output to plain ascii english, which is what some parsing code
        # may expect.
        # According to stackoverflow (http://goo.gl/l74GC8), we are setting LANGUAGE as well
        # just to be sure.
        env["LANGUAGE"] = "C"
        env["LC_ALL"] = "C"
        env.update(self._environment)
        if inline_env is not None:
            env.update(inline_env)

        if is_win:
            cmd_not_found_exception = OSError
            if kill_after_timeout:
                raise GitCommandError(command, '"kill_after_timeout" feature is not supported on Windows.')
        else:
            if sys.version_info[0] > 2:
                cmd_not_found_exception = FileNotFoundError  # NOQA # exists, flake8 unknown @UndefinedVariable
            else:
                cmd_not_found_exception = OSError
        # end handle

        stdout_sink = (PIPE
                       if with_stdout
                       else getattr(subprocess, 'DEVNULL', None) or open(os.devnull, 'wb'))
        log.debug("Popen(%s, cwd=%s, universal_newlines=%s, shell=%s)",
                  command, cwd, universal_newlines, shell)
        try:
            proc = Popen(command,
                         env=env,
                         cwd=cwd,
                         bufsize=-1,
                         stdin=istream,
                         stderr=PIPE,
                         stdout=stdout_sink,
                         shell=shell is not None and shell or self.USE_SHELL,
                         close_fds=is_posix,  # unsupported on windows
                         universal_newlines=universal_newlines,
                         creationflags=PROC_CREATIONFLAGS,
                         **subprocess_kwargs
                         )
        except cmd_not_found_exception as err:
            raise GitCommandNotFound(command, err)

        if as_process:
            return self.AutoInterrupt(proc, command)

        def _kill_process(pid):
            """ Callback method to kill a process. """
            p = Popen(['ps', '--ppid', str(pid)], stdout=PIPE,
                      creationflags=PROC_CREATIONFLAGS)
            child_pids = []
            for line in p.stdout:
                if len(line.split()) > 0:
                    local_pid = (line.split())[0]
                    if local_pid.isdigit():
                        child_pids.append(int(local_pid))
            try:
                # Windows does not have SIGKILL, so use SIGTERM instead
                sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
                os.kill(pid, sig)
                for child_pid in child_pids:
                    try:
                        os.kill(child_pid, sig)
                    except OSError:
                        pass
                kill_check.set()    # tell the main routine that the process was killed
            except OSError:
                # It is possible that the process gets completed in the duration after timeout
                # happens and before we try to kill the process.
                pass
            return
        # end

        if kill_after_timeout:
            kill_check = threading.Event()
            watchdog = threading.Timer(kill_after_timeout, _kill_process, args=(proc.pid,))

        # Wait for the process to return
        status = 0
        stdout_value = b''
        stderr_value = b''
        try:
            if output_stream is None:
                if kill_after_timeout:
                    watchdog.start()
                stdout_value, stderr_value = proc.communicate()
                if kill_after_timeout:
                    watchdog.cancel()
                    if kill_check.isSet():
                        stderr_value = ('Timeout: the command "%s" did not complete in %d '
                                        'secs.' % (" ".join(command), kill_after_timeout)).encode(defenc)
                # strip trailing "\n"
                if stdout_value.endswith(b"\n"):
                    stdout_value = stdout_value[:-1]
                if stderr_value.endswith(b"\n"):
                    stderr_value = stderr_value[:-1]
                status = proc.returncode
            else:
                stream_copy(proc.stdout, output_stream, self.max_chunk_size)
                stdout_value = output_stream
                stderr_value = proc.stderr.read()
                # strip trailing "\n"
                if stderr_value.endswith(b"\n"):
                    stderr_value = stderr_value[:-1]
                status = proc.wait()
            # END stdout handling
        finally:
            proc.stdout.close()
            proc.stderr.close()

        if self.GIT_PYTHON_TRACE == 'full':
            cmdstr = " ".join(command)

            def as_text(stdout_value):
                return not output_stream and safe_decode(stdout_value) or '<OUTPUT_STREAM>'
            # end

            if stderr_value:
                log.info("%s -> %d; stdout: '%s'; stderr: '%s'",
                         cmdstr, status, as_text(stdout_value), safe_decode(stderr_value))
            elif stdout_value:
                log.info("%s -> %d; stdout: '%s'", cmdstr, status, as_text(stdout_value))
            else:
                log.info("%s -> %d", cmdstr, status)
        # END handle debug printing

        if with_exceptions and status != 0:
            raise GitCommandError(command, status, stderr_value, stdout_value)

        if isinstance(stdout_value, bytes) and stdout_as_string:  # could also be output_stream
            stdout_value = safe_decode(stdout_value)

        # Allow access to the command's status code
        if with_extended_output:
            return (status, stdout_value, safe_decode(stderr_value))
        else:
            return stdout_value

    def environment(self):
        return self._environment

    def update_environment(self, **kwargs):
        """
        Set environment variables for future git invocations. Return all changed
        values in a format that can be passed back into this function to revert
        the changes:

        ``Examples``::

            old_env = self.update_environment(PWD='/tmp')
            self.update_environment(**old_env)

        :param kwargs: environment variables to use for git processes
        :return: dict that maps environment variables to their old values
        """
        old_env = {}
        for key, value in kwargs.items():
            # set value if it is None
            if value is not None:
                old_env[key] = self._environment.get(key)
                self._environment[key] = value
            # remove key from environment if its value is None
            elif key in self._environment:
                old_env[key] = self._environment[key]
                del self._environment[key]
        return old_env

    @contextmanager
    def custom_environment(self, **kwargs):
        """
        A context manager around the above ``update_environment`` method to restore the
        environment back to its previous state after operation.

        ``Examples``::

            with self.custom_environment(GIT_SSH='/bin/ssh_wrapper'):
                repo.remotes.origin.fetch()

        :param kwargs: see update_environment
        """
        old_env = self.update_environment(**kwargs)
        try:
            yield
        finally:
            self.update_environment(**old_env)

    def transform_kwarg(self, name, value, split_single_char_options):
        if len(name) == 1:
            if value is True:
                return ["-%s" % name]
            elif type(value) is not bool:
                if split_single_char_options:
                    return ["-%s" % name, "%s" % value]
                else:
                    return ["-%s%s" % (name, value)]
        else:
            if value is True:
                return ["--%s" % dashify(name)]
            elif type(value) is not bool:
                return ["--%s=%s" % (dashify(name), value)]
        return []

    def transform_kwargs(self, split_single_char_options=True, **kwargs):
        """Transforms Python style kwargs into git command line options."""
        args = list()
        kwargs = OrderedDict(sorted(kwargs.items(), key=lambda x: x[0]))
        for k, v in kwargs.items():
            if isinstance(v, (list, tuple)):
                for value in v:
                    args += self.transform_kwarg(k, value, split_single_char_options)
            else:
                args += self.transform_kwarg(k, v, split_single_char_options)
        return args

    @classmethod
    def __unpack_args(cls, arg_list):
        if not isinstance(arg_list, (list, tuple)):
            # This is just required for unicode conversion, as subprocess can't handle it
            # However, in any other case, passing strings (usually utf-8 encoded) is totally fine
            if not PY3 and isinstance(arg_list, unicode):
                return [arg_list.encode(defenc)]
            return [str(arg_list)]

        outlist = list()
        for arg in arg_list:
            if isinstance(arg_list, (list, tuple)):
                outlist.extend(cls.__unpack_args(arg))
            elif not PY3 and isinstance(arg_list, unicode):
                outlist.append(arg_list.encode(defenc))
            # END recursion
            else:
                outlist.append(str(arg))
        # END for each arg
        return outlist

    def __call__(self, **kwargs):
        """Specify command line options to the git executable
        for a subcommand call

        :param kwargs:
            is a dict of keyword arguments.
            these arguments are passed as in _call_process
            but will be passed to the git command rather than
            the subcommand.

        ``Examples``::
            git(work_tree='/tmp').difftool()"""
        self._git_options = self.transform_kwargs(
            split_single_char_options=True, **kwargs)
        return self

    def _call_process(self, method, *args, **kwargs):
        """Run the given git command with the specified arguments and return
        the result as a String

        :param method:
            is the command. Contained "_" characters will be converted to dashes,
            such as in 'ls_files' to call 'ls-files'.

        :param args:
            is the list of arguments. If None is included, it will be pruned.
            This allows your commands to call git more conveniently as None
            is realized as non-existent

        :param kwargs:
            It contains key-values for the following:
            - the :meth:`execute()` kwds, as listed in :var:`execute_kwargs`;
            - "command options" to be converted by :meth:`transform_kwargs()`;
            - the `'insert_kwargs_after'` key which its value must match one of ``*args``,
              and any cmd-options will be appended after the matched arg.

        Examples::

            git.rev_list('master', max_count=10, header=True)

        turns into::

           git rev-list max-count 10 --header master

        :return: Same as ``execute``"""
        # Handle optional arguments prior to calling transform_kwargs
        # otherwise these'll end up in args, which is bad.
        exec_kwargs = dict((k, v) for k, v in kwargs.items() if k in execute_kwargs)
        opts_kwargs = dict((k, v) for k, v in kwargs.items() if k not in execute_kwargs)

        insert_after_this_arg = opts_kwargs.pop('insert_kwargs_after', None)

        # Prepare the argument list
        opt_args = self.transform_kwargs(**opts_kwargs)
        ext_args = self.__unpack_args([a for a in args if a is not None])

        if insert_after_this_arg is None:
            args = opt_args + ext_args
        else:
            try:
                index = ext_args.index(insert_after_this_arg)
            except ValueError:
                raise ValueError("Couldn't find argument '%s' in args %s to insert cmd options after"
                                 % (insert_after_this_arg, str(ext_args)))
            # end handle error
            args = ext_args[:index + 1] + opt_args + ext_args[index + 1:]
        # end handle opts_kwargs

        call = [self.GIT_PYTHON_GIT_EXECUTABLE]

        # add persistent git options
        call.extend(self._persistent_git_options)

        # add the git options, then reset to empty
        # to avoid side_effects
        call.extend(self._git_options)
        self._git_options = ()

        call.append(dashify(method))
        call.extend(args)

        return self.execute(call, **exec_kwargs)

    def _parse_object_header(self, header_line):
        """
        :param header_line:
            <hex_sha> type_string size_as_int

        :return: (hex_sha, type_string, size_as_int)

        :raise ValueError: if the header contains indication for an error due to
            incorrect input sha"""
        tokens = header_line.split()
        if len(tokens) != 3:
            if not tokens:
                raise ValueError("SHA could not be resolved, git returned: %r" % (header_line.strip()))
            else:
                raise ValueError("SHA %s could not be resolved, git returned: %r" % (tokens[0], header_line.strip()))
            # END handle actual return value
        # END error handling

        if len(tokens[0]) != 40:
            raise ValueError("Failed to parse header: %r" % header_line)
        return (tokens[0], tokens[1], int(tokens[2]))

    def _prepare_ref(self, ref):
        # required for command to separate refs on stdin, as bytes
        refstr = ref
        if isinstance(ref, bytes):
            # Assume 40 bytes hexsha - bin-to-ascii for some reason returns bytes, not text
            refstr = ref.decode('ascii')
        elif not isinstance(ref, string_types):
            refstr = str(ref)               # could be ref-object

        if not refstr.endswith("\n"):
            refstr += "\n"
        return refstr.encode(defenc)

    def _get_persistent_cmd(self, attr_name, cmd_name, *args, **kwargs):
        cur_val = getattr(self, attr_name)
        if cur_val is not None:
            return cur_val

        options = {"istream": PIPE, "as_process": True}
        options.update(kwargs)

        cmd = self._call_process(cmd_name, *args, **options)
        setattr(self, attr_name, cmd)
        return cmd

    def __get_object_header(self, cmd, ref):
        cmd.stdin.write(self._prepare_ref(ref))
        cmd.stdin.flush()
        return self._parse_object_header(cmd.stdout.readline())

    def get_object_header(self, ref):
        """ Use this method to quickly examine the type and size of the object behind
        the given ref.

        :note: The method will only suffer from the costs of command invocation
            once and reuses the command in subsequent calls.

        :return: (hexsha, type_string, size_as_int)"""
        cmd = self._get_persistent_cmd("cat_file_header", "cat_file", batch_check=True)
        return self.__get_object_header(cmd, ref)

    def get_object_data(self, ref):
        """ As get_object_header, but returns object data as well
        :return: (hexsha, type_string, size_as_int,data_string)
        :note: not threadsafe"""
        hexsha, typename, size, stream = self.stream_object_data(ref)
        data = stream.read(size)
        del(stream)
        return (hexsha, typename, size, data)

    def stream_object_data(self, ref):
        """ As get_object_header, but returns the data as a stream

        :return: (hexsha, type_string, size_as_int, stream)
        :note: This method is not threadsafe, you need one independent Command instance per thread to be safe !"""
        cmd = self._get_persistent_cmd("cat_file_all", "cat_file", batch=True)
        hexsha, typename, size = self.__get_object_header(cmd, ref)
        return (hexsha, typename, size, self.CatFileContentStream(size, cmd.stdout))

    def clear_cache(self):
        """Clear all kinds of internal caches to release resources.

        Currently persistent commands will be interrupted.

        :return: self"""
        for cmd in (self.cat_file_all, self.cat_file_header):
            if cmd:
                cmd.__del__()

        self.cat_file_all = None
        self.cat_file_header = None
        return self
