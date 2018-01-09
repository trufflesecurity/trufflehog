# helper.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from __future__ import print_function

import contextlib
from functools import wraps
import gc
import io
import logging
import os
import sys
import tempfile
import textwrap
import time

from git.compat import string_types, is_win
from git.util import rmtree, cwd
import gitdb

import os.path as osp


if sys.version_info[0:2] == (2, 6):
    import unittest2 as unittest
else:
    import unittest

TestCase = unittest.TestCase
SkipTest = unittest.SkipTest
skipIf = unittest.skipIf

ospd = osp.dirname

GIT_REPO = os.environ.get("GIT_PYTHON_TEST_GIT_REPO_BASE", ospd(ospd(ospd(ospd(__file__)))))
GIT_DAEMON_PORT = os.environ.get("GIT_PYTHON_TEST_GIT_DAEMON_PORT", "19418")

__all__ = (
    'fixture_path', 'fixture', 'StringProcessAdapter',
    'with_rw_directory', 'with_rw_repo', 'with_rw_and_rw_remote_repo',
    'TestBase', 'TestCase',
    'SkipTest', 'skipIf',
    'GIT_REPO', 'GIT_DAEMON_PORT'
)

log = logging.getLogger(__name__)

#{ Routines


def fixture_path(name):
    return osp.join(ospd(ospd(__file__)), 'fixtures', name)


def fixture(name):
    with open(fixture_path(name), 'rb') as fd:
        return fd.read()

#} END routines

#{ Adapters


class StringProcessAdapter(object):

    """Allows to use strings as Process object as returned by SubProcess.Popen.
    Its tailored to work with the test system only"""

    def __init__(self, input_string):
        self.stdout = io.BytesIO(input_string)
        self.stderr = io.BytesIO()

    def wait(self):
        return 0

    poll = wait

#} END adapters

#{ Decorators


def with_rw_directory(func):
    """Create a temporary directory which can be written to, remove it if the
    test succeeds, but leave it otherwise to aid additional debugging"""

    @wraps(func)
    def wrapper(self):
        path = tempfile.mktemp(prefix=func.__name__)
        os.mkdir(path)
        keep = False
        try:
            try:
                return func(self, path)
            except Exception:
                log.info("Test %s.%s failed, output is at %r\n",
                         type(self).__name__, func.__name__, path)
                keep = True
                raise
        finally:
            # Need to collect here to be sure all handles have been closed. It appears
            # a windows-only issue. In fact things should be deleted, as well as
            # memory maps closed, once objects go out of scope. For some reason
            # though this is not the case here unless we collect explicitly.
            gc.collect()
            if not keep:
                rmtree(path)

    return wrapper


def with_rw_repo(working_tree_ref, bare=False):
    """
    Same as with_bare_repo, but clones the rorepo as non-bare repository, checking
    out the working tree at the given working_tree_ref.

    This repository type is more costly due to the working copy checkout.

    To make working with relative paths easier, the cwd will be set to the working
    dir of the repository.
    """
    assert isinstance(working_tree_ref, string_types), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):
        @wraps(func)
        def repo_creator(self):
            prefix = 'non_'
            if bare:
                prefix = ''
            # END handle prefix
            repo_dir = tempfile.mktemp(prefix="%sbare_%s" % (prefix, func.__name__))
            rw_repo = self.rorepo.clone(repo_dir, shared=True, bare=bare, n=True)

            rw_repo.head.commit = rw_repo.commit(working_tree_ref)
            if not bare:
                rw_repo.head.reference.checkout()
            # END handle checkout

            prev_cwd = os.getcwd()
            os.chdir(rw_repo.working_dir)
            try:
                try:
                    return func(self, rw_repo)
                except:  # noqa E722
                    log.info("Keeping repo after failure: %s", repo_dir)
                    repo_dir = None
                    raise
            finally:
                os.chdir(prev_cwd)
                rw_repo.git.clear_cache()
                rw_repo = None
                if repo_dir is not None:
                    gc.collect()
                    gitdb.util.mman.collect()
                    gc.collect()
                    rmtree(repo_dir)
                # END rm test repo if possible
            # END cleanup
        # END rw repo creator
        return repo_creator
    # END argument passer
    return argument_passer


@contextlib.contextmanager
def git_daemon_launched(base_path, ip, port):
    from git import Git  # Avoid circular deps.

    gd = None
    try:
        if is_win:
            ## On MINGW-git, daemon exists in .\Git\mingw64\libexec\git-core\,
            #  but if invoked as 'git daemon', it detaches from parent `git` cmd,
            #  and then CANNOT DIE!
            #  So, invoke it as a single command.
            ## Cygwin-git has no daemon.  But it can use MINGW's.
            #
            daemon_cmd = ['git-daemon',
                          '--enable=receive-pack',
                          '--listen=%s' % ip,
                          '--port=%s' % port,
                          '--base-path=%s' % base_path,
                          base_path]
            gd = Git().execute(daemon_cmd, as_process=True)
        else:
            gd = Git().daemon(base_path,
                              enable='receive-pack',
                              listen=ip,
                              port=port,
                              base_path=base_path,
                              as_process=True)
        # yes, I know ... fortunately, this is always going to work if sleep time is just large enough
        time.sleep(0.5 * (1 + is_win))
    except Exception as ex:
        msg = textwrap.dedent("""
        Launching git-daemon failed due to: %s
          Probably test will fail subsequently.

          BUT you may start *git-daemon* manually with this command:"
                git daemon --enable=receive-pack  --listen=%s --port=%s --base-path=%s  %s
          You may also run the daemon on a different port by passing --port=<port>"
          and setting the environment variable GIT_PYTHON_TEST_GIT_DAEMON_PORT to <port>
        """)
        if is_win:
            msg += textwrap.dedent(r"""

            On Windows,
              the `git-daemon.exe` must be in PATH.
              For MINGW, look into .\Git\mingw64\libexec\git-core\), but problems with paths might appear.
              CYGWIN has no daemon, but if one exists, it gets along fine (but has also paths problems).""")
        log.warning(msg, ex, ip, port, base_path, base_path, exc_info=1)

        yield  # OK, assume daemon started manually.

    else:
        yield  # Yield outside try, to avoid catching
    finally:
        if gd:
            try:
                log.debug("Killing git-daemon...")
                gd.proc.kill()
            except Exception as ex:
                ## Either it has died (and we're here), or it won't die, again here...
                log.debug("Hidden error while Killing git-daemon: %s", ex, exc_info=1)


def with_rw_and_rw_remote_repo(working_tree_ref):
    """
    Same as with_rw_repo, but also provides a writable remote repository from which the
    rw_repo has been forked as well as a handle for a git-daemon that may be started to
    run the remote_repo.
    The remote repository was cloned as bare repository from the ro repo, whereas
    the rw repo has a working tree and was cloned from the remote repository.

    remote_repo has two remotes: origin and daemon_origin. One uses a local url,
    the other uses a server url. The daemon setup must be done on system level
    and should be an inetd service that serves tempdir.gettempdir() and all
    directories in it.

    The following sketch demonstrates this::
     rorepo ---<bare clone>---> rw_remote_repo ---<clone>---> rw_repo

    The test case needs to support the following signature::
        def case(self, rw_repo, rw_daemon_repo)

    This setup allows you to test push and pull scenarios and hooks nicely.

    See working dir info in with_rw_repo
    :note: We attempt to launch our own invocation of git-daemon, which will be shutdown at the end of the test.
    """
    from git import Git, Remote  # To avoid circular deps.

    assert isinstance(working_tree_ref, string_types), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):

        @wraps(func)
        def remote_repo_creator(self):
            rw_daemon_repo_dir = tempfile.mktemp(prefix="daemon_repo-%s-" % func.__name__)
            rw_repo_dir = tempfile.mktemp(prefix="daemon_cloned_repo-%s-" % func.__name__)

            rw_daemon_repo = self.rorepo.clone(rw_daemon_repo_dir, shared=True, bare=True)
            # recursive alternates info ?
            rw_repo = rw_daemon_repo.clone(rw_repo_dir, shared=True, bare=False, n=True)
            try:
                rw_repo.head.commit = working_tree_ref
                rw_repo.head.reference.checkout()

                # prepare for git-daemon
                rw_daemon_repo.daemon_export = True

                # this thing is just annoying !
                with rw_daemon_repo.config_writer() as crw:
                    section = "daemon"
                    try:
                        crw.add_section(section)
                    except Exception:
                        pass
                    crw.set(section, "receivepack", True)

                # Initialize the remote - first do it as local remote and pull, then
                # we change the url to point to the daemon.
                d_remote = Remote.create(rw_repo, "daemon_origin", rw_daemon_repo_dir)
                d_remote.fetch()

                base_daemon_path, rel_repo_dir = osp.split(rw_daemon_repo_dir)

                remote_repo_url = Git.polish_url("git://localhost:%s/%s" % (GIT_DAEMON_PORT, rel_repo_dir))
                with d_remote.config_writer as cw:
                    cw.set('url', remote_repo_url)

                with git_daemon_launched(Git.polish_url(base_daemon_path, is_cygwin=False),  # No daemon in Cygwin.
                                         '127.0.0.1',
                                         GIT_DAEMON_PORT):
                    # Try listing remotes, to diagnose whether the daemon is up.
                    rw_repo.git.ls_remote(d_remote)

                    with cwd(rw_repo.working_dir):
                        try:
                            return func(self, rw_repo, rw_daemon_repo)
                        except:  # noqa E722
                            log.info("Keeping repos after failure: \n  rw_repo_dir: %s \n  rw_daemon_repo_dir: %s",
                                     rw_repo_dir, rw_daemon_repo_dir)
                            rw_repo_dir = rw_daemon_repo_dir = None
                            raise

            finally:
                rw_repo.git.clear_cache()
                rw_daemon_repo.git.clear_cache()
                del rw_repo
                del rw_daemon_repo
                gc.collect()
                gitdb.util.mman.collect()
                gc.collect()
                if rw_repo_dir:
                    rmtree(rw_repo_dir)
                if rw_daemon_repo_dir:
                    rmtree(rw_daemon_repo_dir)
            # END cleanup
        # END bare repo creator
        return remote_repo_creator
        # END remote repo creator
    # END argument parser

    return argument_passer

#} END decorators


class TestBase(TestCase):

    """
    Base Class providing default functionality to all tests such as:

    - Utility functions provided by the TestCase base of the unittest method such as::
        self.fail("todo")
        self.failUnlessRaises(...)

    - Class level repository which is considered read-only as it is shared among
      all test cases in your type.
      Access it using::
       self.rorepo  # 'ro' stands for read-only

      The rorepo is in fact your current project's git repo. If you refer to specific
      shas for your objects, be sure you choose some that are part of the immutable portion
      of the project history ( to assure tests don't fail for others ).
    """

    # On py26, unittest2 has assertRaisesRegex
    # On py3, unittest has assertRaisesRegex
    # On py27, we use unittest, which names it differently:
    if sys.version_info[0:2] == (2, 7):
        assertRaisesRegex = TestCase.assertRaisesRegexp

    def _small_repo_url(self):
        """:return" a path to a small, clonable repository"""
        from git.cmd import Git
        return Git.polish_url(osp.join(self.rorepo.working_tree_dir, 'git/ext/gitdb/gitdb/ext/smmap'))

    @classmethod
    def setUpClass(cls):
        """
        Dynamically add a read-only repository to our actual type. This way
        each test type has its own repository
        """
        from git import Repo
        gc.collect()
        cls.rorepo = Repo(GIT_REPO)

    @classmethod
    def tearDownClass(cls):
        cls.rorepo.git.clear_cache()
        cls.rorepo.git = None

    def _make_file(self, rela_path, data, repo=None):
        """
        Create a file at the given path relative to our repository, filled
        with the given data. Returns absolute path to created file.
        """
        repo = repo or self.rorepo
        abs_path = osp.join(repo.working_tree_dir, rela_path)
        with open(abs_path, "w") as fp:
            fp.write(data)
        return abs_path
