"""Contains library functions"""
import logging
import os
import tempfile

from git import (
    Repo
)
from git.db import (
    GitCmdObjectDB,
    GitDB
)
from git.test.lib import (
    TestBase
)
from git.util import rmtree
import os.path as osp

#{ Invariants

k_env_git_repo = "GIT_PYTHON_TEST_GIT_REPO_BASE"

#} END invariants


#{ Base Classes

class TestBigRepoR(TestBase):

    """TestCase providing access to readonly 'big' repositories using the following
    member variables:

    * gitrorepo

     * Read-Only git repository - actually the repo of git itself

    * puregitrorepo

     * As gitrepo, but uses pure python implementation
    """

    #{ Invariants
    #} END invariants

    def setUp(self):
        try:
            super(TestBigRepoR, self).setUp()
        except AttributeError:
            pass

        repo_path = os.environ.get(k_env_git_repo)
        if repo_path is None:
            logging.info(
                ("You can set the %s environment variable to a .git repository of" % k_env_git_repo) +
                "your choice - defaulting to the gitpython repository")
            repo_path = osp.dirname(__file__)
        # end set some repo path
        self.gitrorepo = Repo(repo_path, odbt=GitCmdObjectDB, search_parent_directories=True)
        self.puregitrorepo = Repo(repo_path, odbt=GitDB, search_parent_directories=True)

    def tearDown(self):
        self.gitrorepo.git.clear_cache()
        self.gitrorepo = None
        self.puregitrorepo.git.clear_cache()
        self.puregitrorepo = None


class TestBigRepoRW(TestBigRepoR):

    """As above, but provides a big repository that we can write to.

    Provides ``self.gitrwrepo`` and ``self.puregitrwrepo``"""

    def setUp(self):
        self.gitrwrepo = None
        try:
            super(TestBigRepoRW, self).setUp()
        except AttributeError:
            pass
        dirname = tempfile.mktemp()
        os.mkdir(dirname)
        self.gitrwrepo = self.gitrorepo.clone(dirname, shared=True, bare=True, odbt=GitCmdObjectDB)
        self.puregitrwrepo = Repo(dirname, odbt=GitDB)

    def tearDown(self):
        super(TestBigRepoRW, self).tearDown()
        if self.gitrwrepo is not None:
            rmtree(self.gitrwrepo.working_dir)
            self.gitrwrepo.git.clear_cache()
        self.gitrwrepo = None
        self.puregitrwrepo.git.clear_cache()
        self.puregitrwrepo = None

#} END base classes
