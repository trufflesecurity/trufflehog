# __init__.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
# flake8: noqa
#@PydevCodeAnalysisIgnore
import inspect
import os
import sys

import os.path as osp


__version__ = '2.1.8'


#{ Initialization
def _init_externals():
    """Initialize external projects by putting them into the path"""
    if __version__ == '2.1.8':
        sys.path.insert(0, osp.join(osp.dirname(__file__), 'ext', 'gitdb'))

    try:
        import gitdb
    except ImportError:
        raise ImportError("'gitdb' could not be found in your PYTHONPATH")
    # END verify import

#} END initialization

#################
_init_externals()
#################

#{ Imports

from git.exc import *                       # @NoMove @IgnorePep8
try:
    from git.config import GitConfigParser  # @NoMove @IgnorePep8
    from git.objects import *               # @NoMove @IgnorePep8
    from git.refs import *                  # @NoMove @IgnorePep8
    from git.diff import *                  # @NoMove @IgnorePep8
    from git.db import *                    # @NoMove @IgnorePep8
    from git.cmd import Git                 # @NoMove @IgnorePep8
    from git.repo import Repo               # @NoMove @IgnorePep8
    from git.remote import *                # @NoMove @IgnorePep8
    from git.index import *                 # @NoMove @IgnorePep8
    from git.util import (                  # @NoMove @IgnorePep8
        LockFile,
        BlockingLockFile,
        Stats,
        Actor,
        rmtree,
    )
except GitError as exc:
    raise ImportError('%s: %s' % (exc.__class__.__name__, exc))

#} END imports

__all__ = [name for name, obj in locals().items()
           if not (name.startswith('_') or inspect.ismodule(obj))]


#{ Initialize git executable path
GIT_OK = None

def refresh(path=None):
    """Convenience method for setting the git executable path."""
    global GIT_OK
    GIT_OK = False

    if not Git.refresh(path=path):
        return
    if not FetchInfo.refresh():
        return

    GIT_OK = True
#} END initialize git executable path

#################
refresh()
#################
