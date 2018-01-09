# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Initialize the object database module"""

import sys
import os

#{ Initialization


def _init_externals():
    """Initialize external projects by putting them into the path"""
    for module in ('smmap',):
        sys.path.append(os.path.join(os.path.dirname(__file__), 'ext', module))

        try:
            __import__(module)
        except ImportError:
            raise ImportError("'%s' could not be imported, assure it is located in your PYTHONPATH" % module)
        # END verify import
    # END handel imports

#} END initialization

_init_externals()

__author__ = "Sebastian Thiel"
__contact__ = "byronimo@gmail.com"
__homepage__ = "https://github.com/gitpython-developers/gitdb"
version_info = (2, 0, 3)
__version__ = '.'.join(str(i) for i in version_info)


# default imports
from gitdb.base import *
from gitdb.db import *
from gitdb.stream import *
