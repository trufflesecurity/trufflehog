"""
Import all submodules main classes into the package space
"""
# flake8: noqa
from __future__ import absolute_import

import inspect

from .base import *
from .blob import *
from .commit import *
from .submodule import util as smutil
from .submodule.base import *
from .submodule.root import *
from .tag import *
from .tree import *
# Fix import dependency - add IndexObject to the util module, so that it can be
# imported by the submodule.base
smutil.IndexObject = IndexObject
smutil.Object = Object
del(smutil)

# must come after submodule was made available

__all__ = [name for name, obj in locals().items()
           if not (name.startswith('_') or inspect.ismodule(obj))]
