import collections
import os
import sys

import six

try:
    from functools import wraps
except ImportError:
    # only needed for Python 2.4
    def wraps(_):
        def _wraps(func):
            return func
        return _wraps

__unittest = True

def _relpath_nt(path, start=os.path.curdir):
    """Return a relative version of a path"""

    if not path:
        raise ValueError("no path specified")
    start_list = os.path.abspath(start).split(os.path.sep)
    path_list = os.path.abspath(path).split(os.path.sep)
    if start_list[0].lower() != path_list[0].lower():
        unc_path, rest = os.path.splitunc(path)
        unc_start, rest = os.path.splitunc(start)
        if bool(unc_path) ^ bool(unc_start):
            raise ValueError("Cannot mix UNC and non-UNC paths (%s and %s)"
                                                                % (path, start))
        else:
            raise ValueError("path is on drive %s, start on drive %s"
                                                % (path_list[0], start_list[0]))
    # Work out how much of the filepath is shared by start and path.
    for i in range(min(len(start_list), len(path_list))):
        if start_list[i].lower() != path_list[i].lower():
            break
    else:
        i += 1

    rel_list = [os.path.pardir] * (len(start_list)-i) + path_list[i:]
    if not rel_list:
        return os.path.curdir
    return os.path.join(*rel_list)

# default to posixpath definition
def _relpath_posix(path, start=os.path.curdir):
    """Return a relative version of a path"""

    if not path:
        raise ValueError("no path specified")

    start_list = os.path.abspath(start).split(os.path.sep)
    path_list = os.path.abspath(path).split(os.path.sep)

    # Work out how much of the filepath is shared by start and path.
    i = len(os.path.commonprefix([start_list, path_list]))

    rel_list = [os.path.pardir] * (len(start_list)-i) + path_list[i:]
    if not rel_list:
        return os.path.curdir
    return os.path.join(*rel_list)

if os.path is sys.modules.get('ntpath'):
    relpath = _relpath_nt
else:
    relpath = _relpath_posix


def with_context(context, callableobj, *args, **kwargs):
    """
    Execute a callable utilizing a context object
    in the same way that the 'with' statement would
    """
    context.__enter__()
    try:
        callableobj(*args, **kwargs)
    except:
        if not context.__exit__(*sys.exc_info()):
            raise
        else:
            return
    else:
        context.__exit__(None, None, None)


# copied from Python 2.6
try:
    from warnings import catch_warnings
except ImportError:
    class catch_warnings(object):
        def __init__(self, record=False, module=None):
            self._record = record
            self._module = sys.modules['warnings']
            self._entered = False

        def __repr__(self):
            args = []
            if self._record:
                args.append("record=True")
            name = type(self).__name__
            return "%s(%s)" % (name, ", ".join(args))

        def __enter__(self):
            if self._entered:
                raise RuntimeError("Cannot enter %r twice" % self)
            self._entered = True
            self._filters = self._module.filters
            self._module.filters = self._filters[:]
            self._showwarning = self._module.showwarning
            if self._record:
                log = []
                def showwarning(*args, **kwargs):
                    log.append(WarningMessage(*args, **kwargs))
                self._module.showwarning = showwarning
                return log
            else:
                return None

        def __exit__(self, *exc_info):
            if not self._entered:
                raise RuntimeError("Cannot exit %r without entering first" % self)
            self._module.filters = self._filters
            self._module.showwarning = self._showwarning

    class WarningMessage(object):
        _WARNING_DETAILS = ("message", "category", "filename", "lineno", "file",
                            "line")
        def __init__(self, message, category, filename, lineno, file=None,
                        line=None):
            local_values = locals()
            for attr in self._WARNING_DETAILS:
                setattr(self, attr, local_values[attr])
            self._category_name = None
            if category.__name__:
                self._category_name = category.__name__

# Copied from 3.5
########################################################################
###  ChainMap (helper for configparser and string.Template)
########################################################################

class ChainMap(collections.MutableMapping):
    ''' A ChainMap groups multiple dicts (or other mappings) together
    to create a single, updateable view.

    The underlying mappings are stored in a list.  That list is public and can
    accessed or updated using the *maps* attribute.  There is no other state.

    Lookups search the underlying mappings successively until a key is found.
    In contrast, writes, updates, and deletions only operate on the first
    mapping.

    '''

    def __init__(self, *maps):
        '''Initialize a ChainMap by setting *maps* to the given mappings.
        If no mappings are provided, a single empty dictionary is used.

        '''
        self.maps = list(maps) or [{}]          # always at least one map

    def __missing__(self, key):
        raise KeyError(key)

    def __getitem__(self, key):
        for mapping in self.maps:
            try:
                return mapping[key]             # can't use 'key in mapping' with defaultdict
            except KeyError:
                pass
        return self.__missing__(key)            # support subclasses that define __missing__

    def get(self, key, default=None):
        return self[key] if key in self else default

    def __len__(self):
        return len(set().union(*self.maps))     # reuses stored hash values if possible

    def __iter__(self):
        return iter(set().union(*self.maps))

    def __contains__(self, key):
        return any(key in m for m in self.maps)

    def __bool__(self):
        return any(self.maps)

    if getattr(collections, '_recursive_repr', None):
        @collections._recursive_repr()
        def __repr__(self):
            return '{0.__class__.__name__}({1})'.format(
                self, ', '.join(map(repr, self.maps)))
    else:
        def __repr__(self):
            return '{0.__class__.__name__}({1})'.format(
                self, ', '.join(map(repr, self.maps)))

    @classmethod
    def fromkeys(cls, iterable, *args):
        'Create a ChainMap with a single dict created from the iterable.'
        return cls(dict.fromkeys(iterable, *args))

    def copy(self):
        'New ChainMap or subclass with a new copy of maps[0] and refs to maps[1:]'
        return self.__class__(self.maps[0].copy(), *self.maps[1:])

    __copy__ = copy

    def new_child(self, m=None):                # like Django's Context.push()
        '''
        New ChainMap with a new map followed by all previous maps. If no
        map is provided, an empty dict is used.
        '''
        if m is None:
            m = {}
        return self.__class__(m, *self.maps)

    @property
    def parents(self):                          # like Django's Context.pop()
        'New ChainMap from maps[1:].'
        return self.__class__(*self.maps[1:])

    def __setitem__(self, key, value):
        self.maps[0][key] = value

    def __delitem__(self, key):
        try:
            del self.maps[0][key]
        except KeyError:
            raise KeyError('Key not found in the first mapping: {!r}'.format(key))

    def popitem(self):
        'Remove and return an item pair from maps[0]. Raise KeyError is maps[0] is empty.'
        try:
            return self.maps[0].popitem()
        except KeyError:
            raise KeyError('No keys found in the first mapping.')

    def pop(self, key, *args):
        'Remove *key* from maps[0] and return its value. Raise KeyError if *key* not in maps[0].'
        try:
            return self.maps[0].pop(key, *args)
        except KeyError:
            raise KeyError('Key not found in the first mapping: {!r}'.format(key))

    def clear(self):
        'Clear maps[0], leaving maps[1:] intact.'
        self.maps[0].clear()

if sys.version_info[:2] < (3, 4):
    collections.ChainMap = ChainMap


# support raise_from on 3.x:
# submitted to six: https://bitbucket.org/gutworth/six/issue/102/raise-foo-from-bar-is-a-syntax-error-on-27
if sys.version_info[:2] > (3, 2):
    six.exec_("""def raise_from(value, from_value):
    raise value from from_value
""")
else:
    def raise_from(value, from_value):
        raise value
