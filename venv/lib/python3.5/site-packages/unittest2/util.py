"""Various utility functions."""

from os.path import commonprefix

__unittest = True


_MAX_LENGTH = 80
_PLACEHOLDER_LEN = 12
_MIN_BEGIN_LEN = 5
_MIN_END_LEN = 5
_MIN_COMMON_LEN = 5
_MIN_DIFF_LEN = _MAX_LENGTH - \
               (_MIN_BEGIN_LEN + _PLACEHOLDER_LEN + _MIN_COMMON_LEN +
                _PLACEHOLDER_LEN + _MIN_END_LEN)
assert _MIN_DIFF_LEN >= 0

def _shorten(s, prefixlen, suffixlen):
    skip = len(s) - prefixlen - suffixlen
    if skip > _PLACEHOLDER_LEN:
        s = '%s[%d chars]%s' % (s[:prefixlen], skip, s[len(s) - suffixlen:])
    return s

def _common_shorten_repr(*args):
    args = tuple(map(safe_repr, args))
    maxlen = max(map(len, args))
    if maxlen <= _MAX_LENGTH:
        return args

    prefix = commonprefix(args)
    prefixlen = len(prefix)

    common_len = _MAX_LENGTH - \
                 (maxlen - prefixlen + _MIN_BEGIN_LEN + _PLACEHOLDER_LEN)
    if common_len > _MIN_COMMON_LEN:
        assert _MIN_BEGIN_LEN + _PLACEHOLDER_LEN + _MIN_COMMON_LEN + \
               (maxlen - prefixlen) < _MAX_LENGTH
        prefix = _shorten(prefix, _MIN_BEGIN_LEN, common_len)
        return tuple(prefix + s[prefixlen:] for s in args)

    prefix = _shorten(prefix, _MIN_BEGIN_LEN, _MIN_COMMON_LEN)
    return tuple(prefix + _shorten(s[prefixlen:], _MIN_DIFF_LEN, _MIN_END_LEN)
                 for s in args)

def safe_repr(obj, short=False):
    try:
        result = repr(obj)
    except Exception:
        result = object.__repr__(obj)
    if not short or len(result) < _MAX_LENGTH:
        return result
    return result[:_MAX_LENGTH] + ' [truncated]...'

def safe_str(obj):
    try:
        return str(obj)
    except Exception:
        return object.__str__(obj)

def strclass(cls):
    return "%s.%s" % (cls.__module__, getattr(cls, '__qualname__', cls.__name__))


def unorderable_list_difference(expected, actual, ignore_duplicate=False):
    """Same behavior as sorted_list_difference but
    for lists of unorderable items (like dicts).

    As it does a linear search per item (remove) it
    has O(n*n) performance.
    """
    missing = []
    unexpected = []
    while expected:
        item = expected.pop()
        try:
            actual.remove(item)
        except ValueError:
            missing.append(item)
        if ignore_duplicate:
            for lst in expected, actual:
                try:
                    while True:
                        lst.remove(item)
                except ValueError:
                    pass
    if ignore_duplicate:
        while actual:
            item = actual.pop()
            unexpected.append(item)
            try:
                while True:
                    actual.remove(item)
            except ValueError:
                pass
        return missing, unexpected

    # anything left in actual is unexpected
    return missing, actual


def three_way_cmp(x, y):
    """Return -1 if x < y, 0 if x == y and 1 if x > y"""
    return (x > y) - (x < y)

