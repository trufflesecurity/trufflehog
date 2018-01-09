"""Cache lines from files.

This is intended to read lines from modules imported -- hence if a filename
is not found, it will look down the module search path for a file by
that name.
"""

import functools
import io
import sys
import os
import tokenize

__all__ = ["getline", "clearcache", "checkcache"]

def getline(filename, lineno, module_globals=None):
    lines = getlines(filename, module_globals)
    if 1 <= lineno <= len(lines):
        return lines[lineno-1]
    else:
        return ''


# The cache

# The cache. Maps filenames to either a thunk which will provide source code,
# or a tuple (size, mtime, lines, fullname) once loaded.
cache = {}


def clearcache():
    """Clear the cache entirely."""

    global cache
    cache = {}


def getlines(filename, module_globals=None):
    """Get the lines for a file from the cache.
    Update the cache if it doesn't contain an entry for this file already."""

    if filename in cache:
        entry = cache[filename]
        if len(entry) == 1:
            return updatecache(filename, module_globals)
        return cache[filename][2]
    else:
        return updatecache(filename, module_globals)


def checkcache(filename=None):
    """Discard cache entries that are out of date.
    (This is not checked upon each call!)"""

    if filename is None:
        filenames = list(cache.keys())
    else:
        if filename in cache:
            filenames = [filename]
        else:
            return

    for filename in filenames:
        entry = cache[filename]
        if len(entry) == 1:
            # lazy cache entry, leave it lazy.
            continue
        size, mtime, lines, fullname = entry
        if mtime is None:
            continue   # no-op for files loaded via a __loader__
        try:
            stat = os.stat(fullname)
        except OSError:
            del cache[filename]
            continue
        if size != stat.st_size or mtime != stat.st_mtime:
            del cache[filename]


def updatecache(filename, module_globals=None):
    """Update a cache entry and return its list of lines.
    If something's wrong, print a message, discard the cache entry,
    and return an empty list."""

    if filename in cache:
        if len(cache[filename]) != 1:
            del cache[filename]
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return []

    fullname = filename
    try:
        stat = os.stat(fullname)
    except OSError:
        basename = filename

        # Realise a lazy loader based lookup if there is one
        # otherwise try to lookup right now.
        if lazycache(filename, module_globals):
            try:
                data = cache[filename][0]()
            except (ImportError, OSError):
                pass
            else:
                if data is None:
                    # No luck, the PEP302 loader cannot find the source
                    # for this module.
                    return []
                cache[filename] = (
                    len(data), None,
                    [line+'\n' for line in data.splitlines()], fullname
                )
                return cache[filename][2]

        # Try looking through the module search path, which is only useful
        # when handling a relative filename.
        if os.path.isabs(filename):
            return []

        for dirname in sys.path:
            try:
                fullname = os.path.join(dirname, basename)
            except (TypeError, AttributeError):
                # Not sufficiently string-like to do anything useful with.
                continue
            try:
                stat = os.stat(fullname)
                break
            except OSError:
                pass
        else:
            return []
    try:
        with _tokenize_open(fullname) as fp:
            lines = fp.readlines()
    except OSError:
        return []
    if lines and not lines[-1].endswith('\n'):
        lines[-1] += '\n'
    size, mtime = stat.st_size, stat.st_mtime
    cache[filename] = size, mtime, lines, fullname
    return lines


def lazycache(filename, module_globals):
    """Seed the cache for filename with module_globals.

    The module loader will be asked for the source only when getlines is
    called, not immediately.

    If there is an entry in the cache already, it is not altered.

    :return: True if a lazy load is registered in the cache,
        otherwise False. To register such a load a module loader with a
        get_source method must be found, the filename must be a cachable
        filename, and the filename must not be already cached.
    """
    if filename in cache:
        if len(cache[filename]) == 1:
            return True
        else:
            return False
    if not filename or (filename.startswith('<') and filename.endswith('>')):
        return False
    # Try for a __loader__, if available
    if module_globals and '__loader__' in module_globals:
        name = module_globals.get('__name__')
        loader = module_globals['__loader__']
        get_source = getattr(loader, 'get_source', None)

        if name and get_source:
            get_lines = functools.partial(get_source, name)
            cache[filename] = (get_lines,)
            return True
    return False


#### ---- avoiding having a tokenize2 backport for now ----
from codecs import lookup, BOM_UTF8
import re
cookie_re = re.compile(r'^[ \t\f]*#.*coding[:=][ \t]*([-\w.]+)'.encode('utf8'))
blank_re = re.compile(r'^[ \t\f]*(?:[#\r\n]|$)'.encode('utf8'))


def _tokenize_open(filename):
    """Open a file in read only mode using the encoding detected by
    detect_encoding().
    """
    buffer = io.open(filename, 'rb')
    encoding, lines = _detect_encoding(buffer.readline)
    buffer.seek(0)
    text = io.TextIOWrapper(buffer, encoding, line_buffering=True)
    text.mode = 'r'
    return text


def _get_normal_name(orig_enc):
    """Imitates get_normal_name in tokenizer.c."""
    # Only care about the first 12 characters.
    enc = orig_enc[:12].lower().replace("_", "-")
    if enc == "utf-8" or enc.startswith("utf-8-"):
        return "utf-8"
    if enc in ("latin-1", "iso-8859-1", "iso-latin-1") or \
       enc.startswith(("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        return "iso-8859-1"
    return orig_enc


def _detect_encoding(readline):
    """
    The detect_encoding() function is used to detect the encoding that should
    be used to decode a Python source file.  It requires one argument, readline,
    in the same way as the tokenize() generator.

    It will call readline a maximum of twice, and return the encoding used
    (as a string) and a list of any lines (left as bytes) it has read in.

    It detects the encoding from the presence of a utf-8 bom or an encoding
    cookie as specified in pep-0263.  If both a bom and a cookie are present,
    but disagree, a SyntaxError will be raised.  If the encoding cookie is an
    invalid charset, raise a SyntaxError.  Note that if a utf-8 bom is found,
    'utf-8-sig' is returned.

    If no encoding is specified, then the default of 'utf-8' will be returned.
    """
    try:
        filename = readline.__self__.name
    except AttributeError:
        filename = None
    bom_found = False
    encoding = None
    default = 'utf-8'
    def read_or_stop():
        try:
            return readline()
        except StopIteration:
            return b''

    def find_cookie(line):
        try:
            # Decode as UTF-8. Either the line is an encoding declaration,
            # in which case it should be pure ASCII, or it must be UTF-8
            # per default encoding.
            line_string = line.decode('utf-8')
        except UnicodeDecodeError:
            msg = "invalid or missing encoding declaration"
            if filename is not None:
                msg = '{0} for {1!r}'.format(msg, filename)
            raise SyntaxError(msg)

        match = cookie_re.match(line)
        if not match:
            return None
        encoding = _get_normal_name(match.group(1).decode('utf-8'))
        try:
            codec = lookup(encoding)
        except LookupError:
            # This behaviour mimics the Python interpreter
            if filename is None:
                msg = "unknown encoding: " + encoding
            else:
                msg = "unknown encoding for {!r}: {}".format(filename,
                        encoding)
            raise SyntaxError(msg)

        if bom_found:
            if encoding != 'utf-8':
                # This behaviour mimics the Python interpreter
                if filename is None:
                    msg = 'encoding problem: utf-8'
                else:
                    msg = 'encoding problem for {!r}: utf-8'.format(filename)
                raise SyntaxError(msg)
            encoding += '-sig'
        return encoding

    first = read_or_stop()
    if first.startswith(BOM_UTF8):
        bom_found = True
        first = first[3:]
        default = 'utf-8-sig'
    if not first:
        return default, []

    encoding = find_cookie(first)
    if encoding:
        return encoding, [first]
    if not blank_re.match(first):
        return default, [first]

    second = read_or_stop()
    if not second:
        return default, [first]

    encoding = find_cookie(second)
    if encoding:
        return encoding, [first, second]

    return default, [first, second]


