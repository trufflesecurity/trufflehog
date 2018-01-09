# -*- coding: utf-8 -*-
# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""utilities to help provide compatibility with python 3"""
# flake8: noqa

import locale
import os
import sys
import codecs


from gitdb.utils.compat import (
    xrange,
    MAXSIZE,    # @UnusedImport
    izip,       # @UnusedImport
)
from gitdb.utils.encoding import (
    string_types,    # @UnusedImport
    text_type,       # @UnusedImport
    force_bytes,     # @UnusedImport
    force_text       # @UnusedImport
)


PY3 = sys.version_info[0] >= 3
is_win = (os.name == 'nt')
is_posix = (os.name == 'posix')
is_darwin = (os.name == 'darwin')
defenc = sys.getdefaultencoding()

if PY3:
    import io
    FileType = io.IOBase

    def byte_ord(b):
        return b

    def bchr(n):
        return bytes([n])

    def mviter(d):
        return d.values()

    range = xrange  # @ReservedAssignment
    unicode = str
    binary_type = bytes
else:
    FileType = file  # @UndefinedVariable on PY3
    # usually, this is just ascii, which might not enough for our encoding needs
    # Unless it's set specifically, we override it to be utf-8
    if defenc == 'ascii':
        defenc = 'utf-8'
    byte_ord = ord
    bchr = chr
    unicode = unicode
    binary_type = str
    range = xrange  # @ReservedAssignment

    def mviter(d):
        return d.itervalues()


def safe_decode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, unicode):
        return s
    elif isinstance(s, bytes):
        return s.decode(defenc, 'surrogateescape')
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def safe_encode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, unicode):
        return s.encode(defenc)
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def win_encode(s):
    """Encode unicodes for process arguments on Windows."""
    if isinstance(s, unicode):
        return s.encode(locale.getpreferredencoding(False))
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def with_metaclass(meta, *bases):
    """copied from https://github.com/Byron/bcore/blob/master/src/python/butility/future.py#L15"""
    class metaclass(meta):
        __call__ = type.__call__
        __init__ = type.__init__

        def __new__(cls, name, nbases, d):
            if nbases is None:
                return type.__new__(cls, name, (), d)
            # There may be clients who rely on this attribute to be set to a reasonable value, which is why
            # we set the __metaclass__ attribute explicitly
            if not PY3 and '___metaclass__' not in d:
                d['__metaclass__'] = meta
            return meta(name, bases, d)
    return metaclass(meta.__name__ + 'Helper', None, {})


## From https://docs.python.org/3.3/howto/pyporting.html
class UnicodeMixin(object):

    """Mixin class to handle defining the proper __str__/__unicode__
    methods in Python 2 or 3."""

    if PY3:
        def __str__(self):
            return self.__unicode__()
    else:  # Python 2
        def __str__(self):
            return self.__unicode__().encode(defenc)
            
            
"""
This is Victor Stinner's pure-Python implementation of PEP 383: the "surrogateescape" error
handler of Python 3.
Source: misc/python/surrogateescape.py in https://bitbucket.org/haypo/misc
"""

# This code is released under the Python license and the BSD 2-clause license


FS_ERRORS = 'surrogateescape'

#     # -- Python 2/3 compatibility -------------------------------------
#     FS_ERRORS = 'my_surrogateescape'

def u(text):
    if PY3:
        return text
    else:
        return text.decode('unicode_escape')

def b(data):
    if PY3:
        return data.encode('latin1')
    else:
        return data

if PY3:
    _unichr = chr
    bytes_chr = lambda code: bytes((code,))
else:
    _unichr = unichr
    bytes_chr = chr

def surrogateescape_handler(exc):
    """
    Pure Python implementation of the PEP 383: the "surrogateescape" error
    handler of Python 3. Undecodable bytes will be replaced by a Unicode
    character U+DCxx on decoding, and these are translated into the
    original bytes on encoding.
    """
    mystring = exc.object[exc.start:exc.end]

    try:
        if isinstance(exc, UnicodeDecodeError):
            # mystring is a byte-string in this case
            decoded = replace_surrogate_decode(mystring)
        elif isinstance(exc, UnicodeEncodeError):
            # In the case of u'\udcc3'.encode('ascii',
            # 'this_surrogateescape_handler'), both Python 2.x and 3.x raise an
            # exception anyway after this function is called, even though I think
            # it's doing what it should. It seems that the strict encoder is called
            # to encode the unicode string that this function returns ...
            decoded = replace_surrogate_encode(mystring, exc)
        else:
            raise exc
    except NotASurrogateError:
        raise exc
    return (decoded, exc.end)


class NotASurrogateError(Exception):
    pass


def replace_surrogate_encode(mystring, exc):
    """
    Returns a (unicode) string, not the more logical bytes, because the codecs
    register_error functionality expects this.
    """
    decoded = []
    for ch in mystring:
        # if PY3:
        #     code = ch
        # else:
        code = ord(ch)

        # The following magic comes from Py3.3's Python/codecs.c file:
        if not 0xD800 <= code <= 0xDCFF:
            # Not a surrogate. Fail with the original exception.
            raise exc
        # mybytes = [0xe0 | (code >> 12),
        #            0x80 | ((code >> 6) & 0x3f),
        #            0x80 | (code & 0x3f)]
        # Is this a good idea?
        if 0xDC00 <= code <= 0xDC7F:
            decoded.append(_unichr(code - 0xDC00))
        elif code <= 0xDCFF:
            decoded.append(_unichr(code - 0xDC00))
        else:
            raise NotASurrogateError
    return str().join(decoded)


def replace_surrogate_decode(mybytes):
    """
    Returns a (unicode) string
    """
    decoded = []
    for ch in mybytes:
        # We may be parsing newbytes (in which case ch is an int) or a native
        # str on Py2
        if isinstance(ch, int):
            code = ch
        else:
            code = ord(ch)
        if 0x80 <= code <= 0xFF:
            decoded.append(_unichr(0xDC00 + code))
        elif code <= 0x7F:
            decoded.append(_unichr(code))
        else:
            # # It may be a bad byte
            # # Try swallowing it.
            # continue
            # print("RAISE!")
            raise NotASurrogateError
    return str().join(decoded)


def encodefilename(fn):
    if FS_ENCODING == 'ascii':
        # ASCII encoder of Python 2 expects that the error handler returns a
        # Unicode string encodable to ASCII, whereas our surrogateescape error
        # handler has to return bytes in 0x80-0xFF range.
        encoded = []
        for index, ch in enumerate(fn):
            code = ord(ch)
            if code < 128:
                ch = bytes_chr(code)
            elif 0xDC80 <= code <= 0xDCFF:
                ch = bytes_chr(code - 0xDC00)
            else:
                raise UnicodeEncodeError(FS_ENCODING,
                    fn, index, index+1,
                    'ordinal not in range(128)')
            encoded.append(ch)
        return bytes().join(encoded)
    elif FS_ENCODING == 'utf-8':
        # UTF-8 encoder of Python 2 encodes surrogates, so U+DC80-U+DCFF
        # doesn't go through our error handler
        encoded = []
        for index, ch in enumerate(fn):
            code = ord(ch)
            if 0xD800 <= code <= 0xDFFF:
                if 0xDC80 <= code <= 0xDCFF:
                    ch = bytes_chr(code - 0xDC00)
                    encoded.append(ch)
                else:
                    raise UnicodeEncodeError(
                        FS_ENCODING,
                        fn, index, index+1, 'surrogates not allowed')
            else:
                ch_utf8 = ch.encode('utf-8')
                encoded.append(ch_utf8)
        return bytes().join(encoded)
    else:
        return fn.encode(FS_ENCODING, FS_ERRORS)

def decodefilename(fn):
    return fn.decode(FS_ENCODING, FS_ERRORS)

FS_ENCODING = 'ascii'; fn = b('[abc\xff]'); encoded = u('[abc\udcff]')
# FS_ENCODING = 'cp932'; fn = b('[abc\x81\x00]'); encoded = u('[abc\udc81\x00]')
# FS_ENCODING = 'UTF-8'; fn = b('[abc\xff]'); encoded = u('[abc\udcff]')


# normalize the filesystem encoding name.
# For example, we expect "utf-8", not "UTF8".
FS_ENCODING = codecs.lookup(FS_ENCODING).name


def register_surrogateescape():
    """
    Registers the surrogateescape error handler on Python 2 (only)
    """
    if PY3:
        return
    try:
        codecs.lookup_error(FS_ERRORS)
    except LookupError:
        codecs.register_error(FS_ERRORS, surrogateescape_handler)


try:
    b"100644 \x9f\0aaa".decode(defenc, "surrogateescape")
except Exception:
    register_surrogateescape()
