import sys

PY3 = sys.version_info[0] == 3

try:
    from itertools import izip
    xrange = xrange
except ImportError:
    # py3
    izip = zip
    xrange = range
# end handle python version

try:
    # Python 2
    buffer = buffer
    memoryview = buffer
    # Assume no memory view ...
    def to_bytes(i):
        return i
except NameError:
    # Python 3 has no `buffer`; only `memoryview`
    # However, it's faster to just slice the object directly, maybe it keeps a view internally
    def buffer(obj, offset, size=None):
        if size is None:
            # return memoryview(obj)[offset:]
            return obj[offset:]
        else:
            # return memoryview(obj)[offset:offset+size]
            return obj[offset:offset + size]
    # end buffer reimplementation
    # smmap can return memory view objects, which can't be compared as buffers/bytes can ... 
    def to_bytes(i):
        if isinstance(i, memoryview):
            return i.tobytes()
        return i

    memoryview = memoryview

try:
    MAXSIZE = sys.maxint
except AttributeError:
    MAXSIZE = sys.maxsize
