# tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.util import join_path
import git.diff as diff
from git.util import to_bin_sha

from . import util
from .base import IndexObject
from .blob import Blob
from .submodule.base import Submodule
from git.compat import string_types

from .fun import (
    tree_entries_from_data,
    tree_to_stream
)

from git.compat import PY3

if PY3:
    cmp = lambda a, b: (a > b) - (a < b)

__all__ = ("TreeModifier", "Tree")


def git_cmp(t1, t2):
    a, b = t1[2], t2[2]
    len_a, len_b = len(a), len(b)
    min_len = min(len_a, len_b)
    min_cmp = cmp(a[:min_len], b[:min_len])

    if min_cmp:
        return min_cmp

    return len_a - len_b


def merge_sort(a, cmp):
    if len(a) < 2:
        return

    mid = len(a) // 2
    lefthalf = a[:mid]
    righthalf = a[mid:]

    merge_sort(lefthalf, cmp)
    merge_sort(righthalf, cmp)

    i = 0
    j = 0
    k = 0

    while i < len(lefthalf) and j < len(righthalf):
        if cmp(lefthalf[i], righthalf[j]) <= 0:
            a[k] = lefthalf[i]
            i = i + 1
        else:
            a[k] = righthalf[j]
            j = j + 1
        k = k + 1

    while i < len(lefthalf):
        a[k] = lefthalf[i]
        i = i + 1
        k = k + 1

    while j < len(righthalf):
        a[k] = righthalf[j]
        j = j + 1
        k = k + 1


class TreeModifier(object):

    """A utility class providing methods to alter the underlying cache in a list-like fashion.

    Once all adjustments are complete, the _cache, which really is a reference to
    the cache of a tree, will be sorted. Assuring it will be in a serializable state"""
    __slots__ = '_cache'

    def __init__(self, cache):
        self._cache = cache

    def _index_by_name(self, name):
        """:return: index of an item with name, or -1 if not found"""
        for i, t in enumerate(self._cache):
            if t[2] == name:
                return i
            # END found item
        # END for each item in cache
        return -1

    #{ Interface
    def set_done(self):
        """Call this method once you are done modifying the tree information.
        It may be called several times, but be aware that each call will cause
        a sort operation
        :return self:"""
        merge_sort(self._cache, git_cmp)
        return self
    #} END interface

    #{ Mutators
    def add(self, sha, mode, name, force=False):
        """Add the given item to the tree. If an item with the given name already
        exists, nothing will be done, but a ValueError will be raised if the
        sha and mode of the existing item do not match the one you add, unless
        force is True

        :param sha: The 20 or 40 byte sha of the item to add
        :param mode: int representing the stat compatible mode of the item
        :param force: If True, an item with your name and information will overwrite
            any existing item with the same name, no matter which information it has
        :return: self"""
        if '/' in name:
            raise ValueError("Name must not contain '/' characters")
        if (mode >> 12) not in Tree._map_id_to_type:
            raise ValueError("Invalid object type according to mode %o" % mode)

        sha = to_bin_sha(sha)
        index = self._index_by_name(name)
        item = (sha, mode, name)
        if index == -1:
            self._cache.append(item)
        else:
            if force:
                self._cache[index] = item
            else:
                ex_item = self._cache[index]
                if ex_item[0] != sha or ex_item[1] != mode:
                    raise ValueError("Item %r existed with different properties" % name)
                # END handle mismatch
            # END handle force
        # END handle name exists
        return self

    def add_unchecked(self, binsha, mode, name):
        """Add the given item to the tree, its correctness is assumed, which
        puts the caller into responsibility to assure the input is correct.
        For more information on the parameters, see ``add``
        :param binsha: 20 byte binary sha"""
        self._cache.append((binsha, mode, name))

    def __delitem__(self, name):
        """Deletes an item with the given name if it exists"""
        index = self._index_by_name(name)
        if index > -1:
            del(self._cache[index])

    #} END mutators


class Tree(IndexObject, diff.Diffable, util.Traversable, util.Serializable):

    """Tree objects represent an ordered list of Blobs and other Trees.

    ``Tree as a list``::

        Access a specific blob using the
        tree['filename'] notation.

        You may as well access by index
        blob = tree[0]
    """

    type = "tree"
    __slots__ = "_cache"

    # actual integer ids for comparison
    commit_id = 0o16     # equals stat.S_IFDIR | stat.S_IFLNK - a directory link
    blob_id = 0o10
    symlink_id = 0o12
    tree_id = 0o04

    _map_id_to_type = {
        commit_id: Submodule,
        blob_id: Blob,
        symlink_id: Blob
        # tree id added once Tree is defined
    }

    def __init__(self, repo, binsha, mode=tree_id << 12, path=None):
        super(Tree, self).__init__(repo, binsha, mode, path)

    @classmethod
    def _get_intermediate_items(cls, index_object):
        if index_object.type == "tree":
            return tuple(index_object._iter_convert_to_object(index_object._cache))
        return tuple()

    def _set_cache_(self, attr):
        if attr == "_cache":
            # Set the data when we need it
            ostream = self.repo.odb.stream(self.binsha)
            self._cache = tree_entries_from_data(ostream.read())
        else:
            super(Tree, self)._set_cache_(attr)
        # END handle attribute

    def _iter_convert_to_object(self, iterable):
        """Iterable yields tuples of (binsha, mode, name), which will be converted
        to the respective object representation"""
        for binsha, mode, name in iterable:
            path = join_path(self.path, name)
            try:
                yield self._map_id_to_type[mode >> 12](self.repo, binsha, mode, path)
            except KeyError:
                raise TypeError("Unknown mode %o found in tree data for path '%s'" % (mode, path))
        # END for each item

    def join(self, file):
        """Find the named object in this tree's contents
        :return: ``git.Blob`` or ``git.Tree`` or ``git.Submodule``

        :raise KeyError: if given file or tree does not exist in tree"""
        msg = "Blob or Tree named %r not found"
        if '/' in file:
            tree = self
            item = self
            tokens = file.split('/')
            for i, token in enumerate(tokens):
                item = tree[token]
                if item.type == 'tree':
                    tree = item
                else:
                    # safety assertion - blobs are at the end of the path
                    if i != len(tokens) - 1:
                        raise KeyError(msg % file)
                    return item
                # END handle item type
            # END for each token of split path
            if item == self:
                raise KeyError(msg % file)
            return item
        else:
            for info in self._cache:
                if info[2] == file:     # [2] == name
                    return self._map_id_to_type[info[1] >> 12](self.repo, info[0], info[1],
                                                               join_path(self.path, info[2]))
            # END for each obj
            raise KeyError(msg % file)
        # END handle long paths

    def __div__(self, file):
        """For PY2 only"""
        return self.join(file)

    def __truediv__(self, file):
        """For PY3 only"""
        return self.join(file)

    @property
    def trees(self):
        """:return: list(Tree, ...) list of trees directly below this tree"""
        return [i for i in self if i.type == "tree"]

    @property
    def blobs(self):
        """:return: list(Blob, ...) list of blobs directly below this tree"""
        return [i for i in self if i.type == "blob"]

    @property
    def cache(self):
        """
        :return: An object allowing to modify the internal cache. This can be used
            to change the tree's contents. When done, make sure you call ``set_done``
            on the tree modifier, or serialization behaviour will be incorrect.
            See the ``TreeModifier`` for more information on how to alter the cache"""
        return TreeModifier(self._cache)

    def traverse(self, predicate=lambda i, d: True,
                 prune=lambda i, d: False, depth=-1, branch_first=True,
                 visit_once=False, ignore_self=1):
        """For documentation, see util.Traversable.traverse
        Trees are set to visit_once = False to gain more performance in the traversal"""
        return super(Tree, self).traverse(predicate, prune, depth, branch_first, visit_once, ignore_self)

    # List protocol
    def __getslice__(self, i, j):
        return list(self._iter_convert_to_object(self._cache[i:j]))

    def __iter__(self):
        return self._iter_convert_to_object(self._cache)

    def __len__(self):
        return len(self._cache)

    def __getitem__(self, item):
        if isinstance(item, int):
            info = self._cache[item]
            return self._map_id_to_type[info[1] >> 12](self.repo, info[0], info[1], join_path(self.path, info[2]))

        if isinstance(item, string_types):
            # compatibility
            return self.join(item)
        # END index is basestring

        raise TypeError("Invalid index type: %r" % item)

    def __contains__(self, item):
        if isinstance(item, IndexObject):
            for info in self._cache:
                if item.binsha == info[0]:
                    return True
                # END compare sha
            # END for each entry
        # END handle item is index object
        # compatibility

        # treat item as repo-relative path
        path = self.path
        for info in self._cache:
            if item == join_path(path, info[2]):
                return True
        # END for each item
        return False

    def __reversed__(self):
        return reversed(self._iter_convert_to_object(self._cache))

    def _serialize(self, stream):
        """Serialize this tree into the stream. Please note that we will assume
        our tree data to be in a sorted state. If this is not the case, serialization
        will not generate a correct tree representation as these are assumed to be sorted
        by algorithms"""
        tree_to_stream(self._cache, stream.write)
        return self

    def _deserialize(self, stream):
        self._cache = tree_entries_from_data(stream.read())
        return self


# END tree

# finalize map definition
Tree._map_id_to_type[Tree.tree_id] = Tree
#
