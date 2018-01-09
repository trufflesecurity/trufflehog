# index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import glob
from io import BytesIO
import os
from stat import S_ISLNK
import subprocess
import sys
import tempfile

from git.compat import (
    izip,
    xrange,
    string_types,
    force_bytes,
    defenc,
    mviter,
    is_win
)
from git.exc import (
    GitCommandError,
    CheckoutError,
    InvalidGitRepositoryError
)
from git.objects import (
    Blob,
    Submodule,
    Tree,
    Object,
    Commit,
)
from git.objects.util import Serializable
from git.util import (
    LazyMixin,
    LockedFD,
    join_path_native,
    file_contents_ro,
    to_native_path_linux,
    unbare_repo,
    to_bin_sha
)
from gitdb.base import IStream
from gitdb.db import MemoryDB

import git.diff as diff
import os.path as osp

from .fun import (
    entry_key,
    write_cache,
    read_cache,
    aggressive_tree_merge,
    write_tree_from_cache,
    stat_mode_to_index_mode,
    S_IFGITLINK,
    run_commit_hook
)
from .typ import (
    BaseIndexEntry,
    IndexEntry,
)
from .util import (
    TemporaryFileSwap,
    post_clear_cache,
    default_index,
    git_working_dir
)


__all__ = ('IndexFile', 'CheckoutError')


class IndexFile(LazyMixin, diff.Diffable, Serializable):

    """
    Implements an Index that can be manipulated using a native implementation in
    order to save git command function calls wherever possible.

    It provides custom merging facilities allowing to merge without actually changing
    your index or your working tree. This way you can perform own test-merges based
    on the index only without having to deal with the working copy. This is useful
    in case of partial working trees.

    ``Entries``

    The index contains an entries dict whose keys are tuples of type IndexEntry
    to facilitate access.

    You may read the entries dict or manipulate it using IndexEntry instance, i.e.::

        index.entries[index.entry_key(index_entry_instance)] = index_entry_instance

    Make sure you use index.write() once you are done manipulating the index directly
    before operating on it using the git command"""
    __slots__ = ("repo", "version", "entries", "_extension_data", "_file_path")
    _VERSION = 2            # latest version we support
    S_IFGITLINK = S_IFGITLINK  # a submodule

    def __init__(self, repo, file_path=None):
        """Initialize this Index instance, optionally from the given ``file_path``.
        If no file_path is given, we will be created from the current index file.

        If a stream is not given, the stream will be initialized from the current
        repository's index on demand."""
        self.repo = repo
        self.version = self._VERSION
        self._extension_data = b''
        self._file_path = file_path or self._index_path()

    def _set_cache_(self, attr):
        if attr == "entries":
            # read the current index
            # try memory map for speed
            lfd = LockedFD(self._file_path)
            ok = False
            try:
                fd = lfd.open(write=False, stream=False)
                ok = True
            except OSError:
                # in new repositories, there may be no index, which means we are empty
                self.entries = dict()
                return
            finally:
                if not ok:
                    lfd.rollback()
            # END exception handling

            # Here it comes: on windows in python 2.5, memory maps aren't closed properly
            # Hence we are in trouble if we try to delete a file that is memory mapped,
            # which happens during read-tree.
            # In this case, we will just read the memory in directly.
            # Its insanely bad ... I am disappointed !
            allow_mmap = (is_win or sys.version_info[1] > 5)
            stream = file_contents_ro(fd, stream=True, allow_mmap=allow_mmap)

            try:
                self._deserialize(stream)
            finally:
                lfd.rollback()
                # The handles will be closed on destruction
            # END read from default index on demand
        else:
            super(IndexFile, self)._set_cache_(attr)

    def _index_path(self):
        return join_path_native(self.repo.git_dir, "index")

    @property
    def path(self):
        """ :return: Path to the index file we are representing """
        return self._file_path

    def _delete_entries_cache(self):
        """Safely clear the entries cache so it can be recreated"""
        try:
            del(self.entries)
        except AttributeError:
            # fails in python 2.6.5 with this exception
            pass
        # END exception handling

    #{ Serializable Interface

    def _deserialize(self, stream):
        """Initialize this instance with index values read from the given stream"""
        self.version, self.entries, self._extension_data, conten_sha = read_cache(stream)  # @UnusedVariable
        return self

    def _entries_sorted(self):
        """:return: list of entries, in a sorted fashion, first by path, then by stage"""
        return sorted(self.entries.values(), key=lambda e: (e.path, e.stage))

    def _serialize(self, stream, ignore_extension_data=False):
        entries = self._entries_sorted()
        extension_data = self._extension_data
        if ignore_extension_data:
            extension_data = None
        write_cache(entries, stream, extension_data)
        return self

    #} END serializable interface

    def write(self, file_path=None, ignore_extension_data=False):
        """Write the current state to our file path or to the given one

        :param file_path:
            If None, we will write to our stored file path from which we have
            been initialized. Otherwise we write to the given file path.
            Please note that this will change the file_path of this index to
            the one you gave.

        :param ignore_extension_data:
            If True, the TREE type extension data read in the index will not
            be written to disk. NOTE that no extension data is actually written.
            Use this if you have altered the index and
            would like to use git-write-tree afterwards to create a tree
            representing your written changes.
            If this data is present in the written index, git-write-tree
            will instead write the stored/cached tree.
            Alternatively, use IndexFile.write_tree() to handle this case
            automatically

        :return: self"""
        # make sure we have our entries read before getting a write lock
        # else it would be done when streaming. This can happen
        # if one doesn't change the index, but writes it right away
        self.entries
        lfd = LockedFD(file_path or self._file_path)
        stream = lfd.open(write=True, stream=True)

        ok = False
        try:
            self._serialize(stream, ignore_extension_data)
            ok = True
        finally:
            if not ok:
                lfd.rollback()

        lfd.commit()

        # make sure we represent what we have written
        if file_path is not None:
            self._file_path = file_path

    @post_clear_cache
    @default_index
    def merge_tree(self, rhs, base=None):
        """Merge the given rhs treeish into the current index, possibly taking
        a common base treeish into account.

        As opposed to the from_tree_ method, this allows you to use an already
        existing tree as the left side of the merge

        :param rhs:
            treeish reference pointing to the 'other' side of the merge.

        :param base:
            optional treeish reference pointing to the common base of 'rhs' and
            this index which equals lhs

        :return:
            self ( containing the merge and possibly unmerged entries in case of
            conflicts )

        :raise GitCommandError:
            If there is a merge conflict. The error will
            be raised at the first conflicting path. If you want to have proper
            merge resolution to be done by yourself, you have to commit the changed
            index ( or make a valid tree from it ) and retry with a three-way
            index.from_tree call. """
        # -i : ignore working tree status
        # --aggressive : handle more merge cases
        # -m : do an actual merge
        args = ["--aggressive", "-i", "-m"]
        if base is not None:
            args.append(base)
        args.append(rhs)

        self.repo.git.read_tree(args)
        return self

    @classmethod
    def new(cls, repo, *tree_sha):
        """ Merge the given treeish revisions into a new index which is returned.
        This method behaves like git-read-tree --aggressive when doing the merge.

        :param repo: The repository treeish are located in.

        :param tree_sha:
            20 byte or 40 byte tree sha or tree objects

        :return:
            New IndexFile instance. Its path will be undefined.
            If you intend to write such a merged Index, supply an alternate file_path
            to its 'write' method."""
        base_entries = aggressive_tree_merge(repo.odb, [to_bin_sha(str(t)) for t in tree_sha])

        inst = cls(repo)
        # convert to entries dict
        entries = dict(izip(((e.path, e.stage) for e in base_entries),
                            (IndexEntry.from_base(e) for e in base_entries)))

        inst.entries = entries
        return inst

    @classmethod
    def from_tree(cls, repo, *treeish, **kwargs):
        """Merge the given treeish revisions into a new index which is returned.
        The original index will remain unaltered

        :param repo:
            The repository treeish are located in.

        :param treeish:
            One, two or three Tree Objects, Commits or 40 byte hexshas. The result
            changes according to the amount of trees.
            If 1 Tree is given, it will just be read into a new index
            If 2 Trees are given, they will be merged into a new index using a
            two way merge algorithm. Tree 1 is the 'current' tree, tree 2 is the 'other'
            one. It behaves like a fast-forward.
            If 3 Trees are given, a 3-way merge will be performed with the first tree
            being the common ancestor of tree 2 and tree 3. Tree 2 is the 'current' tree,
            tree 3 is the 'other' one

        :param kwargs:
            Additional arguments passed to git-read-tree

        :return:
            New IndexFile instance. It will point to a temporary index location which
            does not exist anymore. If you intend to write such a merged Index, supply
            an alternate file_path to its 'write' method.

        :note:
            In the three-way merge case, --aggressive will be specified to automatically
            resolve more cases in a commonly correct manner. Specify trivial=True as kwarg
            to override that.

            As the underlying git-read-tree command takes into account the current index,
            it will be temporarily moved out of the way to assure there are no unsuspected
            interferences."""
        if len(treeish) == 0 or len(treeish) > 3:
            raise ValueError("Please specify between 1 and 3 treeish, got %i" % len(treeish))

        arg_list = list()
        # ignore that working tree and index possibly are out of date
        if len(treeish) > 1:
            # drop unmerged entries when reading our index and merging
            arg_list.append("--reset")
            # handle non-trivial cases the way a real merge does
            arg_list.append("--aggressive")
        # END merge handling

        # tmp file created in git home directory to be sure renaming
        # works - /tmp/ dirs could be on another device
        tmp_index = tempfile.mktemp('', '', repo.git_dir)
        arg_list.append("--index-output=%s" % tmp_index)
        arg_list.extend(treeish)

        # move current index out of the way - otherwise the merge may fail
        # as it considers existing entries. moving it essentially clears the index.
        # Unfortunately there is no 'soft' way to do it.
        # The TemporaryFileSwap assure the original file get put back
        index_handler = TemporaryFileSwap(join_path_native(repo.git_dir, 'index'))
        try:
            repo.git.read_tree(*arg_list, **kwargs)
            index = cls(repo, tmp_index)
            index.entries       # force it to read the file as we will delete the temp-file
            del(index_handler)  # release as soon as possible
        finally:
            if osp.exists(tmp_index):
                os.remove(tmp_index)
        # END index merge handling

        return index

    # UTILITIES
    @unbare_repo
    def _iter_expand_paths(self, paths):
        """Expand the directories in list of paths to the corresponding paths accordingly,

        Note: git will add items multiple times even if a glob overlapped
        with manually specified paths or if paths where specified multiple
        times - we respect that and do not prune"""
        def raise_exc(e):
            raise e
        r = self.repo.working_tree_dir
        rs = r + os.sep
        for path in paths:
            abs_path = path
            if not osp.isabs(abs_path):
                abs_path = osp.join(r, path)
            # END make absolute path

            try:
                st = os.lstat(abs_path)     # handles non-symlinks as well
            except OSError:
                # the lstat call may fail as the path may contain globs as well
                pass
            else:
                if S_ISLNK(st.st_mode):
                    yield abs_path.replace(rs, '')
                    continue
            # end check symlink

            # resolve globs if possible
            if '?' in path or '*' in path or '[' in path:
                resolved_paths = glob.glob(abs_path)
                # not abs_path in resolved_paths:
                #   a glob() resolving to the same path we are feeding it with
                #   is a glob() that failed to resolve. If we continued calling
                #   ourselves we'd endlessly recurse. If the condition below
                #   evaluates to true then we are likely dealing with a file
                #   whose name contains wildcard characters.
                if abs_path not in resolved_paths:
                    for f in self._iter_expand_paths(glob.glob(abs_path)):
                        yield f.replace(rs, '')
                    continue
            # END glob handling
            try:
                for root, dirs, files in os.walk(abs_path, onerror=raise_exc):  # @UnusedVariable
                    for rela_file in files:
                        # add relative paths only
                        yield osp.join(root.replace(rs, ''), rela_file)
                    # END for each file in subdir
                # END for each subdirectory
            except OSError:
                # was a file or something that could not be iterated
                yield path.replace(rs, '')
            # END path exception handling
        # END for each path

    def _write_path_to_stdin(self, proc, filepath, item, fmakeexc, fprogress,
                             read_from_stdout=True):
        """Write path to proc.stdin and make sure it processes the item, including progress.

        :return: stdout string
        :param read_from_stdout: if True, proc.stdout will be read after the item
            was sent to stdin. In that case, it will return None
        :note: There is a bug in git-update-index that prevents it from sending
            reports just in time. This is why we have a version that tries to
            read stdout and one which doesn't. In fact, the stdout is not
            important as the piped-in files are processed anyway and just in time
        :note: Newlines are essential here, gits behaviour is somewhat inconsistent
            on this depending on the version, hence we try our best to deal with
            newlines carefully. Usually the last newline will not be sent, instead
            we will close stdin to break the pipe."""

        fprogress(filepath, False, item)
        rval = None
        try:
            proc.stdin.write(("%s\n" % filepath).encode(defenc))
        except IOError:
            # pipe broke, usually because some error happened
            raise fmakeexc()
        # END write exception handling
        proc.stdin.flush()
        if read_from_stdout:
            rval = proc.stdout.readline().strip()
        fprogress(filepath, True, item)
        return rval

    def iter_blobs(self, predicate=lambda t: True):
        """
        :return: Iterator yielding tuples of Blob objects and stages, tuple(stage, Blob)

        :param predicate:
            Function(t) returning True if tuple(stage, Blob) should be yielded by the
            iterator. A default filter, the BlobFilter, allows you to yield blobs
            only if they match a given list of paths. """
        for entry in mviter(self.entries):
            blob = entry.to_blob(self.repo)
            blob.size = entry.size
            output = (entry.stage, blob)
            if predicate(output):
                yield output
        # END for each entry

    def unmerged_blobs(self):
        """
        :return:
            Iterator yielding dict(path : list( tuple( stage, Blob, ...))), being
            a dictionary associating a path in the index with a list containing
            sorted stage/blob pairs

        :note:
            Blobs that have been removed in one side simply do not exist in the
            given stage. I.e. a file removed on the 'other' branch whose entries
            are at stage 3 will not have a stage 3 entry.
        """
        is_unmerged_blob = lambda t: t[0] != 0
        path_map = dict()
        for stage, blob in self.iter_blobs(is_unmerged_blob):
            path_map.setdefault(blob.path, list()).append((stage, blob))
        # END for each unmerged blob
        for l in mviter(path_map):
            l.sort()
        return path_map

    @classmethod
    def entry_key(cls, *entry):
        return entry_key(*entry)

    def resolve_blobs(self, iter_blobs):
        """Resolve the blobs given in blob iterator. This will effectively remove the
        index entries of the respective path at all non-null stages and add the given
        blob as new stage null blob.

        For each path there may only be one blob, otherwise a ValueError will be raised
        claiming the path is already at stage 0.

        :raise ValueError: if one of the blobs already existed at stage 0
        :return: self

        :note:
            You will have to write the index manually once you are done, i.e.
            index.resolve_blobs(blobs).write()
        """
        for blob in iter_blobs:
            stage_null_key = (blob.path, 0)
            if stage_null_key in self.entries:
                raise ValueError("Path %r already exists at stage 0" % blob.path)
            # END assert blob is not stage 0 already

            # delete all possible stages
            for stage in (1, 2, 3):
                try:
                    del(self.entries[(blob.path, stage)])
                except KeyError:
                    pass
                # END ignore key errors
            # END for each possible stage

            self.entries[stage_null_key] = IndexEntry.from_blob(blob)
        # END for each blob

        return self

    def update(self):
        """Reread the contents of our index file, discarding all cached information
        we might have.

        :note: This is a possibly dangerious operations as it will discard your changes
            to index.entries
        :return: self"""
        self._delete_entries_cache()
        # allows to lazily reread on demand
        return self

    def write_tree(self):
        """Writes this index to a corresponding Tree object into the repository's
        object database and return it.

        :return: Tree object representing this index
        :note: The tree will be written even if one or more objects the tree refers to
            does not yet exist in the object database. This could happen if you added
            Entries to the index directly.
        :raise ValueError: if there are no entries in the cache
        :raise UnmergedEntriesError: """
        # we obtain no lock as we just flush our contents to disk as tree
        # If we are a new index, the entries access will load our data accordingly
        mdb = MemoryDB()
        entries = self._entries_sorted()
        binsha, tree_items = write_tree_from_cache(entries, mdb, slice(0, len(entries)))

        # copy changed trees only
        mdb.stream_copy(mdb.sha_iter(), self.repo.odb)

        # note: additional deserialization could be saved if write_tree_from_cache
        # would return sorted tree entries
        root_tree = Tree(self.repo, binsha, path='')
        root_tree._cache = tree_items
        return root_tree

    def _process_diff_args(self, args):
        try:
            args.pop(args.index(self))
        except IndexError:
            pass
        # END remove self
        return args

    def _to_relative_path(self, path):
        """:return: Version of path relative to our git directory or raise ValueError
        if it is not within our git direcotory"""
        if not osp.isabs(path):
            return path
        if self.repo.bare:
            raise InvalidGitRepositoryError("require non-bare repository")
        relative_path = path.replace(self.repo.working_tree_dir + os.sep, "")
        if relative_path == path:
            raise ValueError("Absolute path %r is not in git repository at %r" % (path, self.repo.working_tree_dir))
        return relative_path

    def _preprocess_add_items(self, items):
        """ Split the items into two lists of path strings and BaseEntries. """
        paths = list()
        entries = list()

        for item in items:
            if isinstance(item, string_types):
                paths.append(self._to_relative_path(item))
            elif isinstance(item, (Blob, Submodule)):
                entries.append(BaseIndexEntry.from_blob(item))
            elif isinstance(item, BaseIndexEntry):
                entries.append(item)
            else:
                raise TypeError("Invalid Type: %r" % item)
        # END for each item
        return (paths, entries)

    def _store_path(self, filepath, fprogress):
        """Store file at filepath in the database and return the base index entry
        Needs the git_working_dir decorator active ! This must be assured in the calling code"""
        st = os.lstat(filepath)     # handles non-symlinks as well
        if S_ISLNK(st.st_mode):
            # in PY3, readlink is string, but we need bytes. In PY2, it's just OS encoded bytes, we assume UTF-8
            open_stream = lambda: BytesIO(force_bytes(os.readlink(filepath), encoding=defenc))
        else:
            open_stream = lambda: open(filepath, 'rb')
        with open_stream() as stream:
            fprogress(filepath, False, filepath)
            istream = self.repo.odb.store(IStream(Blob.type, st.st_size, stream))
            fprogress(filepath, True, filepath)
        return BaseIndexEntry((stat_mode_to_index_mode(st.st_mode),
                               istream.binsha, 0, to_native_path_linux(filepath)))

    @unbare_repo
    @git_working_dir
    def _entries_for_paths(self, paths, path_rewriter, fprogress, entries):
        entries_added = list()
        if path_rewriter:
            for path in paths:
                if osp.isabs(path):
                    abspath = path
                    gitrelative_path = path[len(self.repo.working_tree_dir) + 1:]
                else:
                    gitrelative_path = path
                    abspath = osp.join(self.repo.working_tree_dir, gitrelative_path)
                # end obtain relative and absolute paths

                blob = Blob(self.repo, Blob.NULL_BIN_SHA,
                            stat_mode_to_index_mode(os.stat(abspath).st_mode),
                            to_native_path_linux(gitrelative_path))
                # TODO: variable undefined
                entries.append(BaseIndexEntry.from_blob(blob))
            # END for each path
            del(paths[:])
        # END rewrite paths

        # HANDLE PATHS
        assert len(entries_added) == 0
        for filepath in self._iter_expand_paths(paths):
            entries_added.append(self._store_path(filepath, fprogress))
        # END for each filepath
        # END path handling
        return entries_added

    def add(self, items, force=True, fprogress=lambda *args: None, path_rewriter=None,
            write=True, write_extension_data=False):
        """Add files from the working tree, specific blobs or BaseIndexEntries
        to the index.

        :param items:
            Multiple types of items are supported, types can be mixed within one call.
            Different types imply a different handling. File paths may generally be
            relative or absolute.

            - path string
                strings denote a relative or absolute path into the repository pointing to
                an existing file, i.e. CHANGES, lib/myfile.ext, '/home/gitrepo/lib/myfile.ext'.

                Absolute paths must start with working tree directory of this index's repository
                to be considered valid. For example, if it was initialized with a non-normalized path, like
                `/root/repo/../repo`, absolute paths to be added must start with `/root/repo/../repo`.

                Paths provided like this must exist. When added, they will be written
                into the object database.

                PathStrings may contain globs, such as 'lib/__init__*' or can be directories
                like 'lib', the latter ones will add all the files within the dirctory and
                subdirectories.

                This equals a straight git-add.

                They are added at stage 0

            - Blob or Submodule object
                Blobs are added as they are assuming a valid mode is set.
                The file they refer to may or may not exist in the file system, but
                must be a path relative to our repository.

                If their sha is null ( 40*0 ), their path must exist in the file system
                relative to the git repository as an object will be created from
                the data at the path.
                The handling now very much equals the way string paths are processed, except that
                the mode you have set will be kept. This allows you to create symlinks
                by settings the mode respectively and writing the target of the symlink
                directly into the file. This equals a default Linux-Symlink which
                is not dereferenced automatically, except that it can be created on
                filesystems not supporting it as well.

                Please note that globs or directories are not allowed in Blob objects.

                They are added at stage 0

            - BaseIndexEntry or type
                Handling equals the one of Blob objects, but the stage may be
                explicitly set. Please note that Index Entries require binary sha's.

        :param force:
            **CURRENTLY INEFFECTIVE**
            If True, otherwise ignored or excluded files will be
            added anyway.
            As opposed to the git-add command, we enable this flag by default
            as the API user usually wants the item to be added even though
            they might be excluded.

        :param fprogress:
            Function with signature f(path, done=False, item=item) called for each
            path to be added, one time once it is about to be added where done==False
            and once after it was added where done=True.
            item is set to the actual item we handle, either a Path or a BaseIndexEntry
            Please note that the processed path is not guaranteed to be present
            in the index already as the index is currently being processed.

        :param path_rewriter:
            Function with signature (string) func(BaseIndexEntry) function returning a path
            for each passed entry which is the path to be actually recorded for the
            object created from entry.path. This allows you to write an index which
            is not identical to the layout of the actual files on your hard-disk.
            If not None and ``items`` contain plain paths, these paths will be
            converted to Entries beforehand and passed to the path_rewriter.
            Please note that entry.path is relative to the git repository.

        :param write:
            If True, the index will be written once it was altered. Otherwise
            the changes only exist in memory and are not available to git commands.

        :param write_extension_data:
            If True, extension data will be written back to the index. This can lead to issues in case
            it is containing the 'TREE' extension, which will cause the `git commit` command to write an
            old tree, instead of a new one representing the now changed index.
            This doesn't matter if you use `IndexFile.commit()`, which ignores the `TREE` extension altogether.
            You should set it to True if you intend to use `IndexFile.commit()` exclusively while maintaining
            support for third-party extensions. Besides that, you can usually safely ignore the built-in
            extensions when using GitPython on repositories that are not handled manually at all.
            All current built-in extensions are listed here:
            http://opensource.apple.com/source/Git/Git-26/src/git-htmldocs/technical/index-format.txt

        :return:
            List(BaseIndexEntries) representing the entries just actually added.

        :raise OSError:
            if a supplied Path did not exist. Please note that BaseIndexEntry
            Objects that do not have a null sha will be added even if their paths
            do not exist.
        """
        # sort the entries into strings and Entries, Blobs are converted to entries
        # automatically
        # paths can be git-added, for everything else we use git-update-index
        paths, entries = self._preprocess_add_items(items)
        entries_added = list()
        # This code needs a working tree, therefore we try not to run it unless required.
        # That way, we are OK on a bare repository as well.
        # If there are no paths, the rewriter has nothing to do either
        if paths:
            entries_added.extend(self._entries_for_paths(paths, path_rewriter, fprogress, entries))

        # HANDLE ENTRIES
        if entries:
            null_mode_entries = [e for e in entries if e.mode == 0]
            if null_mode_entries:
                raise ValueError(
                    "At least one Entry has a null-mode - please use index.remove to remove files for clarity")
            # END null mode should be remove

            # HANLDE ENTRY OBJECT CREATION
            # create objects if required, otherwise go with the existing shas
            null_entries_indices = [i for i, e in enumerate(entries) if e.binsha == Object.NULL_BIN_SHA]
            if null_entries_indices:
                @git_working_dir
                def handle_null_entries(self):
                    for ei in null_entries_indices:
                        null_entry = entries[ei]
                        new_entry = self._store_path(null_entry.path, fprogress)

                        # update null entry
                        entries[ei] = BaseIndexEntry(
                            (null_entry.mode, new_entry.binsha, null_entry.stage, null_entry.path))
                    # END for each entry index
                # end closure
                handle_null_entries(self)
            # END null_entry handling

            # REWRITE PATHS
            # If we have to rewrite the entries, do so now, after we have generated
            # all object sha's
            if path_rewriter:
                for i, e in enumerate(entries):
                    entries[i] = BaseIndexEntry((e.mode, e.binsha, e.stage, path_rewriter(e)))
                # END for each entry
            # END handle path rewriting

            # just go through the remaining entries and provide progress info
            for i, entry in enumerate(entries):
                progress_sent = i in null_entries_indices
                if not progress_sent:
                    fprogress(entry.path, False, entry)
                    fprogress(entry.path, True, entry)
                # END handle progress
            # END for each enty
            entries_added.extend(entries)
        # END if there are base entries

        # FINALIZE
        # add the new entries to this instance
        for entry in entries_added:
            self.entries[(entry.path, 0)] = IndexEntry.from_base(entry)

        if write:
            self.write(ignore_extension_data=not write_extension_data)
        # END handle write

        return entries_added

    def _items_to_rela_paths(self, items):
        """Returns a list of repo-relative paths from the given items which
        may be absolute or relative paths, entries or blobs"""
        paths = list()
        for item in items:
            if isinstance(item, (BaseIndexEntry, (Blob, Submodule))):
                paths.append(self._to_relative_path(item.path))
            elif isinstance(item, string_types):
                paths.append(self._to_relative_path(item))
            else:
                raise TypeError("Invalid item type: %r" % item)
        # END for each item
        return paths

    @post_clear_cache
    @default_index
    def remove(self, items, working_tree=False, **kwargs):
        """Remove the given items from the index and optionally from
        the working tree as well.

        :param items:
            Multiple types of items are supported which may be be freely mixed.

            - path string
                Remove the given path at all stages. If it is a directory, you must
                specify the r=True keyword argument to remove all file entries
                below it. If absolute paths are given, they will be converted
                to a path relative to the git repository directory containing
                the working tree

                The path string may include globs, such as *.c.

            - Blob Object
                Only the path portion is used in this case.

            - BaseIndexEntry or compatible type
                The only relevant information here Yis the path. The stage is ignored.

        :param working_tree:
            If True, the entry will also be removed from the working tree, physically
            removing the respective file. This may fail if there are uncommitted changes
            in it.

        :param kwargs:
            Additional keyword arguments to be passed to git-rm, such
            as 'r' to allow recursive removal of

        :return:
            List(path_string, ...) list of repository relative paths that have
            been removed effectively.
            This is interesting to know in case you have provided a directory or
            globs. Paths are relative to the repository. """
        args = list()
        if not working_tree:
            args.append("--cached")
        args.append("--")

        # preprocess paths
        paths = self._items_to_rela_paths(items)
        removed_paths = self.repo.git.rm(args, paths, **kwargs).splitlines()

        # process output to gain proper paths
        # rm 'path'
        return [p[4:-1] for p in removed_paths]

    @post_clear_cache
    @default_index
    def move(self, items, skip_errors=False, **kwargs):
        """Rename/move the items, whereas the last item is considered the destination of
        the move operation. If the destination is a file, the first item ( of two )
        must be a file as well. If the destination is a directory, it may be preceded
        by one or more directories or files.

        The working tree will be affected in non-bare repositories.

        :parma items:
            Multiple types of items are supported, please see the 'remove' method
            for reference.
        :param skip_errors:
            If True, errors such as ones resulting from missing source files will
            be skipped.
        :param kwargs:
            Additional arguments you would like to pass to git-mv, such as dry_run
            or force.

        :return:List(tuple(source_path_string, destination_path_string), ...)
            A list of pairs, containing the source file moved as well as its
            actual destination. Relative to the repository root.

        :raise ValueError: If only one item was given
            GitCommandError: If git could not handle your request"""
        args = list()
        if skip_errors:
            args.append('-k')

        paths = self._items_to_rela_paths(items)
        if len(paths) < 2:
            raise ValueError("Please provide at least one source and one destination of the move operation")

        was_dry_run = kwargs.pop('dry_run', kwargs.pop('n', None))
        kwargs['dry_run'] = True

        # first execute rename in dryrun so the command tells us what it actually does
        # ( for later output )
        out = list()
        mvlines = self.repo.git.mv(args, paths, **kwargs).splitlines()

        # parse result - first 0:n/2 lines are 'checking ', the remaining ones
        # are the 'renaming' ones which we parse
        for ln in xrange(int(len(mvlines) / 2), len(mvlines)):
            tokens = mvlines[ln].split(' to ')
            assert len(tokens) == 2, "Too many tokens in %s" % mvlines[ln]

            # [0] = Renaming x
            # [1] = y
            out.append((tokens[0][9:], tokens[1]))
        # END for each line to parse

        # either prepare for the real run, or output the dry-run result
        if was_dry_run:
            return out
        # END handle dryrun

        # now apply the actual operation
        kwargs.pop('dry_run')
        self.repo.git.mv(args, paths, **kwargs)

        return out

    def commit(self, message, parent_commits=None, head=True, author=None,
               committer=None, author_date=None, commit_date=None,
               skip_hooks=False):
        """Commit the current default index file, creating a commit object.
        For more information on the arguments, see tree.commit.

        :note: If you have manually altered the .entries member of this instance,
               don't forget to write() your changes to disk beforehand.
               Passing skip_hooks=True is the equivalent of using `-n`
               or `--no-verify` on the command line.
        :return: Commit object representing the new commit"""
        if not skip_hooks:
            run_commit_hook('pre-commit', self)

            self._write_commit_editmsg(message)
            run_commit_hook('commit-msg', self, self._commit_editmsg_filepath())
            message = self._read_commit_editmsg()
            self._remove_commit_editmsg()
        tree = self.write_tree()
        rval = Commit.create_from_tree(self.repo, tree, message, parent_commits,
                                       head, author=author, committer=committer,
                                       author_date=author_date, commit_date=commit_date)
        if not skip_hooks:
            run_commit_hook('post-commit', self)
        return rval
    
    def _write_commit_editmsg(self, message):
        with open(self._commit_editmsg_filepath(), "wb") as commit_editmsg_file:
            commit_editmsg_file.write(message.encode(defenc))

    def _remove_commit_editmsg(self):
        os.remove(self._commit_editmsg_filepath())

    def _read_commit_editmsg(self):
        with open(self._commit_editmsg_filepath(), "rb") as commit_editmsg_file:
            return commit_editmsg_file.read().decode(defenc)

    def _commit_editmsg_filepath(self):
        return osp.join(self.repo.common_dir, "COMMIT_EDITMSG")

    @classmethod
    def _flush_stdin_and_wait(cls, proc, ignore_stdout=False):
        proc.stdin.flush()
        proc.stdin.close()
        stdout = ''
        if not ignore_stdout:
            stdout = proc.stdout.read()
        proc.stdout.close()
        proc.wait()
        return stdout

    @default_index
    def checkout(self, paths=None, force=False, fprogress=lambda *args: None, **kwargs):
        """Checkout the given paths or all files from the version known to the index into
        the working tree.

        :note: Be sure you have written pending changes using the ``write`` method
            in case you have altered the enties dictionary directly

        :param paths:
            If None, all paths in the index will be checked out. Otherwise an iterable
            of relative or absolute paths or a single path pointing to files or directories
            in the index is expected.

        :param force:
            If True, existing files will be overwritten even if they contain local modifications.
            If False, these will trigger a CheckoutError.

        :param fprogress:
            see Index.add_ for signature and explanation.
            The provided progress information will contain None as path and item if no
            explicit paths are given. Otherwise progress information will be send
            prior and after a file has been checked out

        :param kwargs:
            Additional arguments to be passed to git-checkout-index

        :return:
            iterable yielding paths to files which have been checked out and are
            guaranteed to match the version stored in the index

        :raise CheckoutError:
            If at least one file failed to be checked out. This is a summary,
            hence it will checkout as many files as it can anyway.
            If one of files or directories do not exist in the index
            ( as opposed to the  original git command who ignores them ).
            Raise GitCommandError if error lines could not be parsed - this truly is
            an exceptional state

        .. note:: The checkout is limited to checking out the files in the
            index. Files which are not in the index anymore and exist in
            the working tree will not be deleted. This behaviour is fundamentally
            different to *head.checkout*, i.e. if you want git-checkout like behaviour,
            use head.checkout instead of index.checkout.
            """
        args = ["--index"]
        if force:
            args.append("--force")

        def handle_stderr(proc, iter_checked_out_files):
            stderr = proc.stderr.read()
            if not stderr:
                return
            # line contents:
            stderr = stderr.decode(defenc)
            # git-checkout-index: this already exists
            failed_files = list()
            failed_reasons = list()
            unknown_lines = list()
            endings = (' already exists', ' is not in the cache', ' does not exist at stage', ' is unmerged')
            for line in stderr.splitlines():
                if not line.startswith("git checkout-index: ") and not line.startswith("git-checkout-index: "):
                    is_a_dir = " is a directory"
                    unlink_issue = "unable to unlink old '"
                    already_exists_issue = ' already exists, no checkout'   # created by entry.c:checkout_entry(...)
                    if line.endswith(is_a_dir):
                        failed_files.append(line[:-len(is_a_dir)])
                        failed_reasons.append(is_a_dir)
                    elif line.startswith(unlink_issue):
                        failed_files.append(line[len(unlink_issue):line.rfind("'")])
                        failed_reasons.append(unlink_issue)
                    elif line.endswith(already_exists_issue):
                        failed_files.append(line[:-len(already_exists_issue)])
                        failed_reasons.append(already_exists_issue)
                    else:
                        unknown_lines.append(line)
                    continue
                # END special lines parsing

                for e in endings:
                    if line.endswith(e):
                        failed_files.append(line[20:-len(e)])
                        failed_reasons.append(e)
                        break
                    # END if ending matches
                # END for each possible ending
            # END for each line
            if unknown_lines:
                raise GitCommandError(("git-checkout-index",), 128, stderr)
            if failed_files:
                valid_files = list(set(iter_checked_out_files) - set(failed_files))
                raise CheckoutError(
                    "Some files could not be checked out from the index due to local modifications",
                    failed_files, valid_files, failed_reasons)
        # END stderr handler

        if paths is None:
            args.append("--all")
            kwargs['as_process'] = 1
            fprogress(None, False, None)
            proc = self.repo.git.checkout_index(*args, **kwargs)
            proc.wait()
            fprogress(None, True, None)
            rval_iter = (e.path for e in mviter(self.entries))
            handle_stderr(proc, rval_iter)
            return rval_iter
        else:
            if isinstance(paths, string_types):
                paths = [paths]

            # make sure we have our entries loaded before we start checkout_index
            # which will hold a lock on it. We try to get the lock as well during
            # our entries initialization
            self.entries

            args.append("--stdin")
            kwargs['as_process'] = True
            kwargs['istream'] = subprocess.PIPE
            proc = self.repo.git.checkout_index(args, **kwargs)
            # FIXME: Reading from GIL!
            make_exc = lambda: GitCommandError(("git-checkout-index",) + tuple(args), 128, proc.stderr.read())
            checked_out_files = list()

            for path in paths:
                co_path = to_native_path_linux(self._to_relative_path(path))
                # if the item is not in the index, it could be a directory
                path_is_directory = False

                try:
                    self.entries[(co_path, 0)]
                except KeyError:
                    folder = co_path
                    if not folder.endswith('/'):
                        folder += '/'
                    for entry in mviter(self.entries):
                        if entry.path.startswith(folder):
                            p = entry.path
                            self._write_path_to_stdin(proc, p, p, make_exc,
                                                      fprogress, read_from_stdout=False)
                            checked_out_files.append(p)
                            path_is_directory = True
                        # END if entry is in directory
                    # END for each entry
                # END path exception handlnig

                if not path_is_directory:
                    self._write_path_to_stdin(proc, co_path, path, make_exc,
                                              fprogress, read_from_stdout=False)
                    checked_out_files.append(co_path)
                # END path is a file
            # END for each path
            self._flush_stdin_and_wait(proc, ignore_stdout=True)

            handle_stderr(proc, checked_out_files)
            return checked_out_files
        # END paths handling
        assert "Should not reach this point"

    @default_index
    def reset(self, commit='HEAD', working_tree=False, paths=None, head=False, **kwargs):
        """Reset the index to reflect the tree at the given commit. This will not
        adjust our HEAD reference as opposed to HEAD.reset by default.

        :param commit:
            Revision, Reference or Commit specifying the commit we should represent.
            If you want to specify a tree only, use IndexFile.from_tree and overwrite
            the default index.

        :param working_tree:
            If True, the files in the working tree will reflect the changed index.
            If False, the working tree will not be touched
            Please note that changes to the working copy will be discarded without
            warning !

        :param head:
            If True, the head will be set to the given commit. This is False by default,
            but if True, this method behaves like HEAD.reset.

        :param paths: if given as an iterable of absolute or repository-relative paths,
            only these will be reset to their state at the given commit'ish.
            The paths need to exist at the commit, otherwise an exception will be
            raised.

        :param kwargs:
            Additional keyword arguments passed to git-reset

        .. note:: IndexFile.reset, as opposed to HEAD.reset, will not delete anyfiles
            in order to maintain a consistent working tree. Instead, it will just
            checkout the files according to their state in the index.
            If you want git-reset like behaviour, use *HEAD.reset* instead.

        :return: self """
        # what we actually want to do is to merge the tree into our existing
        # index, which is what git-read-tree does
        new_inst = type(self).from_tree(self.repo, commit)
        if not paths:
            self.entries = new_inst.entries
        else:
            nie = new_inst.entries
            for path in paths:
                path = self._to_relative_path(path)
                try:
                    key = entry_key(path, 0)
                    self.entries[key] = nie[key]
                except KeyError:
                    # if key is not in theirs, it musn't be in ours
                    try:
                        del(self.entries[key])
                    except KeyError:
                        pass
                    # END handle deletion keyerror
                # END handle keyerror
            # END for each path
        # END handle paths
        self.write()

        if working_tree:
            self.checkout(paths=paths, force=True)
        # END handle working tree

        if head:
            self.repo.head.set_commit(self.repo.commit(commit), logmsg="%s: Updating HEAD" % commit)
        # END handle head change

        return self

    @default_index
    def diff(self, other=diff.Diffable.Index, paths=None, create_patch=False, **kwargs):
        """Diff this index against the working copy or a Tree or Commit object

        For a documentation of the parameters and return values, see
        Diffable.diff

        :note:
            Will only work with indices that represent the default git index as
            they have not been initialized with a stream.
        """
        # index against index is always empty
        if other is self.Index:
            return diff.DiffIndex()

        # index against anything but None is a reverse diff with the respective
        # item. Handle existing -R flags properly. Transform strings to the object
        # so that we can call diff on it
        if isinstance(other, string_types):
            other = self.repo.rev_parse(other)
        # END object conversion

        if isinstance(other, Object):
            # invert the existing R flag
            cur_val = kwargs.get('R', False)
            kwargs['R'] = not cur_val
            return other.diff(self.Index, paths, create_patch, **kwargs)
        # END diff against other item handling

        # if other is not None here, something is wrong
        if other is not None:
            raise ValueError("other must be None, Diffable.Index, a Tree or Commit, was %r" % other)

        # diff against working copy - can be handled by superclass natively
        return super(IndexFile, self).diff(other, paths, create_patch, **kwargs)
