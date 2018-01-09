# diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import re

from git.cmd import handle_process_output
from git.compat import (
    defenc,
    PY3
)
from git.util import finalize_process, hex_to_bin

from .compat import binary_type
from .objects.blob import Blob
from .objects.util import mode_str_to_int


__all__ = ('Diffable', 'DiffIndex', 'Diff', 'NULL_TREE')

# Special object to compare against the empty tree in diffs
NULL_TREE = object()

_octal_byte_re = re.compile(b'\\\\([0-9]{3})')


def _octal_repl(matchobj):
    value = matchobj.group(1)
    value = int(value, 8)
    if PY3:
        value = bytes(bytearray((value,)))
    else:
        value = chr(value)
    return value


def decode_path(path, has_ab_prefix=True):
    if path == b'/dev/null':
        return None

    if path.startswith(b'"') and path.endswith(b'"'):
        path = (path[1:-1].replace(b'\\n', b'\n')
                          .replace(b'\\t', b'\t')
                          .replace(b'\\"', b'"')
                          .replace(b'\\\\', b'\\'))

    path = _octal_byte_re.sub(_octal_repl, path)

    if has_ab_prefix:
        assert path.startswith(b'a/') or path.startswith(b'b/')
        path = path[2:]

    return path


class Diffable(object):

    """Common interface for all object that can be diffed against another object of compatible type.

    :note:
        Subclasses require a repo member as it is the case for Object instances, for practical
        reasons we do not derive from Object."""
    __slots__ = tuple()

    # standin indicating you want to diff against the index
    class Index(object):
        pass

    def _process_diff_args(self, args):
        """
        :return:
            possibly altered version of the given args list.
            Method is called right before git command execution.
            Subclasses can use it to alter the behaviour of the superclass"""
        return args

    def diff(self, other=Index, paths=None, create_patch=False, **kwargs):
        """Creates diffs between two items being trees, trees and index or an
        index and the working tree. It will detect renames automatically.

        :param other:
            Is the item to compare us with.
            If None, we will be compared to the working tree.
            If Treeish, it will be compared against the respective tree
            If Index ( type ), it will be compared against the index.
            If git.NULL_TREE, it will compare against the empty tree.
            It defaults to Index to assure the method will not by-default fail
            on bare repositories.

        :param paths:
            is a list of paths or a single path to limit the diff to.
            It will only include at least one of the given path or paths.

        :param create_patch:
            If True, the returned Diff contains a detailed patch that if applied
            makes the self to other. Patches are somewhat costly as blobs have to be read
            and diffed.

        :param kwargs:
            Additional arguments passed to git-diff, such as
            R=True to swap both sides of the diff.

        :return: git.DiffIndex

        :note:
            On a bare repository, 'other' needs to be provided as Index or as
            as Tree/Commit, or a git command error will occur"""
        args = list()
        args.append("--abbrev=40")        # we need full shas
        args.append("--full-index")       # get full index paths, not only filenames

        args.append("-M")                 # check for renames, in both formats
        if create_patch:
            args.append("-p")
        else:
            args.append("--raw")

        # in any way, assure we don't see colored output,
        # fixes https://github.com/gitpython-developers/GitPython/issues/172
        args.append('--no-color')

        if paths is not None and not isinstance(paths, (tuple, list)):
            paths = [paths]

        diff_cmd = self.repo.git.diff
        if other is self.Index:
            args.insert(0, '--cached')
        elif other is NULL_TREE:
            args.insert(0, '-r')  # recursive diff-tree
            args.insert(0, '--root')
            diff_cmd = self.repo.git.diff_tree
        elif other is not None:
            args.insert(0, '-r')  # recursive diff-tree
            args.insert(0, other)
            diff_cmd = self.repo.git.diff_tree

        args.insert(0, self)

        # paths is list here or None
        if paths:
            args.append("--")
            args.extend(paths)
        # END paths handling

        kwargs['as_process'] = True
        proc = diff_cmd(*self._process_diff_args(args), **kwargs)

        diff_method = (Diff._index_from_patch_format
                       if create_patch
                       else Diff._index_from_raw_format)
        index = diff_method(self.repo, proc)

        proc.wait()
        return index


class DiffIndex(list):

    """Implements an Index for diffs, allowing a list of Diffs to be queried by
    the diff properties.

    The class improves the diff handling convenience"""
    # change type invariant identifying possible ways a blob can have changed
    # A = Added
    # D = Deleted
    # R = Renamed
    # M = modified
    change_type = ("A", "D", "R", "M")

    def iter_change_type(self, change_type):
        """
        :return:
            iterator yielding Diff instances that match the given change_type

        :param change_type:
            Member of DiffIndex.change_type, namely:

            * 'A' for added paths
            * 'D' for deleted paths
            * 'R' for renamed paths
            * 'M' for paths with modified data"""
        if change_type not in self.change_type:
            raise ValueError("Invalid change type: %s" % change_type)

        for diff in self:
            if diff.change_type == change_type:
                yield diff
            elif change_type == "A" and diff.new_file:
                yield diff
            elif change_type == "D" and diff.deleted_file:
                yield diff
            elif change_type == "R" and diff.renamed:
                yield diff
            elif change_type == "M" and diff.a_blob and diff.b_blob and diff.a_blob != diff.b_blob:
                yield diff
        # END for each diff


class Diff(object):

    """A Diff contains diff information between two Trees.

    It contains two sides a and b of the diff, members are prefixed with
    "a" and "b" respectively to inidcate that.

    Diffs keep information about the changed blob objects, the file mode, renames,
    deletions and new files.

    There are a few cases where None has to be expected as member variable value:

    ``New File``::

        a_mode is None
        a_blob is None
        a_path is None

    ``Deleted File``::

        b_mode is None
        b_blob is None
        b_path is None

    ``Working Tree Blobs``

        When comparing to working trees, the working tree blob will have a null hexsha
        as a corresponding object does not yet exist. The mode will be null as well.
        But the path will be available though.
        If it is listed in a diff the working tree version of the file must
        be different to the version in the index or tree, and hence has been modified."""

    # precompiled regex
    re_header = re.compile(br"""
                                ^diff[ ]--git
                                    [ ](?P<a_path_fallback>"?a/.+?"?)[ ](?P<b_path_fallback>"?b/.+?"?)\n
                                (?:^old[ ]mode[ ](?P<old_mode>\d+)\n
                                   ^new[ ]mode[ ](?P<new_mode>\d+)(?:\n|$))?
                                (?:^similarity[ ]index[ ]\d+%\n
                                   ^rename[ ]from[ ](?P<rename_from>.*)\n
                                   ^rename[ ]to[ ](?P<rename_to>.*)(?:\n|$))?
                                (?:^new[ ]file[ ]mode[ ](?P<new_file_mode>.+)(?:\n|$))?
                                (?:^deleted[ ]file[ ]mode[ ](?P<deleted_file_mode>.+)(?:\n|$))?
                                (?:^index[ ](?P<a_blob_id>[0-9A-Fa-f]+)
                                    \.\.(?P<b_blob_id>[0-9A-Fa-f]+)[ ]?(?P<b_mode>.+)?(?:\n|$))?
                                (?:^---[ ](?P<a_path>[^\t\n\r\f\v]*)[\t\r\f\v]*(?:\n|$))?
                                (?:^\+\+\+[ ](?P<b_path>[^\t\n\r\f\v]*)[\t\r\f\v]*(?:\n|$))?
                            """, re.VERBOSE | re.MULTILINE)
    # can be used for comparisons
    NULL_HEX_SHA = "0" * 40
    NULL_BIN_SHA = b"\0" * 20

    __slots__ = ("a_blob", "b_blob", "a_mode", "b_mode", "a_rawpath", "b_rawpath",
                 "new_file", "deleted_file", "raw_rename_from", "raw_rename_to",
                 "diff", "change_type")

    def __init__(self, repo, a_rawpath, b_rawpath, a_blob_id, b_blob_id, a_mode,
                 b_mode, new_file, deleted_file, raw_rename_from,
                 raw_rename_to, diff, change_type):

        self.a_mode = a_mode
        self.b_mode = b_mode

        assert a_rawpath is None or isinstance(a_rawpath, binary_type)
        assert b_rawpath is None or isinstance(b_rawpath, binary_type)
        self.a_rawpath = a_rawpath
        self.b_rawpath = b_rawpath

        if self.a_mode:
            self.a_mode = mode_str_to_int(self.a_mode)
        if self.b_mode:
            self.b_mode = mode_str_to_int(self.b_mode)

        if a_blob_id is None or a_blob_id == self.NULL_HEX_SHA:
            self.a_blob = None
        else:
            self.a_blob = Blob(repo, hex_to_bin(a_blob_id), mode=self.a_mode, path=self.a_path)

        if b_blob_id is None or b_blob_id == self.NULL_HEX_SHA:
            self.b_blob = None
        else:
            self.b_blob = Blob(repo, hex_to_bin(b_blob_id), mode=self.b_mode, path=self.b_path)

        self.new_file = new_file
        self.deleted_file = deleted_file

        # be clear and use None instead of empty strings
        assert raw_rename_from is None or isinstance(raw_rename_from, binary_type)
        assert raw_rename_to is None or isinstance(raw_rename_to, binary_type)
        self.raw_rename_from = raw_rename_from or None
        self.raw_rename_to = raw_rename_to or None

        self.diff = diff
        self.change_type = change_type

    def __eq__(self, other):
        for name in self.__slots__:
            if getattr(self, name) != getattr(other, name):
                return False
        # END for each name
        return True

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(tuple(getattr(self, n) for n in self.__slots__))

    def __str__(self):
        h = "%s"
        if self.a_blob:
            h %= self.a_blob.path
        elif self.b_blob:
            h %= self.b_blob.path

        msg = ''
        line = None          # temp line
        line_length = 0      # line length
        for b, n in zip((self.a_blob, self.b_blob), ('lhs', 'rhs')):
            if b:
                line = "\n%s: %o | %s" % (n, b.mode, b.hexsha)
            else:
                line = "\n%s: None" % n
            # END if blob is not None
            line_length = max(len(line), line_length)
            msg += line
        # END for each blob

        # add headline
        h += '\n' + '=' * line_length

        if self.deleted_file:
            msg += '\nfile deleted in rhs'
        if self.new_file:
            msg += '\nfile added in rhs'
        if self.rename_from:
            msg += '\nfile renamed from %r' % self.rename_from
        if self.rename_to:
            msg += '\nfile renamed to %r' % self.rename_to
        if self.diff:
            msg += '\n---'
            try:
                msg += self.diff.decode(defenc)
            except UnicodeDecodeError:
                msg += 'OMITTED BINARY DATA'
            # end handle encoding
            msg += '\n---'
        # END diff info

        # Python2 silliness: have to assure we convert our likely to be unicode object to a string with the
        # right encoding. Otherwise it tries to convert it using ascii, which may fail ungracefully
        res = h + msg
        if not PY3:
            res = res.encode(defenc)
        # end
        return res

    @property
    def a_path(self):
        return self.a_rawpath.decode(defenc, 'replace') if self.a_rawpath else None

    @property
    def b_path(self):
        return self.b_rawpath.decode(defenc, 'replace') if self.b_rawpath else None

    @property
    def rename_from(self):
        return self.raw_rename_from.decode(defenc, 'replace') if self.raw_rename_from else None

    @property
    def rename_to(self):
        return self.raw_rename_to.decode(defenc, 'replace') if self.raw_rename_to else None

    @property
    def renamed(self):
        """:returns: True if the blob of our diff has been renamed
        :note: This property is deprecated, please use ``renamed_file`` instead.
        """
        return self.renamed_file

    @property
    def renamed_file(self):
        """:returns: True if the blob of our diff has been renamed
        :note: This property is deprecated, please use ``renamed_file`` instead.
        """
        return self.rename_from != self.rename_to

    @classmethod
    def _pick_best_path(cls, path_match, rename_match, path_fallback_match):
        if path_match:
            return decode_path(path_match)

        if rename_match:
            return decode_path(rename_match, has_ab_prefix=False)

        if path_fallback_match:
            return decode_path(path_fallback_match)

        return None

    @classmethod
    def _index_from_patch_format(cls, repo, proc):
        """Create a new DiffIndex from the given text which must be in patch format
        :param repo: is the repository we are operating on - it is required
        :param stream: result of 'git diff' as a stream (supporting file protocol)
        :return: git.DiffIndex """

        ## FIXME: Here SLURPING raw, need to re-phrase header-regexes linewise.
        text = []
        handle_process_output(proc, text.append, None, finalize_process, decode_streams=False)

        # for now, we have to bake the stream
        text = b''.join(text)
        index = DiffIndex()
        previous_header = None
        for header in cls.re_header.finditer(text):
            a_path_fallback, b_path_fallback, \
                old_mode, new_mode, \
                rename_from, rename_to, \
                new_file_mode, deleted_file_mode, \
                a_blob_id, b_blob_id, b_mode, \
                a_path, b_path = header.groups()

            new_file, deleted_file = bool(new_file_mode), bool(deleted_file_mode)

            a_path = cls._pick_best_path(a_path, rename_from, a_path_fallback)
            b_path = cls._pick_best_path(b_path, rename_to, b_path_fallback)

            # Our only means to find the actual text is to see what has not been matched by our regex,
            # and then retro-actively assign it to our index
            if previous_header is not None:
                index[-1].diff = text[previous_header.end():header.start()]
            # end assign actual diff

            # Make sure the mode is set if the path is set. Otherwise the resulting blob is invalid
            # We just use the one mode we should have parsed
            a_mode = old_mode or deleted_file_mode or (a_path and (b_mode or new_mode or new_file_mode))
            b_mode = b_mode or new_mode or new_file_mode or (b_path and a_mode)
            index.append(Diff(repo,
                              a_path,
                              b_path,
                              a_blob_id and a_blob_id.decode(defenc),
                              b_blob_id and b_blob_id.decode(defenc),
                              a_mode and a_mode.decode(defenc),
                              b_mode and b_mode.decode(defenc),
                              new_file, deleted_file,
                              rename_from,
                              rename_to,
                              None, None))

            previous_header = header
        # end for each header we parse
        if index:
            index[-1].diff = text[header.end():]
        # end assign last diff

        return index

    @classmethod
    def _index_from_raw_format(cls, repo, proc):
        """Create a new DiffIndex from the given stream which must be in raw format.
        :return: git.DiffIndex"""
        # handles
        # :100644 100644 687099101... 37c5e30c8... M    .gitignore

        index = DiffIndex()

        def handle_diff_line(line):
            line = line.decode(defenc)
            if not line.startswith(":"):
                return

            meta, _, path = line[1:].partition('\t')
            old_mode, new_mode, a_blob_id, b_blob_id, change_type = meta.split(None, 4)
            path = path.strip()
            a_path = path.encode(defenc)
            b_path = path.encode(defenc)
            deleted_file = False
            new_file = False
            rename_from = None
            rename_to = None

            # NOTE: We cannot conclude from the existence of a blob to change type
            # as diffs with the working do not have blobs yet
            if change_type == 'D':
                b_blob_id = None
                deleted_file = True
            elif change_type == 'A':
                a_blob_id = None
                new_file = True
            elif change_type[0] == 'R':     # parses RXXX, where XXX is a confidence value
                a_path, b_path = path.split('\t', 1)
                a_path = a_path.encode(defenc)
                b_path = b_path.encode(defenc)
                rename_from, rename_to = a_path, b_path
            # END add/remove handling

            diff = Diff(repo, a_path, b_path, a_blob_id, b_blob_id, old_mode, new_mode,
                        new_file, deleted_file, rename_from, rename_to, '', change_type)
            index.append(diff)

        handle_process_output(proc, handle_diff_line, None, finalize_process, decode_streams=False)

        return index
