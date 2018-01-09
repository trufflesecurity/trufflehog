# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module containing module parser implementation able to properly read and write
configuration files"""

import abc
from functools import wraps
import inspect
import logging
import os
import re

from git.compat import (
    string_types,
    FileType,
    defenc,
    force_text,
    with_metaclass,
    PY3
)
from git.odict import OrderedDict
from git.util import LockFile

import os.path as osp


try:
    import ConfigParser as cp
except ImportError:
    # PY3
    import configparser as cp


__all__ = ('GitConfigParser', 'SectionConstraint')


log = logging.getLogger('git.config')
log.addHandler(logging.NullHandler())


class MetaParserBuilder(abc.ABCMeta):

    """Utlity class wrapping base-class methods into decorators that assure read-only properties"""
    def __new__(cls, name, bases, clsdict):
        """
        Equip all base-class methods with a needs_values decorator, and all non-const methods
        with a set_dirty_and_flush_changes decorator in addition to that."""
        kmm = '_mutating_methods_'
        if kmm in clsdict:
            mutating_methods = clsdict[kmm]
            for base in bases:
                methods = (t for t in inspect.getmembers(base, inspect.isroutine) if not t[0].startswith("_"))
                for name, method in methods:
                    if name in clsdict:
                        continue
                    method_with_values = needs_values(method)
                    if name in mutating_methods:
                        method_with_values = set_dirty_and_flush_changes(method_with_values)
                    # END mutating methods handling

                    clsdict[name] = method_with_values
                # END for each name/method pair
            # END for each base
        # END if mutating methods configuration is set

        new_type = super(MetaParserBuilder, cls).__new__(cls, name, bases, clsdict)
        return new_type


def needs_values(func):
    """Returns method assuring we read values (on demand) before we try to access them"""

    @wraps(func)
    def assure_data_present(self, *args, **kwargs):
        self.read()
        return func(self, *args, **kwargs)
    # END wrapper method
    return assure_data_present


def set_dirty_and_flush_changes(non_const_func):
    """Return method that checks whether given non constant function may be called.
    If so, the instance will be set dirty.
    Additionally, we flush the changes right to disk"""

    def flush_changes(self, *args, **kwargs):
        rval = non_const_func(self, *args, **kwargs)
        self._dirty = True
        self.write()
        return rval
    # END wrapper method
    flush_changes.__name__ = non_const_func.__name__
    return flush_changes


class SectionConstraint(object):

    """Constrains a ConfigParser to only option commands which are constrained to
    always use the section we have been initialized with.

    It supports all ConfigParser methods that operate on an option.

    :note:
        If used as a context manager, will release the wrapped ConfigParser."""
    __slots__ = ("_config", "_section_name")
    _valid_attrs_ = ("get_value", "set_value", "get", "set", "getint", "getfloat", "getboolean", "has_option",
                     "remove_section", "remove_option", "options")

    def __init__(self, config, section):
        self._config = config
        self._section_name = section

    def __del__(self):
        # Yes, for some reason, we have to call it explicitly for it to work in PY3 !
        # Apparently __del__ doesn't get call anymore if refcount becomes 0
        # Ridiculous ... .
        self._config.release()

    def __getattr__(self, attr):
        if attr in self._valid_attrs_:
            return lambda *args, **kwargs: self._call_config(attr, *args, **kwargs)
        return super(SectionConstraint, self).__getattribute__(attr)

    def _call_config(self, method, *args, **kwargs):
        """Call the configuration at the given method which must take a section name
        as first argument"""
        return getattr(self._config, method)(self._section_name, *args, **kwargs)

    @property
    def config(self):
        """return: Configparser instance we constrain"""
        return self._config

    def release(self):
        """Equivalent to GitConfigParser.release(), which is called on our underlying parser instance"""
        return self._config.release()

    def __enter__(self):
        self._config.__enter__()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self._config.__exit__(exception_type, exception_value, traceback)


class GitConfigParser(with_metaclass(MetaParserBuilder, cp.RawConfigParser, object)):

    """Implements specifics required to read git style configuration files.

    This variation behaves much like the git.config command such that the configuration
    will be read on demand based on the filepath given during initialization.

    The changes will automatically be written once the instance goes out of scope, but
    can be triggered manually as well.

    The configuration file will be locked if you intend to change values preventing other
    instances to write concurrently.

    :note:
        The config is case-sensitive even when queried, hence section and option names
        must match perfectly.
        If used as a context manager, will release the locked file."""

    #{ Configuration
    # The lock type determines the type of lock to use in new configuration readers.
    # They must be compatible to the LockFile interface.
    # A suitable alternative would be the BlockingLockFile
    t_lock = LockFile
    re_comment = re.compile(r'^\s*[#;]')

    #} END configuration

    optvalueonly_source = r'\s*(?P<option>[^:=\s][^:=]*)'

    OPTVALUEONLY = re.compile(optvalueonly_source)

    OPTCRE = re.compile(optvalueonly_source + r'\s*(?P<vi>[:=])\s*' + r'(?P<value>.*)$')

    del optvalueonly_source

    # list of RawConfigParser methods able to change the instance
    _mutating_methods_ = ("add_section", "remove_section", "remove_option", "set")

    def __init__(self, file_or_files, read_only=True, merge_includes=True):
        """Initialize a configuration reader to read the given file_or_files and to
        possibly allow changes to it by setting read_only False

        :param file_or_files:
            A single file path or file objects or multiple of these

        :param read_only:
            If True, the ConfigParser may only read the data , but not change it.
            If False, only a single file path or file object may be given. We will write back the changes
            when they happen, or when the ConfigParser is released. This will not happen if other
            configuration files have been included
        :param merge_includes: if True, we will read files mentioned in [include] sections and merge their
            contents into ours. This makes it impossible to write back an individual configuration file.
            Thus, if you want to modify a single configuration file, turn this off to leave the original
            dataset unaltered when reading it."""
        cp.RawConfigParser.__init__(self, dict_type=OrderedDict)

        # Used in python 3, needs to stay in sync with sections for underlying implementation to work
        if not hasattr(self, '_proxies'):
            self._proxies = self._dict()

        self._file_or_files = file_or_files
        self._read_only = read_only
        self._dirty = False
        self._is_initialized = False
        self._merge_includes = merge_includes
        self._lock = None
        self._acquire_lock()

    def _acquire_lock(self):
        if not self._read_only:
            if not self._lock:
                if isinstance(self._file_or_files, (tuple, list)):
                    raise ValueError(
                        "Write-ConfigParsers can operate on a single file only, multiple files have been passed")
                # END single file check

                file_or_files = self._file_or_files
                if not isinstance(self._file_or_files, string_types):
                    file_or_files = self._file_or_files.name
                # END get filename from handle/stream
                # initialize lock base - we want to write
                self._lock = self.t_lock(file_or_files)
            # END lock check

            self._lock._obtain_lock()
        # END read-only check

    def __del__(self):
        """Write pending changes if required and release locks"""
        # NOTE: only consistent in PY2
        self.release()

    def __enter__(self):
        self._acquire_lock()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.release()

    def release(self):
        """Flush changes and release the configuration write lock. This instance must not be used anymore afterwards.
        In Python 3, it's required to explicitly release locks and flush changes, as __del__ is not called
        deterministically anymore."""
        # checking for the lock here makes sure we do not raise during write()
        # in case an invalid parser was created who could not get a lock
        if self.read_only or (self._lock and not self._lock._has_lock()):
            return

        try:
            try:
                self.write()
            except IOError:
                log.error("Exception during destruction of GitConfigParser", exc_info=True)
            except ReferenceError:
                # This happens in PY3 ... and usually means that some state cannot be written
                # as the sections dict cannot be iterated
                # Usually when shutting down the interpreter, don'y know how to fix this
                pass
        finally:
            self._lock._release_lock()

    def optionxform(self, optionstr):
        """Do not transform options in any way when writing"""
        return optionstr

    def _read(self, fp, fpname):
        """A direct copy of the py2.4 version of the super class's _read method
        to assure it uses ordered dicts. Had to change one line to make it work.

        Future versions have this fixed, but in fact its quite embarrassing for the
        guys not to have done it right in the first place !

        Removed big comments to make it more compact.

        Made sure it ignores initial whitespace as git uses tabs"""
        cursect = None                            # None, or a dictionary
        optname = None
        lineno = 0
        is_multi_line = False
        e = None                                  # None, or an exception

        def string_decode(v):
            if v[-1] == '\\':
                v = v[:-1]
            # end cut trailing escapes to prevent decode error

            if PY3:
                return v.encode(defenc).decode('unicode_escape')
            else:
                return v.decode('string_escape')
            # end
        # end

        while True:
            # we assume to read binary !
            line = fp.readline().decode(defenc)
            if not line:
                break
            lineno = lineno + 1
            # comment or blank line?
            if line.strip() == '' or self.re_comment.match(line):
                continue
            if line.split(None, 1)[0].lower() == 'rem' and line[0] in "rR":
                # no leading whitespace
                continue

            # is it a section header?
            mo = self.SECTCRE.match(line.strip())
            if not is_multi_line and mo:
                sectname = mo.group('header').strip()
                if sectname in self._sections:
                    cursect = self._sections[sectname]
                elif sectname == cp.DEFAULTSECT:
                    cursect = self._defaults
                else:
                    cursect = self._dict((('__name__', sectname),))
                    self._sections[sectname] = cursect
                    self._proxies[sectname] = None
                # So sections can't start with a continuation line
                optname = None
            # no section header in the file?
            elif cursect is None:
                raise cp.MissingSectionHeaderError(fpname, lineno, line)
            # an option line?
            elif not is_multi_line:
                mo = self.OPTCRE.match(line)
                if mo:
                    # We might just have handled the last line, which could contain a quotation we want to remove
                    optname, vi, optval = mo.group('option', 'vi', 'value')
                    if vi in ('=', ':') and ';' in optval and not optval.strip().startswith('"'):
                        pos = optval.find(';')
                        if pos != -1 and optval[pos - 1].isspace():
                            optval = optval[:pos]
                    optval = optval.strip()
                    if optval == '""':
                        optval = ''
                    # end handle empty string
                    optname = self.optionxform(optname.rstrip())
                    if len(optval) > 1 and optval[0] == '"' and optval[-1] != '"':
                        is_multi_line = True
                        optval = string_decode(optval[1:])
                    # end handle multi-line
                    cursect[optname] = optval
                else:
                    # check if it's an option with no value - it's just ignored by git
                    if not self.OPTVALUEONLY.match(line):
                        if not e:
                            e = cp.ParsingError(fpname)
                        e.append(lineno, repr(line))
                    continue
            else:
                line = line.rstrip()
                if line.endswith('"'):
                    is_multi_line = False
                    line = line[:-1]
                # end handle quotations
                cursect[optname] += string_decode(line)
            # END parse section or option
        # END while reading

        # if any parsing errors occurred, raise an exception
        if e:
            raise e

    def _has_includes(self):
        return self._merge_includes and self.has_section('include')

    def read(self):
        """Reads the data stored in the files we have been initialized with. It will
        ignore files that cannot be read, possibly leaving an empty configuration

        :return: Nothing
        :raise IOError: if a file cannot be handled"""
        if self._is_initialized:
            return
        self._is_initialized = True

        if not isinstance(self._file_or_files, (tuple, list)):
            files_to_read = [self._file_or_files]
        else:
            files_to_read = list(self._file_or_files)
        # end assure we have a copy of the paths to handle

        seen = set(files_to_read)
        num_read_include_files = 0
        while files_to_read:
            file_path = files_to_read.pop(0)
            fp = file_path
            file_ok = False

            if hasattr(fp, "seek"):
                self._read(fp, fp.name)
            else:
                # assume a path if it is not a file-object
                try:
                    with open(file_path, 'rb') as fp:
                        file_ok = True
                        self._read(fp, fp.name)
                except IOError:
                    continue

            # Read includes and append those that we didn't handle yet
            # We expect all paths to be normalized and absolute (and will assure that is the case)
            if self._has_includes():
                for _, include_path in self.items('include'):
                    if include_path.startswith('~'):
                        include_path = osp.expanduser(include_path)
                    if not osp.isabs(include_path):
                        if not file_ok:
                            continue
                        # end ignore relative paths if we don't know the configuration file path
                        assert osp.isabs(file_path), "Need absolute paths to be sure our cycle checks will work"
                        include_path = osp.join(osp.dirname(file_path), include_path)
                    # end make include path absolute
                    include_path = osp.normpath(include_path)
                    if include_path in seen or not os.access(include_path, os.R_OK):
                        continue
                    seen.add(include_path)
                    # insert included file to the top to be considered first
                    files_to_read.insert(0, include_path)
                    num_read_include_files += 1
                # each include path in configuration file
            # end handle includes
        # END for each file object to read

        # If there was no file included, we can safely write back (potentially) the configuration file
        # without altering it's meaning
        if num_read_include_files == 0:
            self._merge_includes = False
        # end

    def _write(self, fp):
        """Write an .ini-format representation of the configuration state in
        git compatible format"""
        def write_section(name, section_dict):
            fp.write(("[%s]\n" % name).encode(defenc))
            for (key, value) in section_dict.items():
                if key != "__name__":
                    fp.write(("\t%s = %s\n" % (key, self._value_to_string(value).replace('\n', '\n\t'))).encode(defenc))
                # END if key is not __name__
        # END section writing

        if self._defaults:
            write_section(cp.DEFAULTSECT, self._defaults)
        for name, value in self._sections.items():
            write_section(name, value)

    def items(self, section_name):
        """:return: list((option, value), ...) pairs of all items in the given section"""
        return [(k, v) for k, v in super(GitConfigParser, self).items(section_name) if k != '__name__']

    @needs_values
    def write(self):
        """Write changes to our file, if there are changes at all

        :raise IOError: if this is a read-only writer instance or if we could not obtain
            a file lock"""
        self._assure_writable("write")
        if not self._dirty:
            return

        if isinstance(self._file_or_files, (list, tuple)):
            raise AssertionError("Cannot write back if there is not exactly a single file to write to, have %i files"
                                 % len(self._file_or_files))
        # end assert multiple files

        if self._has_includes():
            log.debug("Skipping write-back of configuration file as include files were merged in." +
                      "Set merge_includes=False to prevent this.")
            return
        # end

        fp = self._file_or_files

        # we have a physical file on disk, so get a lock
        is_file_lock = isinstance(fp, string_types + (FileType, ))
        if is_file_lock:
            self._lock._obtain_lock()
        if not hasattr(fp, "seek"):
            with open(self._file_or_files, "wb") as fp:
                self._write(fp)
        else:
            fp.seek(0)
            # make sure we do not overwrite into an existing file
            if hasattr(fp, 'truncate'):
                fp.truncate()
            self._write(fp)

    def _assure_writable(self, method_name):
        if self.read_only:
            raise IOError("Cannot execute non-constant method %s.%s" % (self, method_name))

    def add_section(self, section):
        """Assures added options will stay in order"""
        return super(GitConfigParser, self).add_section(section)

    @property
    def read_only(self):
        """:return: True if this instance may change the configuration file"""
        return self._read_only

    def get_value(self, section, option, default=None):
        """
        :param default:
            If not None, the given default value will be returned in case
            the option did not exist
        :return: a properly typed value, either int, float or string

        :raise TypeError: in case the value could not be understood
            Otherwise the exceptions known to the ConfigParser will be raised."""
        try:
            valuestr = self.get(section, option)
        except Exception:
            if default is not None:
                return default
            raise

        types = (int, float)
        for numtype in types:
            try:
                val = numtype(valuestr)

                # truncated value ?
                if val != float(valuestr):
                    continue

                return val
            except (ValueError, TypeError):
                continue
        # END for each numeric type

        # try boolean values as git uses them
        vl = valuestr.lower()
        if vl == 'false':
            return False
        if vl == 'true':
            return True

        if not isinstance(valuestr, string_types):
            raise TypeError("Invalid value type: only int, long, float and str are allowed", valuestr)

        return valuestr

    def _value_to_string(self, value):
        if isinstance(value, (int, float, bool)):
            return str(value)
        return force_text(value)

    @needs_values
    @set_dirty_and_flush_changes
    def set_value(self, section, option, value):
        """Sets the given option in section to the given value.
        It will create the section if required, and will not throw as opposed to the default
        ConfigParser 'set' method.

        :param section: Name of the section in which the option resides or should reside
        :param option: Name of the options whose value to set

        :param value: Value to set the option to. It must be a string or convertible
            to a string
        :return: this instance"""
        if not self.has_section(section):
            self.add_section(section)
        self.set(section, option, self._value_to_string(value))
        return self

    def rename_section(self, section, new_name):
        """rename the given section to new_name
        :raise ValueError: if section doesn't exit
        :raise ValueError: if a section with new_name does already exist
        :return: this instance
        """
        if not self.has_section(section):
            raise ValueError("Source section '%s' doesn't exist" % section)
        if self.has_section(new_name):
            raise ValueError("Destination section '%s' already exists" % new_name)

        super(GitConfigParser, self).add_section(new_name)
        for k, v in self.items(section):
            self.set(new_name, k, self._value_to_string(v))
        # end for each value to copy

        # This call writes back the changes, which is why we don't have the respective decorator
        self.remove_section(section)
        return self
