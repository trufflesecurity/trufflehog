import git
from git.exc import InvalidGitRepositoryError
from git.config import GitConfigParser
from io import BytesIO
import weakref

__all__ = ('sm_section', 'sm_name', 'mkhead', 'find_first_remote_branch',
           'SubmoduleConfigParser')

#{ Utilities


def sm_section(name):
    """:return: section title used in .gitmodules configuration file"""
    return 'submodule "%s"' % name


def sm_name(section):
    """:return: name of the submodule as parsed from the section name"""
    section = section.strip()
    return section[11:-1]


def mkhead(repo, path):
    """:return: New branch/head instance"""
    return git.Head(repo, git.Head.to_full_path(path))


def find_first_remote_branch(remotes, branch_name):
    """Find the remote branch matching the name of the given branch or raise InvalidGitRepositoryError"""
    for remote in remotes:
        try:
            return remote.refs[branch_name]
        except IndexError:
            continue
        # END exception handling
    # END for remote
    raise InvalidGitRepositoryError("Didn't find remote branch '%r' in any of the given remotes" % branch_name)

#} END utilities


#{ Classes

class SubmoduleConfigParser(GitConfigParser):

    """
    Catches calls to _write, and updates the .gitmodules blob in the index
    with the new data, if we have written into a stream. Otherwise it will
    add the local file to the index to make it correspond with the working tree.
    Additionally, the cache must be cleared

    Please note that no mutating method will work in bare mode
    """

    def __init__(self, *args, **kwargs):
        self._smref = None
        self._index = None
        self._auto_write = True
        super(SubmoduleConfigParser, self).__init__(*args, **kwargs)

    #{ Interface
    def set_submodule(self, submodule):
        """Set this instance's submodule. It must be called before
        the first write operation begins"""
        self._smref = weakref.ref(submodule)

    def flush_to_index(self):
        """Flush changes in our configuration file to the index"""
        assert self._smref is not None
        # should always have a file here
        assert not isinstance(self._file_or_files, BytesIO)

        sm = self._smref()
        if sm is not None:
            index = self._index
            if index is None:
                index = sm.repo.index
            # END handle index
            index.add([sm.k_modules_file], write=self._auto_write)
            sm._clear_cache()
        # END handle weakref

    #} END interface

    #{ Overridden Methods
    def write(self):
        rval = super(SubmoduleConfigParser, self).write()
        self.flush_to_index()
        return rval
    # END overridden methods


#} END classes
