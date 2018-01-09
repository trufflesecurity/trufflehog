import os

from git.util import join_path

import os.path as osp

from .head import Head


__all__ = ["RemoteReference"]


class RemoteReference(Head):

    """Represents a reference pointing to a remote head."""
    _common_path_default = Head._remote_common_path_default

    @classmethod
    def iter_items(cls, repo, common_path=None, remote=None):
        """Iterate remote references, and if given, constrain them to the given remote"""
        common_path = common_path or cls._common_path_default
        if remote is not None:
            common_path = join_path(common_path, str(remote))
        # END handle remote constraint
        return super(RemoteReference, cls).iter_items(repo, common_path)

    @classmethod
    def delete(cls, repo, *refs, **kwargs):
        """Delete the given remote references

        :note:
            kwargs are given for comparability with the base class method as we
            should not narrow the signature."""
        repo.git.branch("-d", "-r", *refs)
        # the official deletion method will ignore remote symbolic refs - these
        # are generally ignored in the refs/ folder. We don't though
        # and delete remainders manually
        for ref in refs:
            try:
                os.remove(osp.join(repo.common_dir, ref.path))
            except OSError:
                pass
            try:
                os.remove(osp.join(repo.git_dir, ref.path))
            except OSError:
                pass
        # END for each ref

    @classmethod
    def create(cls, *args, **kwargs):
        """Used to disable this method"""
        raise TypeError("Cannot explicitly create remote references")
