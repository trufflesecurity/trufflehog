# -*- coding: utf-8 -*-
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os
import sys
try:
    from unittest import skipIf
except ImportError:
    from unittest2 import skipIf

import git
from git.cmd import Git
from git.compat import string_types, is_win
from git.exc import (
    InvalidGitRepositoryError,
    RepositoryDirtyError
)
from git.objects.submodule.base import Submodule
from git.objects.submodule.root import RootModule, RootUpdateProgress
from git.repo.fun import (
    find_submodule_git_dir,
    touch
)
from git.test.lib import (
    TestBase,
    with_rw_repo
)
from git.test.lib import with_rw_directory
from git.util import HIDE_WINDOWS_KNOWN_ERRORS
from git.util import to_native_path_linux, join_path_native
import os.path as osp


class TestRootProgress(RootUpdateProgress):
    """Just prints messages, for now without checking the correctness of the states"""

    def update(self, op, cur_count, max_count, message=''):
        print(op, cur_count, max_count, message)


prog = TestRootProgress()


class TestSubmodule(TestBase):

    def tearDown(self):
        import gc
        gc.collect()

    k_subm_current = "c15a6e1923a14bc760851913858a3942a4193cdb"
    k_subm_changed = "394ed7006ee5dc8bddfd132b64001d5dfc0ffdd3"
    k_no_subm_tag = "0.1.6"

    def _do_base_tests(self, rwrepo):
        """Perform all tests in the given repository, it may be bare or nonbare"""
        # manual instantiation
        smm = Submodule(rwrepo, "\0" * 20)
        # name needs to be set in advance
        self.failUnlessRaises(AttributeError, getattr, smm, 'name')

        # iterate - 1 submodule
        sms = Submodule.list_items(rwrepo, self.k_subm_current)
        assert len(sms) == 1
        sm = sms[0]

        # at a different time, there is None
        assert len(Submodule.list_items(rwrepo, self.k_no_subm_tag)) == 0

        assert sm.path == 'git/ext/gitdb'
        assert sm.path != sm.name                   # in our case, we have ids there, which don't equal the path
        assert sm.url.endswith('github.com/gitpython-developers/gitdb.git')
        assert sm.branch_path == 'refs/heads/master'            # the default ...
        assert sm.branch_name == 'master'
        assert sm.parent_commit == rwrepo.head.commit
        # size is always 0
        assert sm.size == 0
        # the module is not checked-out yet
        self.failUnlessRaises(InvalidGitRepositoryError, sm.module)

        # which is why we can't get the branch either - it points into the module() repository
        self.failUnlessRaises(InvalidGitRepositoryError, getattr, sm, 'branch')

        # branch_path works, as its just a string
        assert isinstance(sm.branch_path, string_types)

        # some commits earlier we still have a submodule, but its at a different commit
        smold = next(Submodule.iter_items(rwrepo, self.k_subm_changed))
        assert smold.binsha != sm.binsha
        assert smold != sm                  # the name changed

        # force it to reread its information
        del(smold._url)
        smold.url == sm.url  # @NoEffect

        # test config_reader/writer methods
        sm.config_reader()
        new_smclone_path = None             # keep custom paths for later
        new_csmclone_path = None                #
        if rwrepo.bare:
            with self.assertRaises(InvalidGitRepositoryError):
                with sm.config_writer() as cw:
                    pass
        else:
            with sm.config_writer() as writer:
                # for faster checkout, set the url to the local path
                new_smclone_path = Git.polish_url(osp.join(self.rorepo.working_tree_dir, sm.path))
                writer.set_value('url', new_smclone_path)
                writer.release()
                assert sm.config_reader().get_value('url') == new_smclone_path
                assert sm.url == new_smclone_path
        # END handle bare repo
        smold.config_reader()

        # cannot get a writer on historical submodules
        if not rwrepo.bare:
            with self.assertRaises(ValueError):
                with smold.config_writer():
                    pass
        # END handle bare repo

        # make the old into a new - this doesn't work as the name changed
        self.failUnlessRaises(ValueError, smold.set_parent_commit, self.k_subm_current)
        # the sha is properly updated
        smold.set_parent_commit(self.k_subm_changed + "~1")
        assert smold.binsha != sm.binsha

        # raises if the sm didn't exist in new parent - it keeps its
        # parent_commit unchanged
        self.failUnlessRaises(ValueError, smold.set_parent_commit, self.k_no_subm_tag)

        # TEST TODO: if a path in the gitmodules file, but not in the index, it raises

        # TEST UPDATE
        ##############
        # module retrieval is not always possible
        if rwrepo.bare:
            self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
            self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
            self.failUnlessRaises(InvalidGitRepositoryError, sm.add, rwrepo, 'here', 'there')
        else:
            # its not checked out in our case
            self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
            assert not sm.module_exists()

            # currently there is only one submodule
            assert len(list(rwrepo.iter_submodules())) == 1
            assert sm.binsha != "\0" * 20

            # TEST ADD
            ###########
            # preliminary tests
            # adding existing returns exactly the existing
            sma = Submodule.add(rwrepo, sm.name, sm.path)
            assert sma.path == sm.path

            # no url and no module at path fails
            self.failUnlessRaises(ValueError, Submodule.add, rwrepo, "newsubm", "pathtorepo", url=None)

            # CONTINUE UPDATE
            #################

            # lets update it - its a recursive one too
            newdir = osp.join(sm.abspath, 'dir')
            os.makedirs(newdir)

            # update fails if the path already exists non-empty
            self.failUnlessRaises(OSError, sm.update)
            os.rmdir(newdir)

            # dry-run does nothing
            sm.update(dry_run=True, progress=prog)
            assert not sm.module_exists()

            assert sm.update() is sm
            sm_repopath = sm.path               # cache for later
            assert sm.module_exists()
            assert isinstance(sm.module(), git.Repo)
            assert sm.module().working_tree_dir == sm.abspath

            # INTERLEAVE ADD TEST
            #####################
            # url must match the one in the existing repository ( if submodule name suggests a new one )
            # or we raise
            self.failUnlessRaises(ValueError, Submodule.add, rwrepo, "newsubm", sm.path, "git://someurl/repo.git")

            # CONTINUE UPDATE
            #################
            # we should have setup a tracking branch, which is also active
            assert sm.module().head.ref.tracking_branch() is not None

            # delete the whole directory and re-initialize
            assert len(sm.children()) != 0
            # shutil.rmtree(sm.abspath)
            sm.remove(force=True, configuration=False)
            assert len(sm.children()) == 0
            # dry-run does nothing
            sm.update(dry_run=True, recursive=False, progress=prog)
            assert len(sm.children()) == 0

            sm.update(recursive=False)
            assert len(list(rwrepo.iter_submodules())) == 2
            assert len(sm.children()) == 1          # its not checked out yet
            csm = sm.children()[0]
            assert not csm.module_exists()
            csm_repopath = csm.path

            # adjust the path of the submodules module to point to the local destination
            new_csmclone_path = Git.polish_url(osp.join(self.rorepo.working_tree_dir, sm.path, csm.path))
            with csm.config_writer() as writer:
                writer.set_value('url', new_csmclone_path)
            assert csm.url == new_csmclone_path

            # dry-run does nothing
            assert not csm.module_exists()
            sm.update(recursive=True, dry_run=True, progress=prog)
            assert not csm.module_exists()

            # update recursively again
            sm.update(recursive=True)
            assert csm.module_exists()

            # tracking branch once again
            csm.module().head.ref.tracking_branch() is not None  # @NoEffect

            # this flushed in a sub-submodule
            assert len(list(rwrepo.iter_submodules())) == 2

            # reset both heads to the previous version, verify that to_latest_revision works
            smods = (sm.module(), csm.module())
            for repo in smods:
                repo.head.reset('HEAD~2', working_tree=1)
            # END for each repo to reset

            # dry run does nothing
            self.failUnlessRaises(RepositoryDirtyError, sm.update, recursive=True, dry_run=True, progress=prog)
            sm.update(recursive=True, dry_run=True, progress=prog, force=True)
            for repo in smods:
                assert repo.head.commit != repo.head.ref.tracking_branch().commit
            # END for each repo to check

            self.failUnlessRaises(RepositoryDirtyError, sm.update, recursive=True, to_latest_revision=True)
            sm.update(recursive=True, to_latest_revision=True, force=True)
            for repo in smods:
                assert repo.head.commit == repo.head.ref.tracking_branch().commit
            # END for each repo to check
            del(smods)

            # if the head is detached, it still works ( but warns )
            smref = sm.module().head.ref
            sm.module().head.ref = 'HEAD~1'
            # if there is no tracking branch, we get a warning as well
            csm_tracking_branch = csm.module().head.ref.tracking_branch()
            csm.module().head.ref.set_tracking_branch(None)
            sm.update(recursive=True, to_latest_revision=True)

            # to_latest_revision changes the child submodule's commit, it needs an
            # update now
            csm.set_parent_commit(csm.repo.head.commit)

            # undo the changes
            sm.module().head.ref = smref
            csm.module().head.ref.set_tracking_branch(csm_tracking_branch)

            # REMOVAL OF REPOSITOTRY
            ########################
            # must delete something
            self.failUnlessRaises(ValueError, csm.remove, module=False, configuration=False)

            # module() is supposed to point to gitdb, which has a child-submodule whose URL is still pointing
            # to github. To save time, we will change it to
            csm.set_parent_commit(csm.repo.head.commit)
            with csm.config_writer() as cw:
                cw.set_value('url', self._small_repo_url())
            csm.repo.index.commit("adjusted URL to point to local source, instead of the internet")

            # We have modified the configuration, hence the index is dirty, and the
            # deletion will fail
            # NOTE: As we did  a few updates in the meanwhile, the indices were reset
            # Hence we create some changes
            csm.set_parent_commit(csm.repo.head.commit)
            with sm.config_writer() as writer:
                writer.set_value("somekey", "somevalue")
            with csm.config_writer() as writer:
                writer.set_value("okey", "ovalue")
            self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
            # if we remove the dirty index, it would work
            sm.module().index.reset()
            # still, we have the file modified
            self.failUnlessRaises(InvalidGitRepositoryError, sm.remove, dry_run=True)
            sm.module().index.reset(working_tree=True)

            # enforce the submodule to be checked out at the right spot as well.
            csm.update()
            assert csm.module_exists()
            assert csm.exists()
            assert osp.isdir(csm.module().working_tree_dir)

            # this would work
            assert sm.remove(force=True, dry_run=True) is sm
            assert sm.module_exists()
            sm.remove(force=True, dry_run=True)
            assert sm.module_exists()

            # but ... we have untracked files in the child submodule
            fn = join_path_native(csm.module().working_tree_dir, "newfile")
            with open(fn, 'w') as fd:
                fd.write("hi")
            self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)

            # forcibly delete the child repository
            prev_count = len(sm.children())
            self.failUnlessRaises(ValueError, csm.remove, force=True)
            # We removed sm, which removed all submodules. However, the instance we
            # have still points to the commit prior to that, where it still existed
            csm.set_parent_commit(csm.repo.commit(), check=False)
            assert not csm.exists()
            assert not csm.module_exists()
            assert len(sm.children()) == prev_count
            # now we have a changed index, as configuration was altered.
            # fix this
            sm.module().index.reset(working_tree=True)

            # now delete only the module of the main submodule
            assert sm.module_exists()
            sm.remove(configuration=False, force=True)
            assert sm.exists()
            assert not sm.module_exists()
            assert sm.config_reader().get_value('url')

            # delete the rest
            sm_path = sm.path
            sm.remove()
            assert not sm.exists()
            assert not sm.module_exists()
            self.failUnlessRaises(ValueError, getattr, sm, 'path')

            assert len(rwrepo.submodules) == 0

            # ADD NEW SUBMODULE
            ###################
            # add a simple remote repo - trailing slashes are no problem
            smid = "newsub"
            osmid = "othersub"
            nsm = Submodule.add(rwrepo, smid, sm_repopath, new_smclone_path + "/", None, no_checkout=True)
            assert nsm.name == smid
            assert nsm.module_exists()
            assert nsm.exists()
            # its not checked out
            assert not osp.isfile(join_path_native(nsm.module().working_tree_dir, Submodule.k_modules_file))
            assert len(rwrepo.submodules) == 1

            # add another submodule, but into the root, not as submodule
            osm = Submodule.add(rwrepo, osmid, csm_repopath, new_csmclone_path, Submodule.k_head_default)
            assert osm != nsm
            assert osm.module_exists()
            assert osm.exists()
            assert osp.isfile(join_path_native(osm.module().working_tree_dir, 'setup.py'))

            assert len(rwrepo.submodules) == 2

            # commit the changes, just to finalize the operation
            rwrepo.index.commit("my submod commit")
            assert len(rwrepo.submodules) == 2

            # needs update as the head changed, it thinks its in the history
            # of the repo otherwise
            nsm.set_parent_commit(rwrepo.head.commit)
            osm.set_parent_commit(rwrepo.head.commit)

            # MOVE MODULE
            #############
            # invalid input
            self.failUnlessRaises(ValueError, nsm.move, 'doesntmatter', module=False, configuration=False)

            # renaming to the same path does nothing
            assert nsm.move(sm_path) is nsm

            # rename a module
            nmp = join_path_native("new", "module", "dir") + "/"  # new module path
            pmp = nsm.path
            assert nsm.move(nmp) is nsm
            nmp = nmp[:-1]          # cut last /
            nmpl = to_native_path_linux(nmp)
            assert nsm.path == nmpl
            assert rwrepo.submodules[0].path == nmpl

            mpath = 'newsubmodule'
            absmpath = join_path_native(rwrepo.working_tree_dir, mpath)
            open(absmpath, 'w').write('')
            self.failUnlessRaises(ValueError, nsm.move, mpath)
            os.remove(absmpath)

            # now it works, as we just move it back
            nsm.move(pmp)
            assert nsm.path == pmp
            assert rwrepo.submodules[0].path == pmp

            # REMOVE 'EM ALL
            ################
            # if a submodule's repo has no remotes, it can't be added without an explicit url
            osmod = osm.module()

            osm.remove(module=False)
            for remote in osmod.remotes:
                remote.remove(osmod, remote.name)
            assert not osm.exists()
            self.failUnlessRaises(ValueError, Submodule.add, rwrepo, osmid, csm_repopath, url=None)
        # END handle bare mode

        # Error if there is no submodule file here
        self.failUnlessRaises(IOError, Submodule._config_parser, rwrepo, rwrepo.commit(self.k_no_subm_tag), True)

    # @skipIf(HIDE_WINDOWS_KNOWN_ERRORS,  ## ACTUALLY skipped by `git.submodule.base#L869`.
    #         "FIXME: fails with: PermissionError: [WinError 32] The process cannot access the file because"
    #         "it is being used by another process: "
    #         "'C:\\Users\\ankostis\\AppData\\Local\\Temp\\tmp95c3z83bnon_bare_test_base_rw\\git\\ext\\gitdb\\gitdb\\ext\\smmap'")  # noqa E501
    @with_rw_repo(k_subm_current)
    def test_base_rw(self, rwrepo):
        self._do_base_tests(rwrepo)

    @with_rw_repo(k_subm_current, bare=True)
    def test_base_bare(self, rwrepo):
        self._do_base_tests(rwrepo)

    @skipIf(HIDE_WINDOWS_KNOWN_ERRORS and sys.version_info[:2] == (3, 5), """
        File "C:\\projects\\gitpython\\git\\cmd.py", line 559, in execute
        raise GitCommandNotFound(command, err)
        git.exc.GitCommandNotFound: Cmd('git') not found due to: OSError('[WinError 6] The handle is invalid')
        cmdline: git clone -n --shared -v C:\\projects\\gitpython\\.git Users\\appveyor\\AppData\\Local\\Temp\\1\\tmplyp6kr_rnon_bare_test_root_module""")  # noqa E501
    @with_rw_repo(k_subm_current, bare=False)
    def test_root_module(self, rwrepo):
        # Can query everything without problems
        rm = RootModule(self.rorepo)
        assert rm.module() is self.rorepo

        # try attributes
        rm.binsha
        rm.mode
        rm.path
        assert rm.name == rm.k_root_name
        assert rm.parent_commit == self.rorepo.head.commit
        rm.url
        rm.branch

        assert len(rm.list_items(rm.module())) == 1
        rm.config_reader()
        with rm.config_writer():
            pass

        # deep traversal gitdb / async
        rsmsp = [sm.path for sm in rm.traverse()]
        assert len(rsmsp) >= 2          # gitdb and async [and smmap], async being a child of gitdb

        # cannot set the parent commit as root module's path didn't exist
        self.failUnlessRaises(ValueError, rm.set_parent_commit, 'HEAD')

        # TEST UPDATE
        #############
        # setup commit which remove existing, add new and modify existing submodules
        rm = RootModule(rwrepo)
        assert len(rm.children()) == 1

        # modify path without modifying the index entry
        # ( which is what the move method would do properly )
        #==================================================
        sm = rm.children()[0]
        pp = "path/prefix"
        fp = join_path_native(pp, sm.path)
        prep = sm.path
        assert not sm.module_exists()               # was never updated after rwrepo's clone

        # assure we clone from a local source
        with sm.config_writer() as writer:
            writer.set_value('url', Git.polish_url(osp.join(self.rorepo.working_tree_dir, sm.path)))

        # dry-run does nothing
        sm.update(recursive=False, dry_run=True, progress=prog)
        assert not sm.module_exists()

        sm.update(recursive=False)
        assert sm.module_exists()
        with sm.config_writer() as writer:
            writer.set_value('path', fp)    # change path to something with prefix AFTER url change

        # update fails as list_items in such a situations cannot work, as it cannot
        # find the entry at the changed path
        self.failUnlessRaises(InvalidGitRepositoryError, rm.update, recursive=False)

        # move it properly - doesn't work as it its path currently points to an indexentry
        # which doesn't exist ( move it to some path, it doesn't matter here )
        self.failUnlessRaises(InvalidGitRepositoryError, sm.move, pp)
        # reset the path(cache) to where it was, now it works
        sm.path = prep
        sm.move(fp, module=False)       # leave it at the old location

        assert not sm.module_exists()
        cpathchange = rwrepo.index.commit("changed sm path")  # finally we can commit

        # update puts the module into place
        rm.update(recursive=False, progress=prog)
        sm.set_parent_commit(cpathchange)
        assert sm.module_exists()

        # add submodule
        #================
        nsmn = "newsubmodule"
        nsmp = "submrepo"
        subrepo_url = Git.polish_url(osp.join(self.rorepo.working_tree_dir, rsmsp[0], rsmsp[1]))
        nsm = Submodule.add(rwrepo, nsmn, nsmp, url=subrepo_url)
        csmadded = rwrepo.index.commit("Added submodule").hexsha    # make sure we don't keep the repo reference
        nsm.set_parent_commit(csmadded)
        assert nsm.module_exists()
        # in our case, the module should not exist, which happens if we update a parent
        # repo and a new submodule comes into life
        nsm.remove(configuration=False, module=True)
        assert not nsm.module_exists() and nsm.exists()

        # dry-run does nothing
        rm.update(recursive=False, dry_run=True, progress=prog)

        # otherwise it will work
        rm.update(recursive=False, progress=prog)
        assert nsm.module_exists()

        # remove submodule - the previous one
        #====================================
        sm.set_parent_commit(csmadded)
        smp = sm.abspath
        assert not sm.remove(module=False).exists()
        assert osp.isdir(smp)           # module still exists
        csmremoved = rwrepo.index.commit("Removed submodule")

        # an update will remove the module
        # not in dry_run
        rm.update(recursive=False, dry_run=True, force_remove=True)
        assert osp.isdir(smp)

        # when removing submodules, we may get new commits as nested submodules are auto-committing changes
        # to allow deletions without force, as the index would be dirty otherwise.
        # QUESTION: Why does this seem to work in test_git_submodule_compatibility() ?
        self.failUnlessRaises(InvalidGitRepositoryError, rm.update, recursive=False, force_remove=False)
        rm.update(recursive=False, force_remove=True)
        assert not osp.isdir(smp)

        # 'apply work' to the nested submodule and assure this is not removed/altered during updates
        # Need to commit first, otherwise submodule.update wouldn't have a reason to change the head
        touch(osp.join(nsm.module().working_tree_dir, 'new-file'))
        # We cannot expect is_dirty to even run as we wouldn't reset a head to the same location
        assert nsm.module().head.commit.hexsha == nsm.hexsha
        nsm.module().index.add([nsm])
        nsm.module().index.commit("added new file")
        rm.update(recursive=False, dry_run=True, progress=prog)  # would not change head, and thus doens't fail
        # Everything we can do from now on will trigger the 'future' check, so no is_dirty() check will even run
        # This would only run if our local branch is in the past and we have uncommitted changes

        prev_commit = nsm.module().head.commit
        rm.update(recursive=False, dry_run=False, progress=prog)
        assert prev_commit == nsm.module().head.commit, "head shouldn't change, as it is in future of remote branch"

        # this kills the new file
        rm.update(recursive=True, progress=prog, force_reset=True)
        assert prev_commit != nsm.module().head.commit, "head changed, as the remote url and its commit changed"

        # change url ...
        #===============
        # ... to the first repository, this way we have a fast checkout, and a completely different
        # repository at the different url
        nsm.set_parent_commit(csmremoved)
        nsmurl = Git.polish_url(osp.join(self.rorepo.working_tree_dir, rsmsp[0]))
        with nsm.config_writer() as writer:
            writer.set_value('url', nsmurl)
        csmpathchange = rwrepo.index.commit("changed url")
        nsm.set_parent_commit(csmpathchange)

        # Now nsm head is in the future of the tracked remote branch
        prev_commit = nsm.module().head.commit
        # dry-run does nothing
        rm.update(recursive=False, dry_run=True, progress=prog)
        assert nsm.module().remotes.origin.url != nsmurl

        rm.update(recursive=False, progress=prog, force_reset=True)
        assert nsm.module().remotes.origin.url == nsmurl
        assert prev_commit != nsm.module().head.commit, "Should now point to gitdb"
        assert len(rwrepo.submodules) == 1
        assert not rwrepo.submodules[0].children()[0].module_exists(), "nested submodule should not be checked out"

        # add the submodule's changed commit to the index, which is what the
        # user would do
        # beforehand, update our instance's binsha with the new one
        nsm.binsha = nsm.module().head.commit.binsha
        rwrepo.index.add([nsm])

        # change branch
        #=================
        # we only have one branch, so we switch to a virtual one, and back
        # to the current one to trigger the difference
        cur_branch = nsm.branch
        nsmm = nsm.module()
        prev_commit = nsmm.head.commit
        for branch in ("some_virtual_branch", cur_branch.name):
            with nsm.config_writer() as writer:
                writer.set_value(Submodule.k_head_option, git.Head.to_full_path(branch))
            csmbranchchange = rwrepo.index.commit("changed branch to %s" % branch)
            nsm.set_parent_commit(csmbranchchange)
        # END for each branch to change

        # Lets remove our tracking branch to simulate some changes
        nsmmh = nsmm.head
        assert nsmmh.ref.tracking_branch() is None                  # never set it up until now
        assert not nsmmh.is_detached

        # dry run does nothing
        rm.update(recursive=False, dry_run=True, progress=prog)
        assert nsmmh.ref.tracking_branch() is None

        # the real thing does
        rm.update(recursive=False, progress=prog)

        assert nsmmh.ref.tracking_branch() is not None
        assert not nsmmh.is_detached

        # recursive update
        # =================
        # finally we recursively update a module, just to run the code at least once
        # remove the module so that it has more work
        assert len(nsm.children()) >= 1  # could include smmap
        assert nsm.exists() and nsm.module_exists() and len(nsm.children()) >= 1
        # assure we pull locally only
        nsmc = nsm.children()[0]
        with nsmc.config_writer() as writer:
            writer.set_value('url', subrepo_url)
        rm.update(recursive=True, progress=prog, dry_run=True)      # just to run the code
        rm.update(recursive=True, progress=prog)

        # gitdb: has either 1 or 2 submodules depending on the version
        assert len(nsm.children()) >= 1 and nsmc.module_exists()

    @with_rw_repo(k_no_subm_tag, bare=False)
    def test_first_submodule(self, rwrepo):
        assert len(list(rwrepo.iter_submodules())) == 0

        for sm_name, sm_path in (('first', 'submodules/first'),
                                 ('second', osp.join(rwrepo.working_tree_dir, 'submodules/second'))):
            sm = rwrepo.create_submodule(sm_name, sm_path, rwrepo.git_dir, no_checkout=True)
            assert sm.exists() and sm.module_exists()
            rwrepo.index.commit("Added submodule " + sm_name)
        # end for each submodule path to add

        self.failUnlessRaises(ValueError, rwrepo.create_submodule, 'fail', osp.expanduser('~'))
        self.failUnlessRaises(ValueError, rwrepo.create_submodule, 'fail-too',
                              rwrepo.working_tree_dir + osp.sep)

    @with_rw_directory
    def test_add_empty_repo(self, rwdir):
        empty_repo_dir = osp.join(rwdir, 'empty-repo')

        parent = git.Repo.init(osp.join(rwdir, 'parent'))
        git.Repo.init(empty_repo_dir)

        for checkout_mode in range(2):
            name = 'empty' + str(checkout_mode)
            self.failUnlessRaises(ValueError, parent.create_submodule, name, name,
                                  url=empty_repo_dir, no_checkout=checkout_mode and True or False)
        # end for each checkout mode

    @skipIf(HIDE_WINDOWS_KNOWN_ERRORS,
            """FIXME on cygwin: File "C:\\projects\\gitpython\\git\\cmd.py", line 671, in execute
                raise GitCommandError(command, status, stderr_value, stdout_value)
            GitCommandError: Cmd('git') failed due to: exit code(128)
              cmdline: git add 1__Xava verbXXten 1_test _myfile 1_test_other_file 1_XXava-----verbXXten
              stderr: 'fatal: pathspec '"1__çava verböten"' did not match any files'
             FIXME on appveyor: see https://ci.appveyor.com/project/Byron/gitpython/build/1.0.185
                """)
    @with_rw_directory
    def test_git_submodules_and_add_sm_with_new_commit(self, rwdir):
        parent = git.Repo.init(osp.join(rwdir, 'parent'))
        parent.git.submodule('add', self._small_repo_url(), 'module')
        parent.index.commit("added submodule")

        assert len(parent.submodules) == 1
        sm = parent.submodules[0]

        assert sm.exists() and sm.module_exists()

        clone = git.Repo.clone_from(self._small_repo_url(),
                                    osp.join(parent.working_tree_dir, 'existing-subrepository'))
        sm2 = parent.create_submodule('nongit-file-submodule', clone.working_tree_dir)
        assert len(parent.submodules) == 2

        for _ in range(2):
            for init in (False, True):
                sm.update(init=init)
                sm2.update(init=init)
            # end for each init state
        # end for each iteration

        sm.move(sm.path + '_moved')
        sm2.move(sm2.path + '_moved')

        parent.index.commit("moved submodules")

        with sm.config_writer() as writer:
            writer.set_value('user.email', 'example@example.com')
            writer.set_value('user.name', 'me')
        smm = sm.module()
        fp = osp.join(smm.working_tree_dir, 'empty-file')
        with open(fp, 'w'):
            pass
        smm.git.add(Git.polish_url(fp))
        smm.git.commit(m="new file added")

        # submodules are retrieved from the current commit's tree, therefore we can't really get a new submodule
        # object pointing to the new submodule commit
        sm_too = parent.submodules['module_moved']
        assert parent.head.commit.tree[sm.path].binsha == sm.binsha
        assert sm_too.binsha == sm.binsha, "cached submodule should point to the same commit as updated one"

        added_bies = parent.index.add([sm])  # addded base-index-entries
        assert len(added_bies) == 1
        parent.index.commit("add same submodule entry")
        commit_sm = parent.head.commit.tree[sm.path]
        assert commit_sm.binsha == added_bies[0].binsha
        assert commit_sm.binsha == sm.binsha

        sm_too.binsha = sm_too.module().head.commit.binsha
        added_bies = parent.index.add([sm_too])
        assert len(added_bies) == 1
        parent.index.commit("add new submodule entry")
        commit_sm = parent.head.commit.tree[sm.path]
        assert commit_sm.binsha == added_bies[0].binsha
        assert commit_sm.binsha == sm_too.binsha
        assert sm_too.binsha != sm.binsha

    # @skipIf(HIDE_WINDOWS_KNOWN_ERRORS,  ## ACTUALLY skipped by `git.submodule.base#L869`.
    #         "FIXME: helper.wrapper fails with: PermissionError: [WinError 5] Access is denied: "
    #         "'C:\\Users\\appveyor\\AppData\\Local\\Temp\\1\\test_work_tree_unsupportedryfa60di\\master_repo\\.git\\objects\\pack\\pack-bc9e0787aef9f69e1591ef38ea0a6f566ec66fe3.idx")  # noqa E501
    @with_rw_directory
    def test_git_submodule_compatibility(self, rwdir):
        parent = git.Repo.init(osp.join(rwdir, 'parent'))
        sm_path = join_path_native('submodules', 'intermediate', 'one')
        sm = parent.create_submodule('mymodules/myname', sm_path, url=self._small_repo_url())
        parent.index.commit("added submodule")

        def assert_exists(sm, value=True):
            assert sm.exists() == value
            assert sm.module_exists() == value
        # end

        # As git is backwards compatible itself, it would still recognize what we do here ... unless we really
        # muss it up. That's the only reason why the test is still here ... .
        assert len(parent.git.submodule().splitlines()) == 1

        module_repo_path = osp.join(sm.module().working_tree_dir, '.git')
        assert module_repo_path.startswith(osp.join(parent.working_tree_dir, sm_path))
        if not sm._need_gitfile_submodules(parent.git):
            assert osp.isdir(module_repo_path)
            assert not sm.module().has_separate_working_tree()
        else:
            assert osp.isfile(module_repo_path)
            assert sm.module().has_separate_working_tree()
            assert find_submodule_git_dir(module_repo_path) is not None, "module pointed to by .git file must be valid"
        # end verify submodule 'style'

        # test move
        new_sm_path = join_path_native('submodules', 'one')
        sm.move(new_sm_path)
        assert_exists(sm)

        # Add additional submodule level
        csm = sm.module().create_submodule('nested-submodule', join_path_native('nested-submodule', 'working-tree'),
                                           url=self._small_repo_url())
        sm.module().index.commit("added nested submodule")
        sm_head_commit = sm.module().commit()
        assert_exists(csm)

        # Fails because there are new commits, compared to the remote we cloned from
        self.failUnlessRaises(InvalidGitRepositoryError, sm.remove, dry_run=True)
        assert_exists(sm)
        assert sm.module().commit() == sm_head_commit
        assert_exists(csm)

        # rename nested submodule
        # This name would move itself one level deeper - needs special handling internally
        new_name = csm.name + '/mine'
        assert csm.rename(new_name).name == new_name
        assert_exists(csm)
        assert csm.repo.is_dirty(index=True, working_tree=False), "index must contain changed .gitmodules file"
        csm.repo.index.commit("renamed module")

        # keep_going evaluation
        rsm = parent.submodule_update()
        assert_exists(sm)
        assert_exists(csm)
        with csm.config_writer().set_value('url', 'bar'):
            pass
        csm.repo.index.commit("Have to commit submodule change for algorithm to pick it up")
        assert csm.url == 'bar'

        self.failUnlessRaises(Exception, rsm.update, recursive=True, to_latest_revision=True, progress=prog)
        assert_exists(csm)
        rsm.update(recursive=True, to_latest_revision=True, progress=prog, keep_going=True)

        # remove
        sm_module_path = sm.module().git_dir

        for dry_run in (True, False):
            sm.remove(dry_run=dry_run, force=True)
            assert_exists(sm, value=dry_run)
            assert osp.isdir(sm_module_path) == dry_run
        # end for each dry-run mode

    @with_rw_directory
    def test_remove_norefs(self, rwdir):
        parent = git.Repo.init(osp.join(rwdir, 'parent'))
        sm_name = 'mymodules/myname'
        sm = parent.create_submodule(sm_name, sm_name, url=self._small_repo_url())
        assert sm.exists()

        parent.index.commit("Added submodule")

        assert sm.repo is parent  # yoh was surprised since expected sm repo!!
        # so created a new instance for submodule
        smrepo = git.Repo(osp.join(rwdir, 'parent', sm.path))
        # Adding a remote without fetching so would have no references
        smrepo.create_remote('special', 'git@server-shouldnotmatter:repo.git')
        # And we should be able to remove it just fine
        sm.remove()
        assert not sm.exists()

    @with_rw_directory
    def test_rename(self, rwdir):
        parent = git.Repo.init(osp.join(rwdir, 'parent'))
        sm_name = 'mymodules/myname'
        sm = parent.create_submodule(sm_name, sm_name, url=self._small_repo_url())
        parent.index.commit("Added submodule")

        assert sm.rename(sm_name) is sm and sm.name == sm_name
        assert not sm.repo.is_dirty(index=True, working_tree=False, untracked_files=False)

        new_path = 'renamed/myname'
        assert sm.move(new_path).name == new_path

        new_sm_name = "shortname"
        assert sm.rename(new_sm_name) is sm
        assert sm.repo.is_dirty(index=True, working_tree=False, untracked_files=False)
        assert sm.exists()

        sm_mod = sm.module()
        if osp.isfile(osp.join(sm_mod.working_tree_dir, '.git')) == sm._need_gitfile_submodules(parent.git):
            assert sm_mod.git_dir.endswith(join_path_native('.git', 'modules', new_sm_name))
        # end

    @with_rw_directory
    def test_branch_renames(self, rw_dir):
        # Setup initial sandbox:
        # parent repo has one submodule, which has all the latest changes
        source_url = self._small_repo_url()
        sm_source_repo = git.Repo.clone_from(source_url, osp.join(rw_dir, 'sm-source'), b='master')
        parent_repo = git.Repo.init(osp.join(rw_dir, 'parent'))
        sm = parent_repo.create_submodule('mysubmodule', 'subdir/submodule',
                                          sm_source_repo.working_tree_dir, branch='master')
        parent_repo.index.commit('added submodule')
        assert sm.exists()

        # Create feature branch with one new commit in submodule source
        sm_fb = sm_source_repo.create_head('feature')
        sm_fb.checkout()
        new_file = touch(osp.join(sm_source_repo.working_tree_dir, 'new-file'))
        sm_source_repo.index.add([new_file])
        sm.repo.index.commit("added new file")

        # change designated submodule checkout branch to the new upstream feature branch
        with sm.config_writer() as smcw:
            smcw.set_value('branch', sm_fb.name)
        assert sm.repo.is_dirty(index=True, working_tree=False)
        sm.repo.index.commit("changed submodule branch to '%s'" % sm_fb)

        # verify submodule update with feature branch that leaves currently checked out branch in it's past
        sm_mod = sm.module()
        prev_commit = sm_mod.commit()
        assert sm_mod.head.ref.name == 'master'
        assert parent_repo.submodule_update()
        assert sm_mod.head.ref.name == sm_fb.name
        assert sm_mod.commit() == prev_commit, "Without to_latest_revision, we don't change the commit"

        assert parent_repo.submodule_update(to_latest_revision=True)
        assert sm_mod.head.ref.name == sm_fb.name
        assert sm_mod.commit() == sm_fb.commit

        # Create new branch which is in our past, and thus seemingly unrelated to the currently checked out one
        # To make it even 'harder', we shall fork and create a new commit
        sm_pfb = sm_source_repo.create_head('past-feature', commit='HEAD~20')
        sm_pfb.checkout()
        sm_source_repo.index.add([touch(osp.join(sm_source_repo.working_tree_dir, 'new-file'))])
        sm_source_repo.index.commit("new file added, to past of '%r'" % sm_fb)

        # Change designated submodule checkout branch to a new commit in its own past
        with sm.config_writer() as smcw:
            smcw.set_value('branch', sm_pfb.path)
        sm.repo.index.commit("changed submodule branch to '%s'" % sm_pfb)

        # Test submodule updates - must fail if submodule is dirty
        touch(osp.join(sm_mod.working_tree_dir, 'unstaged file'))
        # This doesn't fail as our own submodule binsha didn't change, and the reset is only triggered if
        # to latest revision is True.
        parent_repo.submodule_update(to_latest_revision=False)
        sm_mod.head.ref.name == sm_pfb.name, "should have been switched to past head"
        sm_mod.commit() == sm_fb.commit, "Head wasn't reset"

        self.failUnlessRaises(RepositoryDirtyError, parent_repo.submodule_update, to_latest_revision=True)
        parent_repo.submodule_update(to_latest_revision=True, force_reset=True)
        assert sm_mod.commit() == sm_pfb.commit, "Now head should have been reset"
        assert sm_mod.head.ref.name == sm_pfb.name

    @skipIf(not is_win, "Specifically for Windows.")
    def test_to_relative_path_with_super_at_root_drive(self):
        class Repo(object):
            working_tree_dir = 'D:\\'
        super_repo = Repo()
        submodule_path = 'D:\\submodule_path'
        relative_path = Submodule._to_relative_path(super_repo, submodule_path)
        msg = '_to_relative_path should be "submodule_path" but was "%s"' % relative_path
        assert relative_path == 'submodule_path', msg
