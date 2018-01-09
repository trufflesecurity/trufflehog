# -*- coding: utf-8 -*-
# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
import os

from git.test.lib import TestBase
from git.test.lib.helper import with_rw_directory

import os.path as osp


class Tutorials(TestBase):

    def tearDown(self):
        import gc
        gc.collect()

    # @skipIf(HIDE_WINDOWS_KNOWN_ERRORS,  ## ACTUALLY skipped by `git.submodule.base#L869`.
    #         "FIXME: helper.wrapper fails with: PermissionError: [WinError 5] Access is denied: "
    #         "'C:\\Users\\appveyor\\AppData\\Local\\Temp\\1\\test_work_tree_unsupportedryfa60di\\master_repo\\.git\\objects\\pack\\pack-bc9e0787aef9f69e1591ef38ea0a6f566ec66fe3.idx")  # noqa E501
    @with_rw_directory
    def test_init_repo_object(self, rw_dir):
        # [1-test_init_repo_object]
        from git import Repo
        join = osp.join

        # rorepo is a Repo instance pointing to the git-python repository.
        # For all you know, the first argument to Repo is a path to the repository
        # you want to work with
        repo = Repo(self.rorepo.working_tree_dir)
        assert not repo.bare
        # ![1-test_init_repo_object]

        # [2-test_init_repo_object]
        bare_repo = Repo.init(join(rw_dir, 'bare-repo'), bare=True)
        assert bare_repo.bare
        # ![2-test_init_repo_object]

        # [3-test_init_repo_object]
        repo.config_reader()             # get a config reader for read-only access
        with repo.config_writer():       # get a config writer to change configuration
            pass                         # call release() to be sure changes are written and locks are released
        # ![3-test_init_repo_object]

        # [4-test_init_repo_object]
        assert not bare_repo.is_dirty()  # check the dirty state
        repo.untracked_files             # retrieve a list of untracked files
        # ['my_untracked_file']
        # ![4-test_init_repo_object]

        # [5-test_init_repo_object]
        cloned_repo = repo.clone(join(rw_dir, 'to/this/path'))
        assert cloned_repo.__class__ is Repo     # clone an existing repository
        assert Repo.init(join(rw_dir, 'path/for/new/repo')).__class__ is Repo
        # ![5-test_init_repo_object]

        # [6-test_init_repo_object]
        with open(join(rw_dir, 'repo.tar'), 'wb') as fp:
            repo.archive(fp)
        # ![6-test_init_repo_object]

        # repository paths
        # [7-test_init_repo_object]
        assert osp.isdir(cloned_repo.working_tree_dir)                   # directory with your work files
        assert cloned_repo.git_dir.startswith(cloned_repo.working_tree_dir)  # directory containing the git repository
        assert bare_repo.working_tree_dir is None                            # bare repositories have no working tree
        # ![7-test_init_repo_object]

        # heads, tags and references
        # heads are branches in git-speak
        # [8-test_init_repo_object]
        self.assertEqual(repo.head.ref, repo.heads.master,  # head is a sym-ref pointing to master
                         "It's ok if TC not running from `master`.")
        self.assertEqual(repo.tags['0.3.5'], repo.tag('refs/tags/0.3.5'))   # you can access tags in various ways too
        self.assertEqual(repo.refs.master, repo.heads['master'])            # .refs provides all refs, ie heads ...

        if 'TRAVIS' not in os.environ:
            self.assertEqual(repo.refs['origin/master'], repo.remotes.origin.refs.master)  # ... remotes ...
        self.assertEqual(repo.refs['0.3.5'], repo.tags['0.3.5'])             # ... and tags
        # ![8-test_init_repo_object]

        # create a new head/branch
        # [9-test_init_repo_object]
        new_branch = cloned_repo.create_head('feature')               # create a new branch ...
        assert cloned_repo.active_branch != new_branch                # which wasn't checked out yet ...
        self.assertEqual(new_branch.commit, cloned_repo.active_branch.commit)  # pointing to the checked-out commit
        # It's easy to let a branch point to the previous commit, without affecting anything else
        # Each reference provides access to the git object it points to, usually commits
        assert new_branch.set_commit('HEAD~1').commit == cloned_repo.active_branch.commit.parents[0]
        # ![9-test_init_repo_object]

        # create a new tag reference
        # [10-test_init_repo_object]
        past = cloned_repo.create_tag('past', ref=new_branch,
                                      message="This is a tag-object pointing to %s" % new_branch.name)
        self.assertEqual(past.commit, new_branch.commit)        # the tag points to the specified commit
        assert past.tag.message.startswith("This is")  # and its object carries the message provided

        now = cloned_repo.create_tag('now')            # This is a tag-reference. It may not carry meta-data
        assert now.tag is None
        # ![10-test_init_repo_object]

        # Object handling
        # [11-test_init_repo_object]
        assert now.commit.message != past.commit.message
        # You can read objects directly through binary streams, no working tree required
        assert (now.commit.tree / 'VERSION').data_stream.read().decode('ascii').startswith('2')

        # You can traverse trees as well to handle all contained files of a particular commit
        file_count = 0
        tree_count = 0
        tree = past.commit.tree
        for item in tree.traverse():
            file_count += item.type == 'blob'
            tree_count += item.type == 'tree'
        assert file_count and tree_count                        # we have accumulated all directories and files
        self.assertEqual(len(tree.blobs) + len(tree.trees), len(tree))   # a tree is iterable on its children
        # ![11-test_init_repo_object]

        # remotes allow handling push, pull and fetch operations
        # [12-test_init_repo_object]
        from git import RemoteProgress

        class MyProgressPrinter(RemoteProgress):
            def update(self, op_code, cur_count, max_count=None, message=''):
                print(op_code, cur_count, max_count, cur_count / (max_count or 100.0), message or "NO MESSAGE")
        # end

        self.assertEqual(len(cloned_repo.remotes), 1)                    # we have been cloned, so should be one remote
        self.assertEqual(len(bare_repo.remotes), 0)                      # this one was just initialized
        origin = bare_repo.create_remote('origin', url=cloned_repo.working_tree_dir)
        assert origin.exists()
        for fetch_info in origin.fetch(progress=MyProgressPrinter()):
            print("Updated %s to %s" % (fetch_info.ref, fetch_info.commit))
        # create a local branch at the latest fetched master. We specify the name statically, but you have all
        # information to do it programatically as well.
        bare_master = bare_repo.create_head('master', origin.refs.master)
        bare_repo.head.set_reference(bare_master)
        assert not bare_repo.delete_remote(origin).exists()
        # push and pull behave very similarly
        # ![12-test_init_repo_object]

        # index
        # [13-test_init_repo_object]
        self.assertEqual(new_branch.checkout(), cloned_repo.active_branch)     # checking out branch adjusts the wtree
        self.assertEqual(new_branch.commit, past.commit)                       # Now the past is checked out

        new_file_path = osp.join(cloned_repo.working_tree_dir, 'my-new-file')
        open(new_file_path, 'wb').close()                             # create new file in working tree
        cloned_repo.index.add([new_file_path])                        # add it to the index
        # Commit the changes to deviate masters history
        cloned_repo.index.commit("Added a new file in the past - for later merege")

        # prepare a merge
        master = cloned_repo.heads.master                         # right-hand side is ahead of us, in the future
        merge_base = cloned_repo.merge_base(new_branch, master)   # allwos for a three-way merge
        cloned_repo.index.merge_tree(master, base=merge_base)     # write the merge result into index
        cloned_repo.index.commit("Merged past and now into future ;)",
                                 parent_commits=(new_branch.commit, master.commit))

        # now new_branch is ahead of master, which probably should be checked out and reset softly.
        # note that all these operations didn't touch the working tree, as we managed it ourselves.
        # This definitely requires you to know what you are doing :) !
        assert osp.basename(new_file_path) in new_branch.commit.tree  # new file is now in tree
        master.commit = new_branch.commit            # let master point to most recent commit
        cloned_repo.head.reference = master          # we adjusted just the reference, not the working tree or index
        # ![13-test_init_repo_object]

        # submodules

        # [14-test_init_repo_object]
        # create a new submodule and check it out on the spot, setup to track master branch of `bare_repo`
        # As our GitPython repository has submodules already that point to github, make sure we don't
        # interact with them
        for sm in cloned_repo.submodules:
            assert not sm.remove().exists()                   # after removal, the sm doesn't exist anymore
        sm = cloned_repo.create_submodule('mysubrepo', 'path/to/subrepo', url=bare_repo.git_dir, branch='master')

        # .gitmodules was written and added to the index, which is now being committed
        cloned_repo.index.commit("Added submodule")
        assert sm.exists() and sm.module_exists()             # this submodule is defintely available
        sm.remove(module=True, configuration=False)           # remove the working tree
        assert sm.exists() and not sm.module_exists()         # the submodule itself is still available

        # update all submodules, non-recursively to save time, this method is very powerful, go have a look
        cloned_repo.submodule_update(recursive=False)
        assert sm.module_exists()                             # The submodules working tree was checked out by update
        # ![14-test_init_repo_object]

    @with_rw_directory
    def test_references_and_objects(self, rw_dir):
        # [1-test_references_and_objects]
        import git
        repo = git.Repo.clone_from(self._small_repo_url(), osp.join(rw_dir, 'repo'), branch='master')

        heads = repo.heads
        master = heads.master       # lists can be accessed by name for convenience
        master.commit               # the commit pointed to by head called master
        master.rename('new_name')   # rename heads
        master.rename('master')
        # ![1-test_references_and_objects]

        # [2-test_references_and_objects]
        tags = repo.tags
        tagref = tags[0]
        tagref.tag                  # tags may have tag objects carrying additional information
        tagref.commit               # but they always point to commits
        repo.delete_tag(tagref)     # delete or
        repo.create_tag("my_tag")   # create tags using the repo for convenience
        # ![2-test_references_and_objects]

        # [3-test_references_and_objects]
        head = repo.head            # the head points to the active branch/ref
        master = head.reference     # retrieve the reference the head points to
        master.commit               # from here you use it as any other reference
        # ![3-test_references_and_objects]
#
        # [4-test_references_and_objects]
        log = master.log()
        log[0]                      # first (i.e. oldest) reflog entry
        log[-1]                     # last (i.e. most recent) reflog entry
        # ![4-test_references_and_objects]

        # [5-test_references_and_objects]
        new_branch = repo.create_head('new')     # create a new one
        new_branch.commit = 'HEAD~10'            # set branch to another commit without changing index or working trees
        repo.delete_head(new_branch)             # delete an existing head - only works if it is not checked out
        # ![5-test_references_and_objects]

        # [6-test_references_and_objects]
        new_tag = repo.create_tag('my_new_tag', message='my message')
        # You cannot change the commit a tag points to. Tags need to be re-created
        self.failUnlessRaises(AttributeError, setattr, new_tag, 'commit', repo.commit('HEAD~1'))
        repo.delete_tag(new_tag)
        # ![6-test_references_and_objects]

        # [7-test_references_and_objects]
        new_branch = repo.create_head('another-branch')
        repo.head.reference = new_branch
        # ![7-test_references_and_objects]

        # [8-test_references_and_objects]
        hc = repo.head.commit
        hct = hc.tree
        hc != hct                           # @NoEffect
        hc != repo.tags[0]                  # @NoEffect
        hc == repo.head.reference.commit    # @NoEffect
        # ![8-test_references_and_objects]

        # [9-test_references_and_objects]
        self.assertEqual(hct.type, 'tree')           # preset string type, being a class attribute
        assert hct.size > 0                 # size in bytes
        assert len(hct.hexsha) == 40
        assert len(hct.binsha) == 20
        # ![9-test_references_and_objects]

        # [10-test_references_and_objects]
        self.assertEqual(hct.path, '')                  # root tree has no path
        assert hct.trees[0].path != ''         # the first contained item has one though
        self.assertEqual(hct.mode, 0o40000)              # trees have the mode of a linux directory
        self.assertEqual(hct.blobs[0].mode, 0o100644)   # blobs have specific mode, comparable to a standard linux fs
        # ![10-test_references_and_objects]

        # [11-test_references_and_objects]
        hct.blobs[0].data_stream.read()        # stream object to read data from
        hct.blobs[0].stream_data(open(osp.join(rw_dir, 'blob_data'), 'wb'))  # write data to given stream
        # ![11-test_references_and_objects]

        # [12-test_references_and_objects]
        repo.commit('master')
        repo.commit('v0.8.1')
        repo.commit('HEAD~10')
        # ![12-test_references_and_objects]

        # [13-test_references_and_objects]
        fifty_first_commits = list(repo.iter_commits('master', max_count=50))
        assert len(fifty_first_commits) == 50
        # this will return commits 21-30 from the commit list as traversed backwards master
        ten_commits_past_twenty = list(repo.iter_commits('master', max_count=10, skip=20))
        assert len(ten_commits_past_twenty) == 10
        assert fifty_first_commits[20:30] == ten_commits_past_twenty
        # ![13-test_references_and_objects]

        # [14-test_references_and_objects]
        headcommit = repo.head.commit
        assert len(headcommit.hexsha) == 40
        assert len(headcommit.parents) > 0
        assert headcommit.tree.type == 'tree'
        assert len(headcommit.author.name) != 0
        assert isinstance(headcommit.authored_date, int)
        assert len(headcommit.committer.name) != 0
        assert isinstance(headcommit.committed_date, int)
        assert headcommit.message != ''
        # ![14-test_references_and_objects]

        # [15-test_references_and_objects]
        import time
        time.asctime(time.gmtime(headcommit.committed_date))
        time.strftime("%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date))
        # ![15-test_references_and_objects]

        # [16-test_references_and_objects]
        assert headcommit.parents[0].parents[0].parents[0] == repo.commit('master^^^')
        # ![16-test_references_and_objects]

        # [17-test_references_and_objects]
        tree = repo.heads.master.commit.tree
        assert len(tree.hexsha) == 40
        # ![17-test_references_and_objects]

        # [18-test_references_and_objects]
        assert len(tree.trees) > 0          # trees are subdirectories
        assert len(tree.blobs) > 0          # blobs are files
        assert len(tree.blobs) + len(tree.trees) == len(tree)
        # ![18-test_references_and_objects]

        # [19-test_references_and_objects]
        self.assertEqual(tree['smmap'], tree / 'smmap')          # access by index and by sub-path
        for entry in tree:                                         # intuitive iteration of tree members
            print(entry)
        blob = tree.trees[0].blobs[0]                              # let's get a blob in a sub-tree
        assert blob.name
        assert len(blob.path) < len(blob.abspath)
        self.assertEqual(tree.trees[0].name + '/' + blob.name, blob.path)   # this is how relative blob path generated
        self.assertEqual(tree[blob.path], blob)                             # you can use paths like 'dir/file' in tree
        # ![19-test_references_and_objects]

        # [20-test_references_and_objects]
        assert tree / 'smmap' == tree['smmap']
        assert tree / blob.path == tree[blob.path]
        # ![20-test_references_and_objects]

        # [21-test_references_and_objects]
        # This example shows the various types of allowed ref-specs
        assert repo.tree() == repo.head.commit.tree
        past = repo.commit('HEAD~5')
        assert repo.tree(past) == repo.tree(past.hexsha)
        self.assertEqual(repo.tree('v0.8.1').type, 'tree')        # yes, you can provide any refspec - works everywhere
        # ![21-test_references_and_objects]

        # [22-test_references_and_objects]
        assert len(tree) < len(list(tree.traverse()))
        # ![22-test_references_and_objects]

        # [23-test_references_and_objects]
        index = repo.index
        # The index contains all blobs in a flat list
        assert len(list(index.iter_blobs())) == len([o for o in repo.head.commit.tree.traverse() if o.type == 'blob'])
        # Access blob objects
        for (path, stage), entry in index.entries.items():  # @UnusedVariable
            pass
        new_file_path = osp.join(repo.working_tree_dir, 'new-file-name')
        open(new_file_path, 'w').close()
        index.add([new_file_path])                                             # add a new file to the index
        index.remove(['LICENSE'])                                              # remove an existing one
        assert osp.isfile(osp.join(repo.working_tree_dir, 'LICENSE'))  # working tree is untouched

        self.assertEqual(index.commit("my commit message").type, 'commit')              # commit changed index
        repo.active_branch.commit = repo.commit('HEAD~1')                      # forget last commit

        from git import Actor
        author = Actor("An author", "author@example.com")
        committer = Actor("A committer", "committer@example.com")
        # commit by commit message and author and committer
        index.commit("my commit message", author=author, committer=committer)
        # ![23-test_references_and_objects]

        # [24-test_references_and_objects]
        from git import IndexFile
        # loads a tree into a temporary index, which exists just in memory
        IndexFile.from_tree(repo, 'HEAD~1')
        # merge two trees three-way into memory
        merge_index = IndexFile.from_tree(repo, 'HEAD~10', 'HEAD', repo.merge_base('HEAD~10', 'HEAD'))
        # and persist it
        merge_index.write(osp.join(rw_dir, 'merged_index'))
        # ![24-test_references_and_objects]

        # [25-test_references_and_objects]
        empty_repo = git.Repo.init(osp.join(rw_dir, 'empty'))
        origin = empty_repo.create_remote('origin', repo.remotes.origin.url)
        assert origin.exists()
        assert origin == empty_repo.remotes.origin == empty_repo.remotes['origin']
        origin.fetch()                  # assure we actually have data. fetch() returns useful information
        # Setup a local tracking branch of a remote branch
        empty_repo.create_head('master', origin.refs.master)  # create local branch "master" from remote "master"
        empty_repo.heads.master.set_tracking_branch(origin.refs.master)  # set local "master" to track remote "master
        empty_repo.heads.master.checkout()  # checkout local "master" to working tree
        # Three above commands in one:
        empty_repo.create_head('master', origin.refs.master).set_tracking_branch(origin.refs.master).checkout()
        # rename remotes
        origin.rename('new_origin')
        # push and pull behaves similarly to `git push|pull`
        origin.pull()
        origin.push()
        # assert not empty_repo.delete_remote(origin).exists()     # create and delete remotes
        # ![25-test_references_and_objects]

        # [26-test_references_and_objects]
        assert origin.url == repo.remotes.origin.url
        with origin.config_writer as cw:
            cw.set("pushurl", "other_url")

        # Please note that in python 2, writing origin.config_writer.set(...) is totally safe.
        # In py3 __del__ calls can be delayed, thus not writing changes in time.
        # ![26-test_references_and_objects]

        # [27-test_references_and_objects]
        hcommit = repo.head.commit
        hcommit.diff()                  # diff tree against index
        hcommit.diff('HEAD~1')          # diff tree against previous tree
        hcommit.diff(None)              # diff tree against working tree

        index = repo.index
        index.diff()                    # diff index against itself yielding empty diff
        index.diff(None)                # diff index against working copy
        index.diff('HEAD')              # diff index against current HEAD tree
        # ![27-test_references_and_objects]

        # [28-test_references_and_objects]
        # Traverse added Diff objects only
        for diff_added in hcommit.diff('HEAD~1').iter_change_type('A'):
            print(diff_added)
        # ![28-test_references_and_objects]

        # [29-test_references_and_objects]
        # Reset our working tree 10 commits into the past
        past_branch = repo.create_head('past_branch', 'HEAD~10')
        repo.head.reference = past_branch
        assert not repo.head.is_detached
        # reset the index and working tree to match the pointed-to commit
        repo.head.reset(index=True, working_tree=True)

        # To detach your head, you have to point to a commit directly
        repo.head.reference = repo.commit('HEAD~5')
        assert repo.head.is_detached
        # now our head points 15 commits into the past, whereas the working tree
        # and index are 10 commits in the past
        # ![29-test_references_and_objects]

        # [30-test_references_and_objects]
        # checkout the branch using git-checkout. It will fail as the working tree appears dirty
        self.failUnlessRaises(git.GitCommandError, repo.heads.master.checkout)
        repo.heads.past_branch.checkout()
        # ![30-test_references_and_objects]

        # [31-test_references_and_objects]
        git = repo.git
        git.checkout('HEAD', b="my_new_branch")         # create a new branch
        git.branch('another-new-one')
        git.branch('-D', 'another-new-one')             # pass strings for full control over argument order
        git.for_each_ref()                              # '-' becomes '_' when calling it
        # ![31-test_references_and_objects]

        repo.git.clear_cache()

    def test_submodules(self):
        # [1-test_submodules]
        repo = self.rorepo
        sms = repo.submodules

        assert len(sms) == 1
        sm = sms[0]
        self.assertEqual(sm.name, 'gitdb')                         # git-python has gitdb as single submodule ...
        self.assertEqual(sm.children()[0].name, 'smmap')           # ... which has smmap as single submodule

        # The module is the repository referenced by the submodule
        assert sm.module_exists()                         # the module is available, which doesn't have to be the case.
        assert sm.module().working_tree_dir.endswith('gitdb')
        # the submodule's absolute path is the module's path
        assert sm.abspath == sm.module().working_tree_dir
        self.assertEqual(len(sm.hexsha), 40)                       # Its sha defines the commit to checkout
        assert sm.exists()                                # yes, this submodule is valid and exists
        # read its configuration conveniently
        assert sm.config_reader().get_value('path') == sm.path
        self.assertEqual(len(sm.children()), 1)                    # query the submodule hierarchy
        # ![1-test_submodules]

    @with_rw_directory
    def test_add_file_and_commit(self, rw_dir):
        import git

        repo_dir = osp.join(rw_dir, 'my-new-repo')
        file_name = osp.join(repo_dir, 'new-file')

        r = git.Repo.init(repo_dir)
        # This function just creates an empty file ...
        open(file_name, 'wb').close()
        r.index.add([file_name])
        r.index.commit("initial commit")

        # ![test_add_file_and_commit]
