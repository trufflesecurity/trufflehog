# ########################## Copyrights and license ############################
#                                                                              #
# Copyright 2012 Vincent Jacques <vincent@vincent-jacques.net>                 #
# Copyright 2012 Zearin <zearin@gonk.net>                                      #
# Copyright 2013 Vincent Jacques <vincent@vincent-jacques.net>                 #
#                                                                              #
# This file is part of PyGithub.                                               #
# http://pygithub.github.io/PyGithub/v1/index.html                             #
#                                                                              #
# PyGithub is free software: you can redistribute it and/or modify it under    #
# the terms of the GNU Lesser General Public License as published by the Free  #
# Software Foundation, either version 3 of the License, or (at your option)    #
# any later version.                                                           #
#                                                                              #
# PyGithub is distributed in the hope that it will be useful, but WITHOUT ANY  #
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS    #
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more #
# details.                                                                     #
#                                                                              #
# You should have received a copy of the GNU Lesser General Public License     #
# along with PyGithub. If not, see <http://www.gnu.org/licenses/>.             #
#                                                                              #
# ##############################################################################

from . import Framework

import github
import datetime


class Repository(Framework.TestCase):
    def setUp(self):
        Framework.TestCase.setUp(self)
        self.user = self.g.get_user()
        self.repo = self.user.get_repo("PyGithub")

    def testAttributes(self):
        self.assertEqual(self.repo.clone_url, "https://github.com/jacquev6/PyGithub.git")
        self.assertEqual(self.repo.created_at, datetime.datetime(2012, 2, 25, 12, 53, 47))
        self.assertEqual(self.repo.description, "Python library implementing the full Github API v3")
        self.assertFalse(self.repo.fork)
        self.assertEqual(self.repo.forks, 3)
        self.assertEqual(self.repo.full_name, "jacquev6/PyGithub")
        self.assertEqual(self.repo.git_url, "git://github.com/jacquev6/PyGithub.git")
        self.assertTrue(self.repo.has_downloads)
        self.assertTrue(self.repo.has_issues)
        self.assertFalse(self.repo.has_wiki)
        self.assertEqual(self.repo.homepage, "http://vincent-jacques.net/PyGithub")
        self.assertEqual(self.repo.html_url, "https://github.com/jacquev6/PyGithub")
        self.assertEqual(self.repo.id, 3544490)
        self.assertEqual(self.repo.language, "Python")
        self.assertEqual(self.repo.master_branch, None)
        self.assertEqual(self.repo.name, "PyGithub")
        self.assertEqual(self.repo.open_issues, 16)
        self.assertEqual(self.repo.organization, None)
        self.assertEqual(self.repo.owner.login, "jacquev6")
        self.assertEqual(self.repo.parent, None)
        self.assertTrue(self.repo.permissions.admin)
        self.assertTrue(self.repo.permissions.pull)
        self.assertTrue(self.repo.permissions.push)
        self.assertFalse(self.repo.private)
        self.assertEqual(self.repo.pushed_at, datetime.datetime(2012, 5, 27, 6, 0, 28))
        self.assertEqual(self.repo.size, 308)
        self.assertEqual(self.repo.source, None)
        self.assertEqual(self.repo.ssh_url, "git@github.com:jacquev6/PyGithub.git")
        self.assertEqual(self.repo.svn_url, "https://github.com/jacquev6/PyGithub")
        self.assertEqual(self.repo.updated_at, datetime.datetime(2012, 5, 27, 6, 55, 28))
        self.assertEqual(self.repo.url, "https://api.github.com/repos/jacquev6/PyGithub")
        self.assertEqual(self.repo.watchers, 15)

        # test __repr__() based on this attributes
        self.assertEqual(self.repo.__repr__(), 'Repository(full_name="jacquev6/PyGithub")')

    def testProtectBranch(self):
        self.repo.protect_branch("master", True, "everyone", ["test"])
        branch = self.repo.get_protected_branch("master")
        self.assertTrue(branch.protected)
        self.assertEqual(branch.enforcement_level, "everyone")
        self.assertEqual(branch.contexts, ["test"])

    def testRemoveBranchProtection(self):
        self.repo.protect_branch("master", False)
        branch = self.repo.get_protected_branch("master")
        self.assertFalse(branch.protected)
        self.assertEqual(branch.enforcement_level, "off")
        self.assertEqual(branch.contexts, [])

    def testChangeBranchProtectionContexts(self):
        self.repo.protect_branch("master", True, "everyone", ["test"])
        branch = self.repo.get_protected_branch("master")
        self.assertTrue(branch.protected)
        self.assertEqual(branch.enforcement_level, "everyone")
        self.assertEqual(branch.contexts, ["test"])
        self.repo.protect_branch("master", True, "everyone", ["test", "default"])
        branch = self.repo.get_protected_branch("master")
        self.assertEqual(branch.contexts, ["default", "test"])
        self.repo.protect_branch("master", True, "everyone", ["default"])
        branch = self.repo.get_protected_branch("master")
        self.assertEqual(branch.contexts, ["default"])

    def testRaiseErrorWithOutBranch(self):
        raised = False
        try:
            self.repo.protect_branch("", True, "everyone", ["test"])
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 404)
            self.assertEqual(
                exception.data, {
                    'documentation_url': 'https://developer.github.com/v3/repos/#get-branch',
                    'message': 'Branch not found'
                }
            )
            self.assertTrue(raised)

    def testRaiseErrorWithBranchProtectionWithOutContext(self):
        raised = False
        try:
            self.repo.protect_branch("master", True, "everyone")
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 422)
            self.assertEqual(
                exception.data, {
                    'documentation_url': 'https://developer.github.com/v3',
                    'message': 'Invalid request.\n\n"contexts" wasn\'t supplied.'
                }
            )
            self.assertTrue(raised)

    def testRaiseErrorWithBranchProtectionWithInvalidEnforcementLevel(self):
        raised = False
        try:
            self.repo.protect_branch("master", True, "", ["test"])
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 422)
            self.assertEqual(
                exception.data, {
                    'documentation_url':
                    'https://developer.github.com/v3/repos/#enabling-and-disabling-branch-protection',
                    'message': 'Validation Failed',
                    'errors': [
                        {
                            'field': 'required_status_checks_enforcement_level',
                            'message': "required_status_checks_enforcement_level enforcement level '%s' is not valid",
                            'code': 'custom',
                            'resource': 'ProtectedBranch'
                        }
                    ]
                }
            )
            self.assertTrue(raised)

    def testChangeBranchProtectionEnforcementLevel(self):
        self.repo.protect_branch("master", True, "everyone", ["test"])
        branch = self.repo.get_protected_branch("master")
        self.assertTrue(branch.protected)
        self.assertEqual(branch.enforcement_level, "everyone")
        self.repo.protect_branch("master", True, "non_admins", ["test"])
        branch = self.repo.get_protected_branch("master")
        self.assertEqual(branch.enforcement_level, "non_admins")

    def testEditWithoutArguments(self):
        self.repo.edit("PyGithub")

    def testEditWithAllArguments(self):
        self.repo.edit("PyGithub", "Description edited by PyGithub", "http://vincent-jacques.net/PyGithub", private=True, has_issues=True, has_wiki=False, has_downloads=True)
        self.assertEqual(self.repo.description, "Description edited by PyGithub")
        self.repo.edit("PyGithub", "Python library implementing the full Github API v3")
        self.assertEqual(self.repo.description, "Python library implementing the full Github API v3")

    def testEditWithDefaultBranch(self):
        self.assertEqual(self.repo.master_branch, None)
        self.repo.edit("PyGithub", default_branch="master")
        self.assertEqual(self.repo.master_branch, "master")

    def testDelete(self):
        repo = self.g.get_user().get_repo("TestPyGithub")
        repo.delete()

    def testGetContributors(self):
        self.assertListKeyEqual(self.repo.get_contributors(), lambda c: (c.login, c.contributions), [("jacquev6", 355)])

    def testCreateMilestone(self):
        milestone = self.repo.create_milestone("Milestone created by PyGithub", state="open", description="Description created by PyGithub", due_on=datetime.date(2012, 6, 15))
        self.assertEqual(milestone.number, 5)

    def testCreateMilestoneWithMinimalArguments(self):
        milestone = self.repo.create_milestone("Milestone also created by PyGithub")
        self.assertEqual(milestone.number, 6)

    def testCreateIssue(self):
        issue = self.repo.create_issue("Issue created by PyGithub")
        self.assertEqual(issue.number, 28)

    def testCreateIssueWithAllArguments(self):
        user = self.g.get_user("jacquev6")
        milestone = self.repo.get_milestone(2)
        question = self.repo.get_label("Question")
        issue = self.repo.create_issue("Issue also created by PyGithub", "Body created by PyGithub", user, milestone, [question], ["jacquev6", "stuglaser"])
        self.assertEqual(issue.number, 30)

    def testCreateIssueWithAllArgumentsStringLabel(self):
        user = self.g.get_user("jacquev6")
        milestone = self.repo.get_milestone(2)
        issue = self.repo.create_issue("Issue also created by PyGithub", "Body created by PyGithub", user, milestone, ["Question"], ["jacquev6", "stuglaser"])
        self.assertEqual(issue.number, 30)

    def testCreateLabel(self):
        label = self.repo.create_label("Label with silly name % * + created by PyGithub", "00ff00")
        self.assertEqual(label.color, "00ff00")
        self.assertEqual(label.name, "Label with silly name % * + created by PyGithub")
        self.assertEqual(label.url, "https://api.github.com/repos/jacquev6/PyGithub/labels/Label+with+silly+name+%25+%2A+%2B+created+by+PyGithub")

    def testGetLabel(self):
        label = self.repo.get_label("Label with silly name % * + created by PyGithub")
        self.assertEqual(label.color, "00ff00")
        self.assertEqual(label.name, "Label with silly name % * + created by PyGithub")
        self.assertEqual(label.url, "https://api.github.com/repos/jacquev6/PyGithub/labels/Label+with+silly+name+%25+%2A+%2B+created+by+PyGithub")

    def testCreateHookWithMinimalParameters(self):
        hook = self.repo.create_hook("web", {"url": "http://foobar.com"})
        self.assertEqual(hook.id, 257967)

    def testCreateHookWithAllParameters(self):
        hook = self.repo.create_hook("web", {"url": "http://foobar.com"}, ["fork"], False)
        self.assertTrue(hook.active)  # WTF
        self.assertEqual(hook.id, 257993)

    def testCreateGitRef(self):
        ref = self.repo.create_git_ref("refs/heads/BranchCreatedByPyGithub", "4303c5b90e2216d927155e9609436ccb8984c495")
        self.assertEqual(ref.url, "https://api.github.com/repos/jacquev6/PyGithub/git/refs/heads/BranchCreatedByPyGithub")

    def testCreateGitBlob(self):
        blob = self.repo.create_git_blob("Blob created by PyGithub", "latin1")
        self.assertEqual(blob.sha, "5dd930f591cd5188e9ea7200e308ad355182a1d8")

    def testCreateGitTree(self):
        tree = self.repo.create_git_tree(
            [github.InputGitTreeElement(
                "Foobar.txt",
                "100644",
                "blob",
                content="File created by PyGithub"
            )]
        )
        self.assertEqual(tree.sha, "41cf8c178c636a018d537cb20daae09391efd70b")

    def testCreateGitTreeWithBaseTree(self):
        base_tree = self.repo.get_git_tree("41cf8c178c636a018d537cb20daae09391efd70b")
        tree = self.repo.create_git_tree(
            [github.InputGitTreeElement(
                "Barbaz.txt",
                "100644",
                "blob",
                content="File also created by PyGithub"
            )],
            base_tree
        )
        self.assertEqual(tree.sha, "107139a922f33bab6fbeb9f9eb8787e7f19e0528")

    def testCreateGitTreeWithSha(self):
        tree = self.repo.create_git_tree(
            [github.InputGitTreeElement(
                "Barbaz.txt",
                "100644",
                "blob",
                sha="5dd930f591cd5188e9ea7200e308ad355182a1d8"
            )]
        )
        self.assertEqual(tree.sha, "fae707821159639589bf94f3fb0a7154ec5d441b")

    def testCreateGitCommit(self):
        tree = self.repo.get_git_tree("107139a922f33bab6fbeb9f9eb8787e7f19e0528")
        commit = self.repo.create_git_commit("Commit created by PyGithub", tree, [])
        self.assertEqual(commit.sha, "0b820628236ab8bab3890860fc414fa757ca15f4")

    def testCreateGitCommitWithParents(self):
        parents = [
            self.repo.get_git_commit("7248e66831d4ffe09ef1f30a1df59ec0a9331ece"),
            self.repo.get_git_commit("12d427464f8d91c8e981043a86ba8a2a9e7319ea"),
        ]
        tree = self.repo.get_git_tree("fae707821159639589bf94f3fb0a7154ec5d441b")
        commit = self.repo.create_git_commit("Commit created by PyGithub", tree, parents)
        self.assertEqual(commit.sha, "6adf9ea25ff8a8f2a42bcb1c09e42526339037cd")

    def testCreateGitCommitWithAllArguments(self):
        tree = self.repo.get_git_tree("107139a922f33bab6fbeb9f9eb8787e7f19e0528")
        commit = self.repo.create_git_commit("Commit created by PyGithub", tree, [], github.InputGitAuthor("John Doe", "j.doe@vincent-jacques.net", "2008-07-09T16:13:30+12:00"), github.InputGitAuthor("John Doe", "j.doe@vincent-jacques.net", "2008-07-09T16:13:30+12:00"))
        self.assertEqual(commit.sha, "526946197ae9da59c6507cacd13ad6f1cfb686ea")

    def testCreateGitTag(self):
        tag = self.repo.create_git_tag("TaggedByPyGithub", "Tag created by PyGithub", "0b820628236ab8bab3890860fc414fa757ca15f4", "commit")
        self.assertEqual(tag.sha, "5ba561eaa2b7ca9015662510157b15d8f3b0232a")

    def testCreateGitTagWithAllArguments(self):
        tag = self.repo.create_git_tag("TaggedByPyGithub2", "Tag also created by PyGithub", "526946197ae9da59c6507cacd13ad6f1cfb686ea", "commit", github.InputGitAuthor("John Doe", "j.doe@vincent-jacques.net", "2008-07-09T16:13:30+12:00"))
        self.assertEqual(tag.sha, "f0e99a8335fbc84c53366c4a681118468f266625")

    def testCreateKey(self):
        key = self.repo.create_key("Key added through PyGithub", "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA2Mm0RjTNAYFfSCtUpO54usdseroUSIYg5KX4JoseTpqyiB/hqewjYLAdUq/tNIQzrkoEJWSyZrQt0ma7/YCyMYuNGd3DU6q6ZAyBeY3E9RyCiKjO3aTL2VKQGFvBVVmGdxGVSCITRphAcsKc/PF35/fg9XP9S0anMXcEFtdfMHz41SSw+XtE+Vc+6cX9FuI5qUfLGbkv8L1v3g4uw9VXlzq4GfTA+1S7D6mcoGHopAIXFlVr+2RfDKdSURMcB22z41fljO1MW4+zUS/4FyUTpL991es5fcwKXYoiE+x06VJeJJ1Krwx+DZj45uweV6cHXt2JwJEI9fWB6WyBlDejWw== vincent@IDEE")
        self.assertEqual(key.id, 2626761)

    def testCollaborators(self):
        lyloa = self.g.get_user("Lyloa")
        self.assertFalse(self.repo.has_in_collaborators(lyloa))
        self.repo.add_to_collaborators(lyloa)
        self.assertTrue(self.repo.has_in_collaborators(lyloa))
        self.assertListKeyEqual(self.repo.get_collaborators(), lambda u: u.login, ["jacquev6", "Lyloa"])
        self.repo.remove_from_collaborators(lyloa)
        self.assertFalse(self.repo.has_in_collaborators(lyloa))

    def testCompare(self):
        comparison = self.repo.compare("v0.6", "v0.7")
        self.assertEqual(comparison.status, "ahead")
        self.assertEqual(comparison.ahead_by, 4)
        self.assertEqual(comparison.behind_by, 0)
        self.assertEqual(comparison.diff_url, "https://github.com/jacquev6/PyGithub/compare/v0.6...v0.7.diff")
        self.assertEqual(comparison.html_url, "https://github.com/jacquev6/PyGithub/compare/v0.6...v0.7")
        self.assertEqual(comparison.url, "https://api.github.com/repos/jacquev6/PyGithub/compare/v0.6...v0.7")
        self.assertEqual(comparison.patch_url, "https://github.com/jacquev6/PyGithub/compare/v0.6...v0.7.patch")
        self.assertEqual(comparison.permalink_url, "https://github.com/jacquev6/PyGithub/compare/jacquev6:4303c5b...jacquev6:ecda065")
        self.assertEqual(comparison.total_commits, 4)
        self.assertListKeyEqual(comparison.files, lambda f: f.filename, ["ReferenceOfClasses.md", "github/Github.py", "github/Requester.py", "setup.py"])
        self.assertEqual(comparison.base_commit.sha, "4303c5b90e2216d927155e9609436ccb8984c495")
        self.assertListKeyEqual(comparison.commits, lambda c: c.sha, ["5bb654d26dd014d36794acd1e6ecf3736f12aad7", "cb0313157bf904f2d364377d35d9397b269547a5", "0cec0d25e606c023a62a4fc7cdc815309ebf6d16", "ecda065e01876209d2bdf5fe4e91cee8ffaa9ff7"])

    def testGetComments(self):
        self.assertListKeyEqual(
            self.repo.get_comments(),
            lambda c: c.body,
            [
                "probably a noob question: does this completion refer to autocompletion in IDE's/editors? \nI have observed that this is pretty erratic sometimes. I'm using PyDev+Eclipse.\nFor example, in the tutorial from the readme, `g.get_u` gets autocompleted correctly, but `g.get_user().get_r` (or any method or attribute applicable to NamedUsers/AuthenticatedUser, really) does not show autocompletion to `g.get_user().get_repo()`. Is that by design? It makes exploring the library/API a bit cumbersome. ",
                "No, it has nothing to do with auto-completion in IDEs :D\n\nGithub API v3 sends only the main part of objects in reply to some requests. So, if the user wants an attribute that has not been received yet, I have to do another request to complete the object.\n\nYet, in version 1.0 (see the milesone), my library will be much more readable for IDEs and their auto-completion mechanisms, because I am giving up the meta-description that I used until 0.6, and I'm now generating much more traditional code, that you will be able to explore as if it was written manually.\n\nIf you want to take the time to open an issue about auto-completion in IDEs, I'll deal with it in milestone 1.0.\n\nThanks !",
                "Ah, thanks for the clarification. :blush:\n\nI made issue #27 for the autocompletion. I already suspected something like this meta-description magic, since I tried to read some of the code and it was pretty arcane. I attributed that to my pythonic noobness, though. Thank you. ",
                "Comment created by PyGithub"
            ]
        )

    def testGetCommits(self):
        self.assertListKeyBegin(self.repo.get_commits(), lambda c: c.sha, ['ecda065e01876209d2bdf5fe4e91cee8ffaa9ff7', '0cec0d25e606c023a62a4fc7cdc815309ebf6d16', 'cb0313157bf904f2d364377d35d9397b269547a5', '5bb654d26dd014d36794acd1e6ecf3736f12aad7', '4303c5b90e2216d927155e9609436ccb8984c495', '2a7e80e6421c5d4d201d60619068dea6bae612cb', '0af24499a98e85f8ab2191898e8b809e5cebd4c5', 'e5ae923a68a9ae295ce5aa20b1227253de60e918', '2f64b625f7e2afc9bef61d0decb459e2ef65c550', '590798d349cba7de6e83b43aa5d4f8b0a38e685d', 'e7dca9143a23b8e2045a4a910a4a329007b10086', 'ab3f9b422cb3043d35cf6002fc9c042f8ead8c2a', '632d8b63c32a2b79e87eb3b93e1ad228724de4bd', '64c6a1e975e61b9c1449bed016cd19f33ee4b1c5', '99963536fc81db3b9986c761b9dd08de22089aa2', '8d57522bbd15d1fb6b616fae795cd8721deb1c4d', '1140a91f3e45d09bc15463724f178a7ebf8e3149', '936f4a97f1a86392637ec002bbf89ff036a5062d', 'e10470481795506e2c232720e2a9ecf588c8b567', 'e456549e5265406f8090ae5145255c8ca9ea5e4e', 'a91131be42eb328ae030f584af500f56aa08424b', '2469c6e1aeb7919126a8271f6980b555b167e8b0', 'a655d0424135befd3a0d53f3f7eff2d1c754854f', 'ce62e91268aa34dad0ba0dbee4769933e3a71e50', '1c88ee221b7f995855a1fdfac7d0ba19db918739', 'bd1a5dff3c547c634b2d89f5847218820e343883', 'b226b5b4e2f44107dde674e7a5d3e88d4e3518df', '25dbd4053e982402c7d92139f167dbe46008c932', 'a0cc821c1beada4aa9ca0d5218664c5372720936', 'c1440bdf20bfeb62684c6d1779448719dce9d2df', '1095d304b7fab3818dcb4c42093c8c56d3ac05e4', 'bd39726f7cf86ea7ffb33b5718241fdab5fc8f53', '1d2b27824d20612066d84be42d6691c66bb18ef4', '6af2bfd0d46bc0eeb8c37b85c7b3003e0e4ae297', 'a475d685d8ae709095d09094ea0962ac182d33f0', 'a85de99ea5b5e7b38bd68e076d09c49207b8687e', 'd24cf209ddd1758188c5f35344f76df818d09a46', '0909fec395bb1f97e2580d6a029cfc64b352aff9', '6e421e9e85e12008758870bc046bc2c6120af72a', '32ed0ebc377efbed5b482b3d49ff54bf1715d55a', '8213df1d744f251aa8e52229643a9f6ce352f3c0', '69cc298fd159f19eb204dd09f17d31dc4abc3d41', '85eef756353e13efcb24c726320cd2617c2a7bd8', '50ac55b25ceba555b84709839f80447552450697', '767d75a580279e457f9bc52bc308a17ff8ea0509', '75e72ffa3066693291f7da03070666e8f885097a', '504047e218e6b34a3828ccc408431634f17b9504', '960db1d5c9853e9f5fbbc9237c2c166ceef1f080', '877dde23e140bbf038f9a2d8f0f07b4e3a965c61', '1c95ddfa09ec0aa1f07ee9ad50a77be1dd74b55e', '99564c1cab139d1e4678f5f83f60d26f1210db7e', '231926207709ceaa61e87b64e34e17d85adecd9c', 'fb722625dddb9a32f75190723f7da12683b7c4b2', 'cab9d71603e127bdd1f600a759dccea1781fa1ab', 'e648e5aeb5edc1fbf83e9d37d2a3cb57c005019a', '4a5cf98e7f959f1b5d9af484760c25cd27d9180d', '5d1add448e0b0b1dadb8c6094a9e5e19b255f67e', '0d9fc99a4b5d1ec6473c9c81c888917c132ffa65', 'b56aa09011378b014221f86dffb8304957a9e6bd', '3e8169c0a98ce1e2c6a32ae1256ae0f735065df5', '378558f6cac6183b4a7100c0ce5eaad1cfff6717', '58b4396aa0e7cb72911b75cb035798143a06e0ee', 'a3be28756101370fbc689eec3a7825c4c385a6c9', '3d6bd49ce229243fea4bb46a937622d0ec7d4d1c', '58cb0dbdef9765e0e913c726f923a47315aaf80e', '7b7ac20c6fa27f72a24483c73ab1bf4deffc89f0', '97f308e67383368a2d15788cac28e126c8528bb2', 'fc33a6de4f0e08d7ff2de05935517ec3932d212e', 'cc6d0fc044eadf2e6fde5da699f61654c1e691f3', '2dd71f3777b87f2ba61cb20d2c67f10401e3eb2c', '366ca58ca004b9129f9d435db8204ce0f5bc57c3', '0d3b3ffd1e5c143af8725fdee808101f626f683d', '157f9c13275738b6b39b8d7a874f5f0aee47cb18'])

    def testGetCommitsWithArguments(self):
        self.assertListKeyEqual(self.repo.get_commits("topic/RewriteWithGeneratedCode", "codegen/GenerateCode.py"), lambda c: c.sha, ["de386d5dc9cf103c90c4128eeca0e6abdd382065", "5b44982f6111bff2454243869df2e1c3086ccbba", "d6835ff949141957a733c8ddfa147026515ae493", "075d3d961d4614a2a0835d5583248adfc0687a7d", "8956796e7f462a49f499eac52fab901cdb59abdb", "283da5e7de6a4a3b6aaae7045909d70b643ad380", "d631e83b7901b0a0b6061b361130700a79505319"])

    def testGetCommitsWithSinceUntil(self):
        self.assertListKeyEqual(self.repo.get_commits(since=datetime.datetime(2013, 3, 1), until=datetime.datetime(2013, 3, 31)), lambda c: c.sha, ['db5560bd658b5d8057a864f7037ace4d5f618f1b', 'f266fed520fea4f683caabe0b38e1f758cfc5cff', 'dff094650011398fd8f0a57bf2668a066fb2cbcb', 'c1d747a9133a1c6cae1f0e11105a5f490f65fda6', '0bc368973acfb50a531329b6c196ba92e0a81890', '7b3e4c15ed6182963d66ffa9f0522acd0765275c', '4df3a7eb47888f38c4c6dae50573f030a0a3f1e1', 'e0db8cad4ec01c65e5e0eb50e11765e425e88ef9', '1c47be4e895b823baf907b25c647e43ab63c16dd', '8a9afbb1aa36c6ba04142c6e6c1cfbd7de982a6a', '1c67359a318f05e50bf457818e1983ce95aa5946', '1d18bd66f3a4a4225435bd38df04b8a227b5e821', 'b9d71fa787a2ffb99b6631e4bd6df932a4d4adbb', 'f5d8e221d116b74a200d87afca32247f01204ba1', 'dc96fef052f2b5c6adb34da65169e8df3f35f611', 'c85af79db11ed1d2f93261ea4069a23ff1709125', '0dd1adb4f06f45d554d12083b312fcdb6f6be8d1', 'b7e4000450e89b8c6e947e3a1e52fb06da7c9621', '1d9ad14fa918866c418067e774f65cede8e38682', '1bb05fef01d0a040cb2b931a4d44392784a2f0c1', 'd9b29851ddccc907f71f1ae662e57f2cd7c7dc71', 'f962bc71fee609cd54fe69c956c8b81703d2c19a', '7a9c0b916c632be8d6a65bc1b6f558508f04bb22', '82ce7b1ee30d308b48bdac6d8737dbca70500462', '1e99e7d5b21c71bf68cc5cc21faec30ee603b8b8', 'a397fac6db9f87a903ec3ede9643cb2b4224ed82', '109495175e926731703a55cafd8b542a07366513', 'da6bbdb69485fc3256030d8296589d4c2fb5df21', '34c18342dcce9697abc6f522c3506485202e6e7e', 'ee29deddd27480401db484733ecde9e7b1df5eda', '0901df1a2bed3f993cfe6e0d4cff5923bbf6ce32', 'edcf40bc7f25d1aff5c404406fbb37ad1bcf691e', 'f25c54e1d4eefb11c18f3de85270a4b19edea3ce', '23d668f11bdd806a871e0979bf5295d001f66ef2', '50a243671f1fa139cb1186c4a44c1e96b8cd5749', '6a3a384fd0decac1203db6c2bddc58039b0390bc', '82f5b4c61f86ae8c7cc85a31cb1a31180eeae32f', '6ac783974d3985dd0c162c1e8d1150615cc0082e', '0f9bb5d9fd2dcfbf03f094362e86323c9ef915e6', 'e25a6a49d1ab1a10c84db9b6722a6186ff6dfcbd', '4f1780f427eba400cbc06897e69eda0ecdecd887', '28648a51a15e430b85d6fe8f2514e1cb06bc76b8', 'a39f421ca24bd7aae984f8703159c7e30798a121', '86fe370b97b62548317cb35bc02ece3fabb7fa03', '03a256a4052cacea998d8205a83d5b5465f31e18', '9e6b086c2db5e4884484a04934f6f2e53e3f441b', '0ddb34d987b5a03813fdfa2fac13c933834a4804'])

    def testGetCommitsWithAuthor(self):
        self.g.per_page = 5
        akfish = self.g.get_user("AKFish")
        self.assertListKeyBegin(self.repo.get_commits(author=self.user), lambda c: c.sha, ["54f718a15770579a37ffbe7ae94ad30003407786"])
        self.assertListKeyBegin(self.repo.get_commits(author=akfish), lambda c: c.sha, ["38b137fb37c0fdc74f8802a4184518e105db9121"])
        self.assertListKeyBegin(self.repo.get_commits(author="m.ki2@laposte.net"), lambda c: c.sha, ["ab674dfcbc86c70bc32d9ecbe171b48a5694c337"])

    def testGetDownloads(self):
        self.assertListKeyEqual(self.repo.get_downloads(), lambda d: d.id, [245143])

    def testGetEvents(self):
        self.assertListKeyBegin(self.repo.get_events(), lambda e: e.type, ["DownloadEvent", "DownloadEvent", "PushEvent", "IssuesEvent", "MemberEvent", "MemberEvent"])

    def testGetForks(self):
        self.assertListKeyEqual(self.repo.get_forks(), lambda r: r.owner.login, ["abersager"])

    def testGetGitRefs(self):
        self.assertListKeyEqual(self.repo.get_git_refs(), lambda r: r.ref, ["refs/heads/develop", "refs/heads/master", "refs/heads/topic/DependencyGraph", "refs/heads/topic/RewriteWithGeneratedCode", "refs/tags/v0.1", "refs/tags/v0.2", "refs/tags/v0.3", "refs/tags/v0.4", "refs/tags/v0.5", "refs/tags/v0.6", "refs/tags/v0.7"])

    def testGetGitRef(self):
        self.assertTrue(self.g.FIX_REPO_GET_GIT_REF)
        self.assertEqual(self.repo.get_git_ref("heads/master").object.sha, "31110327ec45f3138e58ed247b2cf420fee481ec")

    def testGetGitRefWithIssue102Reverted(self):
        self.g.FIX_REPO_GET_GIT_REF = False
        self.assertFalse(self.g.FIX_REPO_GET_GIT_REF)
        self.assertEqual(self.repo.get_git_ref("refs/heads/master").object.sha, "31110327ec45f3138e58ed247b2cf420fee481ec")
        self.g.FIX_REPO_GET_GIT_REF = True
        self.assertTrue(self.g.FIX_REPO_GET_GIT_REF)

    def testGetGitTreeWithRecursive(self):
        tree = self.repo.get_git_tree("f492784d8ca837779650d1fb406a1a3587a764ad", True)
        self.assertEqual(len(tree.tree), 90)
        self.assertEqual(tree.tree[50].path, "github/GithubObjects/Gist.py")

    def testGetHooks(self):
        self.assertListKeyEqual(self.repo.get_hooks(), lambda h: h.id, [257993])

    def testGetIssues(self):
        self.assertListKeyEqual(self.repo.get_issues(), lambda i: i.id, [4769659, 4639931, 4452000, 4356743, 3716033, 3715946, 3643837, 3628022, 3624595, 3624570, 3624561, 3624556, 3619973, 3527266, 3527245, 3527231])

    def testGetIssuesWithArguments(self):
        milestone = self.repo.get_milestone(3)
        user = self.g.get_user("jacquev6")
        otherUser = self.g.get_user("Lyloa")
        bug = self.repo.get_label("Bug")
        self.assertListKeyEqual(self.repo.get_issues(milestone, "closed"), lambda i: i.id, [3624472, 3620132, 3619658, 3561926])
        self.assertListKeyEqual(self.repo.get_issues(labels=[bug]), lambda i: i.id, [4780155])
        self.assertListKeyEqual(self.repo.get_issues(assignee=user, sort="comments", direction="asc"), lambda i: i.id, [4793106, 3527231, 3527266, 3624556, 4793216, 3619973, 3624595, 4452000, 3643837, 3628022, 3527245, 4793162, 4356743, 4780155])
        self.assertListKeyEqual(self.repo.get_issues(since=datetime.datetime(2012, 5, 28, 23, 0, 0)), lambda i: i.id, [4793216, 4793162, 4793106, 3624556, 3619973, 3527266])
        self.assertListKeyEqual(self.repo.get_issues(mentioned=otherUser), lambda i: i.id, [4793162])

    def testGetIssuesWithWildcards(self):
        self.assertListKeyEqual(self.repo.get_issues(milestone="*"), lambda i: i.id, [4809786, 4793216, 4789817, 4452000, 3628022, 3624595, 3619973, 3527231])
        self.assertListKeyEqual(self.repo.get_issues(milestone="none"), lambda i: i.id, [4823331, 4809803, 4809778, 4793106, 3643837, 3527245])
        self.assertListKeyEqual(self.repo.get_issues(assignee="*"), lambda i: i.id, [4823331, 4809803, 4809786, 4809778, 4793216, 4793106, 4789817, 4452000, 3643837, 3628022, 3624595, 3527245, 3527231])
        self.assertListKeyEqual(self.repo.get_issues(assignee="none"), lambda i: i.id, [3619973])

    def testGetKeys(self):
        self.assertListKeyEqual(self.repo.get_keys(), lambda k: k.title, ["Key added through PyGithub"])

    def testGetLabels(self):
        self.assertListKeyEqual(self.repo.get_labels(), lambda l: l.name, ["Refactoring", "Public interface", "Functionalities", "Project management", "Bug", "Question"])

    def testGetLanguages(self):
        self.assertEqual(self.repo.get_languages(), {"Python": 127266, "Shell": 673})

    def testGetMilestones(self):
        self.assertListKeyEqual(self.repo.get_milestones(), lambda m: m.id, [93547])

    def testGetMilestonesWithArguments(self):
        self.assertListKeyEqual(self.repo.get_milestones("closed", "due_date", "asc"), lambda m: m.id, [93546, 95354, 108652, 124045])

    def testGetIssuesEvents(self):
        self.assertListKeyBegin(self.repo.get_issues_events(), lambda e: e.event, ["assigned", "subscribed", "closed", "assigned", "closed"])

    def testGetNetworkEvents(self):
        self.assertListKeyBegin(self.repo.get_network_events(), lambda e: e.type, ["DownloadEvent", "DownloadEvent", "PushEvent", "IssuesEvent", "MemberEvent"])

    def testGetTeams(self):
        repo = self.g.get_organization("BeaverSoftware").get_repo("FatherBeaver")
        self.assertListKeyEqual(repo.get_teams(), lambda t: t.name, ["Members"])

    def testGetWatchers(self):
        self.assertListKeyEqual(self.repo.get_watchers(), lambda u: u.login, ["Stals", "att14", "jardon-u", "huxley", "mikofski", "L42y", "fanzeyi", "abersager", "waylan", "adericbourg", "tallforasmurf", "pvicente", "roskakori", "michaelpedersen", "BeaverSoftware"])

    def testGetStargazers(self):
        self.assertListKeyEqual(self.repo.get_stargazers(), lambda u: u.login, ["Stals", "att14", "jardon-u", "huxley", "mikofski", "L42y", "fanzeyi", "abersager", "waylan", "adericbourg", "tallforasmurf", "pvicente", "roskakori", "michaelpedersen", "stefanfoulis", "equus12", "JuRogn", "joshmoore", "jsilter", "dasapich", "ritratt", "hcilab", "vxnick", "pmuilu", "herlo", "malexw", "ahmetvurgun", "PengGu", "cosmin", "Swop", "kennethreitz", "bryandyck", "jason2506", "zsiciarz", "waawal", "gregorynicholas", "sente", "richmiller55", "thouis", "mazubieta", "michaelhood", "engie", "jtriley", "oangeor", "coryking", "noddi", "alejo8591", "omab", "Carreau", "bilderbuchi", "schwa", "rlerallut", "PengHub", "zoek1", "xobb1t", "notgary", "hattya", "ZebtinRis", "aaronhall", "youngsterxyf", "ailling", "gregwjacobs", "n0rmrx", "awylie", "firstthumb", "joshbrand", "berndca"])

    def testGetStargazersWithDates(self):
        repo = self.g.get_user("danvk").get_repo("comparea")
        self.assertListKeyEqual(
            repo.get_stargazers_with_dates(),
            lambda stargazer: (stargazer.starred_at, stargazer.user.login),
            [
                (datetime.datetime(2014, 8, 13, 19, 22, 5), 'sAlexander'),
                (datetime.datetime(2014, 10, 15, 5, 2, 30), 'ThomasG77'),
                (datetime.datetime(2015, 4, 14, 15, 22, 40), 'therusek'),
                (datetime.datetime(2015, 4, 29, 0, 9, 40), 'athomann'),
                (datetime.datetime(2015, 4, 29, 14, 26, 46), 'jcapron'),
                (datetime.datetime(2015, 5, 9, 19, 14, 45), 'JoePython1')
            ]
        )

    def testGetSubscribers(self):
        self.assertListKeyEqual(self.repo.get_subscribers(), lambda u: u.login, ["jacquev6", "equus12", "bilderbuchi", "hcilab", "hattya", "firstthumb", "gregwjacobs", "sagarsane", "liang456", "berndca", "Lyloa"])

    def testCreatePull(self):
        pull = self.repo.create_pull("Pull request created by PyGithub", "Body of the pull request", "topic/RewriteWithGeneratedCode", "BeaverSoftware:master")
        self.assertEqual(pull.id, 1436215)

    def testCreatePullFromIssue(self):
        issue = self.repo.get_issue(32)
        pull = self.repo.create_pull(issue, "topic/RewriteWithGeneratedCode", "BeaverSoftware:master")
        self.assertEqual(pull.id, 1436310)

    def testGetPulls(self):
        self.assertListKeyEqual(self.repo.get_pulls(), lambda p: p.id, [1436310])

    def testGetPullsWithArguments(self):
        self.assertListKeyEqual(self.repo.get_pulls("closed"), lambda p: p.id, [1448168, 1436310, 1436215])

    def testLegacySearchIssues(self):
        issues = self.repo.legacy_search_issues("open", "search")
        self.assertListKeyEqual(issues, lambda i: i.title, ["Support new Search API"])

        # Attributes retrieved from legacy API without lazy completion call
        self.assertEqual(issues[0].number, 49)
        self.assertEqual(issues[0].created_at, datetime.datetime(2012, 6, 21, 12, 27, 38))
        self.assertEqual(issues[0].comments, 4)
        self.assertEqual(issues[0].body[: 20], "New API ported from ")
        self.assertEqual(issues[0].title, "Support new Search API")
        self.assertEqual(issues[0].updated_at, datetime.datetime(2012, 6, 28, 21, 13, 25))
        self.assertEqual(issues[0].user.login, "kukuts")
        self.assertEqual(issues[0].user.url, "/users/kukuts")
        self.assertListKeyEqual(issues[0].labels, lambda l: l.name, ["Functionalities", "RequestedByUser"])
        self.assertEqual(issues[0].state, "open")

    def testAssignees(self):
        lyloa = self.g.get_user("Lyloa")
        jacquev6 = self.g.get_user("jacquev6")
        self.assertTrue(self.repo.has_in_assignees(jacquev6))
        self.assertFalse(self.repo.has_in_assignees(lyloa))
        self.repo.add_to_collaborators(lyloa)
        self.assertTrue(self.repo.has_in_assignees(lyloa))
        self.assertListKeyEqual(self.repo.get_assignees(), lambda u: u.login, ["jacquev6", "Lyloa"])
        self.repo.remove_from_collaborators(lyloa)
        self.assertFalse(self.repo.has_in_assignees(lyloa))

    def testGetContents(self):
        self.assertEqual(len(self.repo.get_readme().content), 10212)
        self.assertEqual(len(self.repo.get_contents("/doc/ReferenceOfClasses.md").content), 38121)

    def testGetContentDir(self):

        contents = self.repo.get_contents("/")
        self.assertTrue(isinstance(contents, list))
        self.assertEqual(len(contents), 14)

    def testGetContentsWithRef(self):
        self.assertEqual(len(self.repo.get_readme(ref="refs/heads/topic/ExperimentOnDocumentation").content), 6747)
        self.assertEqual(len(self.repo.get_contents("/doc/ReferenceOfClasses.md", ref="refs/heads/topic/ExperimentOnDocumentation").content), 43929)

    def testCreateFile(self):
        newFile = '/doc/testCreateUpdateDeleteFile.md'
        content = 'Hello world'
        self.repo.create_file(
            path=newFile, message='Create file for testCreateFile', content=content,
            branch="master", committer=github.InputGitAuthor("Enix Yu", "enix223@163.com", "2016-01-15T16:13:30+12:00"),
            author=github.InputGitAuthor("Enix Yu", "enix223@163.com", "2016-01-15T16:13:30+12:00"))

    def testUpdateFile(self):
        updateFile = '/doc/testCreateUpdateDeleteFile.md'
        content = 'Hello World'
        sha = self.repo.get_contents(updateFile).sha
        self.repo.update_file(
            path=updateFile, message='Update file for testUpdateFile', content=content, sha=sha,
            branch="master", committer=github.InputGitAuthor("Enix Yu", "enix223@163.com", "2016-01-15T16:13:30+12:00"),
            author=github.InputGitAuthor("Enix Yu", "enix223@163.com", "2016-01-15T16:13:30+12:00"))

    def testDeleteFile(self):
        deleteFile = '/doc/testCreateUpdateDeleteFile.md'
        sha = self.repo.get_contents(deleteFile).sha
        self.repo.delete_file(path=deleteFile, message='Delete file for testDeleteFile', sha=sha, branch="master")

    def testGetArchiveLink(self):
        self.assertEqual(self.repo.get_archive_link("tarball"), "https://nodeload.github.com/jacquev6/PyGithub/tarball/master")
        self.assertEqual(self.repo.get_archive_link("zipball"), "https://nodeload.github.com/jacquev6/PyGithub/zipball/master")
        self.assertEqual(self.repo.get_archive_link("zipball", "master"), "https://nodeload.github.com/jacquev6/PyGithub/zipball/master")
        self.assertEqual(self.repo.get_archive_link("tarball", "develop"), "https://nodeload.github.com/jacquev6/PyGithub/tarball/develop")

    def testGetBranch(self):
        branch = self.repo.get_branch("develop")
        self.assertEqual(branch.commit.sha, "03058a36164d2a7d946db205f25538434fa27d94")

    def testMergeWithoutMessage(self):
        commit = self.repo.merge("branchForBase", "branchForHead")
        self.assertEqual(commit.commit.message, "Merge branchForHead into branchForBase")

    def testMergeWithMessage(self):
        commit = self.repo.merge("branchForBase", "branchForHead", "Commit message created by PyGithub")
        self.assertEqual(commit.commit.message, "Commit message created by PyGithub")

    def testMergeWithNothingToDo(self):
        commit = self.repo.merge("branchForBase", "branchForHead", "Commit message created by PyGithub")
        self.assertEqual(commit, None)

    def testMergeWithConflict(self):
        raised = False
        try:
            commit = self.repo.merge("branchForBase", "branchForHead")
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 409)
            self.assertEqual(exception.data, {"message": "Merge conflict"})
        self.assertTrue(raised)

    def testGetIssuesComments(self):
        self.assertListKeyEqual(self.repo.get_issues_comments()[:40], lambda c: c.id, [5168757, 5181640, 5183010, 5186061, 5226090, 5449237, 5518272, 5547576, 5780183, 5781803, 5820199, 5820912, 5924198, 5965724, 5965812, 5965891, 5966555, 5966633, 5981084, 5981232, 5981409, 5981451, 5991965, 6019700, 6088432, 6293572, 6305625, 6357374, 6357422, 6447481, 6467193, 6467312, 6467642, 6481200, 6481392, 6556134, 6557261, 6568164, 6568181, 6568553])
        self.assertListKeyEqual(self.repo.get_issues_comments(sort="created", direction="asc")[:40], lambda c: c.id, [5168757, 5181640, 5183010, 5186061, 5226090, 5449237, 5518272, 5547576, 5780183, 5781803, 5820199, 5820912, 5924198, 5965724, 5965812, 5965891, 5966555, 5966633, 5981084, 5981232, 5981409, 5981451, 5991965, 6019700, 6088432, 6293572, 6305625, 6357374, 6357422, 6447481, 6467193, 6467312, 6467642, 6481200, 6481392, 6556134, 6557261, 6568164, 6568181, 6568553])
        self.assertListKeyEqual(self.repo.get_issues_comments(since=datetime.datetime(2012, 5, 28, 23, 0, 0))[:40], lambda c: c.id, [5981084, 5981232, 5981409, 5981451, 5991965, 6019700, 6088432, 6293572, 6305625, 6357374, 6357422, 6447481, 6467193, 6467312, 6467642, 6481200, 6481392, 6556134, 6557261, 6568164, 6568181, 6568553, 6640187, 6640189, 6641223, 6673380, 6710355, 6727553, 6727659, 6727848, 6728069, 6728241, 6728370, 6886561, 6972414, 6994436, 7060818, 7060993, 7211543, 7407798])

    def testGetPullsComments(self):
        self.assertListKeyEqual(self.repo.get_pulls_comments(), lambda c: c.id, [1580134])
        self.assertListKeyEqual(self.repo.get_pulls_comments(sort="created", direction="asc"), lambda c: c.id, [1580134])
        self.assertListKeyEqual(self.repo.get_pulls_comments(since=datetime.datetime(2012, 5, 28, 23, 0, 0)), lambda c: c.id, [1580134])

    def testSubscribePubSubHubbub(self):
        self.repo.subscribe_to_hub("push", "http://requestb.in/1bc1sc61", "my_secret")

    def testBadSubscribePubSubHubbub(self):
        raised = False
        try:
            self.repo.subscribe_to_hub("non-existing-event", "http://requestb.in/1bc1sc61")
        except github.GithubException as exception:
            raised = True
            self.assertEqual(exception.status, 422)
            self.assertEqual(exception.data, {"message": "Invalid event: \"non-existing-event\""})
        self.assertTrue(raised)

    def testUnsubscribePubSubHubbub(self):
        self.repo.unsubscribe_from_hub("push", "http://requestb.in/1bc1sc61")

    def testStatisticsBeforeCaching(self):
        self.assertEqual(self.repo.get_stats_contributors(), None)
        self.assertEqual(self.repo.get_stats_commit_activity(), None)
        self.assertEqual(self.repo.get_stats_code_frequency(), None)
        # ReplayData for those last two get_stats is forged because I was not
        # able to find a repo where participation and punch_card had never been
        # computed, and pushing to master did not reset the cache for them
        self.assertEqual(self.repo.get_stats_participation(), None)
        self.assertEqual(self.repo.get_stats_punch_card(), None)

    def testStatisticsAfterCaching(self):
        stats = self.repo.get_stats_contributors()
        seenJacquev6 = False
        for s in stats:
            adTotal = 0
            total = 0
            for w in s.weeks:
                total += w.c
                adTotal += w.a + w.d
            self.assertEqual(total, s.total)
            if s.author.login == "jacquev6":
                seenJacquev6 = True
                self.assertEqual(adTotal, 282147)
                self.assertEqual(s.weeks[0].w, datetime.datetime(2012, 2, 12))
        self.assertTrue(seenJacquev6)

        stats = self.repo.get_stats_commit_activity()
        self.assertEqual(stats[0].week, datetime.datetime(2012, 11, 18, 0, 0))
        self.assertEqual(stats[0].total, 29)
        self.assertEqual(stats[0].days, [0, 7, 3, 9, 7, 3, 0])

        stats = self.repo.get_stats_code_frequency()
        self.assertEqual(stats[0].week, datetime.datetime(2012, 2, 12, 0, 0))
        self.assertEqual(stats[0].additions, 3853)
        self.assertEqual(stats[0].deletions, -2098)

        stats = self.repo.get_stats_participation()
        self.assertEqual(stats.owner, [1, 36, 8, 0, 0, 8, 18, 0, 0, 0, 0, 7, 20, 6, 9, 0, 4, 11, 20, 16, 0, 3, 0, 16, 0, 0, 6, 1, 4, 0, 1, 6, 0, 0, 12, 10, 0, 0, 0, 1, 44, 0, 20, 10, 0, 0, 0, 0, 0, 10, 0, 0])
        self.assertEqual(stats.all, [4, 36, 8, 0, 0, 10, 20, 0, 0, 0, 0, 11, 20, 6, 9, 0, 4, 14, 21, 16, 0, 3, 0, 20, 0, 0, 8, 1, 9, 16, 1, 15, 1, 0, 12, 12, 0, 4, 6, 15, 116, 20, 20, 11, 0, 0, 0, 0, 0, 10, 0, 0])

        stats = self.repo.get_stats_punch_card()
        self.assertEqual(stats.get(4, 12), 7)
        self.assertEqual(stats.get(6, 18), 2)


class LazyRepository(Framework.TestCase):

    def setUp(self):
        Framework.TestCase.setUp(self)
        self.user = self.g.get_user()
        self.repository_name = '%s/%s' % (self.user.login, "PyGithub")

    def getLazyRepository(self):
        return self.g.get_repo(self.repository_name, lazy=True)

    def getEagerRepository(self):
        return self.g.get_repo(self.repository_name, lazy=False)

    def testGetIssues(self):
        lazy_repo = self.getLazyRepository()
        issues = lazy_repo.get_issues()
        eager_repo = self.getEagerRepository()
        issues2 = eager_repo.get_issues()
        self.assertListKeyEqual(issues2, id, [x for x in issues])

    def testOwner(self):
        lazy_repo = self.getLazyRepository()
        owner = lazy_repo.owner
        eager_repo = self.getEagerRepository()
        self.assertEqual(owner, eager_repo.owner)
