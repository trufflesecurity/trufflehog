import unittest
import os
from truffleHog import truffleHog
from mock import patch 
from mock import MagicMock


class TestStringMethods(unittest.TestCase):

    def test_shannon(self):
        random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        random_stringHex = "b3A0a1FDfe86dcCE945B72" 
        self.assertGreater(truffleHog.shannon_entropy(random_stringB64, truffleHog.BASE64_CHARS), 4.5)
        self.assertGreater(truffleHog.shannon_entropy(random_stringHex, truffleHog.HEX_CHARS), 3)

    def test_cloning(self):
        project_path = truffleHog.clone_git_repo("https://github.com/dxa4481/truffleHog.git")
        license_file = os.path.join(project_path, "LICENSE")
        self.assertTrue(os.path.isfile(license_file))

    def test_unicode_expection(self):
        try:
            truffleHog.find_strings("https://github.com/dxa4481/tst.git")
        except UnicodeEncodeError:
            self.fail("Unicode print error")

    @patch('truffleHog.truffleHog.clone_git_repo')
    @patch('truffleHog.truffleHog.Repo')
    def test_branch(self, repo_const_mock, clone_git_repo): 
        repo = MagicMock()
        repo_const_mock.return_value = repo
        truffleHog.find_strings("test_repo", branch="testbranch")
        repo.remotes.origin.fetch.assert_called_once_with("testbranch")

if __name__ == '__main__':
    unittest.main()
