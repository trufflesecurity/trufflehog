import unittest
import os
import sys
import json
import io
import re
from collections import namedtuple
from truffleHog import truffleHog
from mock import patch 
from mock import MagicMock
from tempfile import mkdtemp
from subprocess import run, STDOUT
from truffleHog import truffleHog

FNULL = open(os.devnull, 'w')


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

    def test_return_correct_commit_hash(self):
        # Start at commit d15627104d07846ac2914a976e8e347a663bbd9b, which 
        # is immediately followed by a secret inserting commit:
        # https://github.com/dxa4481/truffleHog/commit/9ed54617547cfca783e0f81f8dc5c927e3d1e345
        since_commit = 'd15627104d07846ac2914a976e8e347a663bbd9b'
        commit_w_secret = '9ed54617547cfca783e0f81f8dc5c927e3d1e345'
        cross_valdiating_commit_w_secret_comment = 'OH no a secret'

        json_result = ''
        if sys.version_info >= (3,):
            tmp_stdout = io.StringIO()
        else:
            tmp_stdout = io.BytesIO()
        bak_stdout = sys.stdout

        # Redirect STDOUT, run scan and re-establish STDOUT
        sys.stdout = tmp_stdout
        try:
            truffleHog.find_strings("https://github.com/dxa4481/truffleHog.git", 
                since_commit=since_commit, printJson=True, surpress_output=False)
        finally:
            sys.stdout = bak_stdout

        json_result_list = tmp_stdout.getvalue().split('\n')
        results = [json.loads(r) for r in json_result_list if bool(r.strip())]
        filtered_results = list(filter(lambda r: r['commitHash'] == commit_w_secret, results))
        self.assertEqual(1, len(filtered_results))
        self.assertEqual(commit_w_secret, filtered_results[0]['commitHash'])
        # Additionally, we cross-validate the commit comment matches the expected comment
        self.assertEqual(cross_valdiating_commit_w_secret_comment, filtered_results[0]['commit'].strip())

    @patch('truffleHog.truffleHog.clone_git_repo')
    @patch('truffleHog.truffleHog.Repo')
    @patch('shutil.rmtree')
    def test_branch(self, rmtree_mock, repo_const_mock, clone_git_repo):
        repo = MagicMock()
        repo_const_mock.return_value = repo
        truffleHog.find_strings("test_repo", branch="testbranch")
        repo.remotes.origin.fetch.assert_called_once_with("testbranch")
    def test_path_included(self):
        Blob = namedtuple('Blob', ('a_path', 'b_path'))
        blobs = {
            'file-root-dir': Blob('file', 'file'),
            'file-sub-dir': Blob('sub-dir/file', 'sub-dir/file'),
            'new-file-root-dir': Blob(None, 'new-file'),
            'new-file-sub-dir': Blob(None, 'sub-dir/new-file'),
            'deleted-file-root-dir': Blob('deleted-file', None),
            'deleted-file-sub-dir': Blob('sub-dir/deleted-file', None),
            'renamed-file-root-dir': Blob('file', 'renamed-file'),
            'renamed-file-sub-dir': Blob('sub-dir/file', 'sub-dir/renamed-file'),
            'moved-file-root-dir-to-sub-dir': Blob('moved-file', 'sub-dir/moved-file'),
            'moved-file-sub-dir-to-root-dir': Blob('sub-dir/moved-file', 'moved-file'),
            'moved-file-sub-dir-to-sub-dir': Blob('sub-dir/moved-file', 'moved/moved-file'),
        }
        src_paths = set(blob.a_path for blob in blobs.values() if blob.a_path is not None)
        dest_paths = set(blob.b_path for blob in blobs.values() if blob.b_path is not None)
        all_paths = src_paths.union(dest_paths)
        all_paths_patterns = [re.compile(re.escape(p)) for p in all_paths]
        overlap_patterns = [re.compile(r'sub-dir/.*'), re.compile(r'moved/'), re.compile(r'[^/]*file$')]
        sub_dirs_patterns = [re.compile(r'.+/.+')]
        deleted_paths_patterns = [re.compile(r'(.*/)?deleted-file$')]
        for name, blob in blobs.items():
            self.assertTrue(truffleHog.path_included(blob),
                            '{} should be included by default'.format(blob))
            self.assertTrue(truffleHog.path_included(blob, include_patterns=all_paths_patterns),
                            '{} should be included with include_patterns: {}'.format(blob, all_paths_patterns))
            self.assertFalse(truffleHog.path_included(blob, exclude_patterns=all_paths_patterns),
                             '{} should be excluded with exclude_patterns: {}'.format(blob, all_paths_patterns))
            self.assertFalse(truffleHog.path_included(blob,
                                                      include_patterns=all_paths_patterns,
                                                      exclude_patterns=all_paths_patterns),
                             '{} should be excluded with overlapping patterns: \n\tinclude: {}\n\texclude: {}'.format(
                                 blob, all_paths_patterns, all_paths_patterns))
            self.assertFalse(truffleHog.path_included(blob,
                                                      include_patterns=overlap_patterns,
                                                      exclude_patterns=all_paths_patterns),
                             '{} should be excluded with overlapping patterns: \n\tinclude: {}\n\texclude: {}'.format(
                                 blob, overlap_patterns, all_paths_patterns))
            self.assertFalse(truffleHog.path_included(blob,
                                                      include_patterns=all_paths_patterns,
                                                      exclude_patterns=overlap_patterns),
                             '{} should be excluded with overlapping patterns: \n\tinclude: {}\n\texclude: {}'.format(
                                 blob, all_paths_patterns, overlap_patterns))
            path = blob.b_path if blob.b_path else blob.a_path
            if '/' in path:
                self.assertTrue(truffleHog.path_included(blob, include_patterns=sub_dirs_patterns),
                                '{}: inclusion should include sub directory paths: {}'.format(blob, sub_dirs_patterns))
                self.assertFalse(truffleHog.path_included(blob, exclude_patterns=sub_dirs_patterns),
                                 '{}: exclusion should exclude sub directory paths: {}'.format(blob, sub_dirs_patterns))
            else:
                self.assertFalse(truffleHog.path_included(blob, include_patterns=sub_dirs_patterns),
                                 '{}: inclusion should exclude root directory paths: {}'.format(blob, sub_dirs_patterns))
                self.assertTrue(truffleHog.path_included(blob, exclude_patterns=sub_dirs_patterns),
                                '{}: exclusion should include root directory paths: {}'.format(blob, sub_dirs_patterns))
            if name.startswith('deleted-file-'):
                self.assertTrue(truffleHog.path_included(blob, include_patterns=deleted_paths_patterns),
                                '{}: inclusion should match deleted paths: {}'.format(blob, deleted_paths_patterns))
                self.assertFalse(truffleHog.path_included(blob, exclude_patterns=deleted_paths_patterns),
                                 '{}: exclusion should match deleted paths: {}'.format(blob, deleted_paths_patterns))



    @patch('truffleHog.truffleHog.clone_git_repo')
    @patch('truffleHog.truffleHog.Repo')
    @patch('shutil.rmtree')
    def test_repo_path(self, rmtree_mock, repo_const_mock, clone_git_repo):
        truffleHog.find_strings("test_repo", repo_path="test/path/")
        rmtree_mock.assert_not_called()
        clone_git_repo.assert_not_called()


class TestDiff(unittest.TestCase):

    def setUp(self):
        # Create repo
        self.repo_dir = mkdtemp()
        self.file_path = os.path.join(self.repo_dir, "file.txt")
        run(['git', 'init', self.repo_dir], stdout=FNULL, stderr=STDOUT)

    def test_diff_one_commit(self):
        self.commit_new_line('commit 1', 'commit 1 with secret m5nR7k7AmZ88Ge0IP9wZ8OQDT6zCYEiWjRVZxaMAGapTKvr9pRkDF')

        # Fire
        output = truffleHog.find_strings(self.repo_dir + '/.git')

        diff = self.get_first_diff(output)
        self.assert_diff_appends(diff)

    def test_diff_multiple_commits(self):
        self.commit_new_line('commit 1', 'commit 1')
        self.commit_new_line('commit 2', 'commit 2 with secret m5nR7k7AmZ88Ge0IP9wZ8OQDT6zCYEiWjRVZxaMAGapTKvr9pRkDF')

        # Fire
        output = truffleHog.find_strings(self.repo_dir + '/.git')

        diff = self.get_first_diff(output)
        self.assert_diff_appends(diff)

    def commit_new_line(self, msg, content):
        with open(self.file_path, 'a') as f:
            f.write(content + "\n")
        run(['git', 'add', self.file_path], cwd=self.repo_dir, stdout=FNULL, stderr=STDOUT)
        run(['git', 'commit', '-m', msg], cwd=self.repo_dir, stdout=FNULL, stderr=STDOUT)

    def assert_diff_appends(self, diff):
        last_line = diff.splitlines()[-1]
        self.assertEqual('+', last_line[:1])

    def get_first_diff(self, output):
        if not output['foundIssues']:
            self.fail('no issues found')
        with open(output['foundIssues'][0], 'r') as f:
            issue = json.loads(f.read())
            return issue['diff']


if __name__ == '__main__':
    unittest.main()
