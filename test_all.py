import unittest
import os
import re
from collections import namedtuple
from truffleHog import truffleHog


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



if __name__ == '__main__':
    unittest.main()
