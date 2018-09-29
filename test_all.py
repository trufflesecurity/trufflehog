import unittest
import os
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


    def test_report_with_repeated_findings(self):
        issues = [{
            "stringsFound": ["abc", "abc"],
            "reason": "",
            "date": "",
            "commitHash": "",
            "commitAuthorName": "",
            "commitAuthorEmail": "",
            "path": "",
            "branch": "",
            "commit": ""
        }]
        report_issues = []

        truffleHog.addIssuesToReport(issues, report_issues)

        self.assertEqual(len(report_issues), 1)


    def test_report_with_repeated_commit(self):
        issues = [{
            "stringsFound": ["abc", "abc"],
            "reason": "",
            "date": "",
            "commitHash": "11111",
            "commitAuthorName": "",
            "commitAuthorEmail": "",
            "path": "",
            "branch": "",
            "commit": ""
        }]
        report_issues = []

        truffleHog.addIssuesToReport(issues, report_issues)

        commits = report_issues[0]['commits']
        self.assertEqual(len(commits), 1)


    def test_report_high_entropy_issue_has_relevant_lines(self):
        issues = [{
            "stringsFound": ["abc", "abc"],
            "linesFound": ["lorem abc", "ipsum abc amet"],
            "reason": "",
            "date": "",
            "commitHash": "11111",
            "commitAuthorName": "",
            "commitAuthorEmail": "",
            "path": "",
            "branch": "",
            "commit": ""
        }]
        report_issues = []

        truffleHog.addIssuesToReport(issues, report_issues)

        commit = report_issues[0]['commits'][0]
        self.assertEqual(len(commit['relevantLines']), 2)


    def test_saveReport_without_issues(self):
        truffleHog.saveReport('/tmp/test.json', [])


if __name__ == '__main__':
    unittest.main()
