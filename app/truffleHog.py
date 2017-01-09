#!/usr/bin/env python
import shutil
import sys
import argparse
import tempfile
import os
import stat
from git import Repo

import thlib

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf8')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def find_strings(git_url):
    project_path = tempfile.mkdtemp()

    Repo.clone_from(git_url, project_path)

    repo = Repo(project_path)

    already_searched = set()
    for remote_branch in repo.remotes.origin.fetch():
        branch_name = str(remote_branch).split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits():
            if not prev_commit:
                pass
            else:
                # avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:
                    printableDiff = blob.diff.decode()
                    if printableDiff.startswith("Binary files"):
                        continue
                    lines = blob.diff.decode().split("\n")
                    for line in lines:
                        for word in line.split():
                            base64_strings = thlib.Utility.get_strings_of_set(word, BASE64_CHARS)
                            hex_strings = thlib.Utility.get_strings_of_set(word, HEX_CHARS)
                            for string in base64_strings:
                                printableDiff.replace(string, thlib.Utility.examine_string(string, "b64"))
                            for string in hex_strings:
                                printableDiff.replace(string, thlib.Utility.examine_string(string, "b64"))
                    if thlib.BColors.WARNING in printableDiff:
                        thlib.Utility.print_alert(prev_commit, branch_name, printableDiff)
            prev_commit = curr_commit
    return project_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()
    print args
    project_path = find_strings(args.git_url)
    shutil.rmtree(project_path, onerror=del_rw)
