#!/usr/bin/env python
import shutil
import sys
import argparse
import tempfile
import os
import stat
import sys
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
    clean_exit = True
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
                    issues_found = False
                    for line in lines:
                        for word in line.split():
                            base64_strings = thlib.Utility.get_strings_of_set(word, BASE64_CHARS)
                            hex_strings = thlib.Utility.get_strings_of_set(word, HEX_CHARS)
                            for in_string in base64_strings:
                                out_string = thlib.Utility.examine_string(in_string, "b64")
                                if in_string != out_string:
                                    issues_found = True
                                    printableDiff = printableDiff.replace(in_string, out_string)
                            for in_string in hex_strings:
                                out_string = thlib.Utility.examine_string(in_string, "hex")
                                if in_string != out_string:
                                    issues_found = True
                                    printableDiff = printableDiff.replace(in_string, out_string)
                    if issues_found is True:
                        clean_exit = False
                        thlib.Utility.print_alert(prev_commit, branch_name, printableDiff)
            prev_commit = curr_commit
    return(project_path, clean_exit)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()
    print args
    project_path, clean_exit = find_strings(args.git_url)
    shutil.rmtree(project_path, onerror=del_rw)
    if clean_exit is False:
        sys.exit(1)
