#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import subprocess
import json
import stat
from git import Repo
from urlparse import urlparse

# Global Vars
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument('git_repo', type=str, help='Git Repository: Remote URL or local filesystem for secret searching')
    args = parser.parse_args()
    output = find_strings(args.git_repo, args.output_json)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)

def is_abs_url(url=None):
    """Checks if string is absolute URL or not and returns boolean denoting True or False if valid URL.  

    :param url: A string, absolute URL.
    """
    if url is None or url.strip() == '':
        return False
    if url.strip().lower()[:4] == 'http' is False:
        return False
    try:
        result = urlparse(url)
        return True if [result.scheme, result.netloc, result.path] else False
    except:
        return False

def is_git_dir(filepath=None):
    """Checks if filepath is directory and if directory itself is a git repository.
    Returns boolean denoting True or False if valid directory and git repository.  

    :param filepath: A string, filepath of the directory.
    """
    if filepath is None or filepath.strip() == '':
        return False

    if filepath[-4:] != '.git':
        filepath += '/.git'

    # verify actual git directory
    if os.path.isdir(filepath) and os.path.exists(filepath):
        try:
            rc = subprocess.call(['git', 'rev-parse'], cwd=filepath)
            return (rc == 0)
        except OSError as e:
            sys.stderr.write("Unable to invoke cmd 'git rev-parse' due to following: " + e.message)
            return False  
    else:
        return False

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def find_strings(git_repo, printJson=False):
    if is_abs_url(git_repo):
        project_path = tempfile.mkdtemp()
        Repo.clone_from(git_repo, project_path)
    elif is_git_dir(git_repo):
        project_path = git_repo
    else:
        sys.exit("Unable to scan for secrets due to invalid Git repository " + git_repo)

    output = {"entropicDiffs": []}
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
                #avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:
                    #print i.a_blob.data_stream.read()
                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    stringsFound = []
                    lines = blob.diff.decode('utf-8', errors='replace').split("\n")
                    for line in lines:
                        for word in line.split():
                            base64_strings = get_strings_of_set(word, BASE64_CHARS)
                            hex_strings = get_strings_of_set(word, HEX_CHARS)
                            for string in base64_strings:
                                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                                if b64Entropy > 4.5:
                                    stringsFound.append(string)
                                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                            for string in hex_strings:
                                hexEntropy = shannon_entropy(string, HEX_CHARS)
                                if hexEntropy > 3:
                                    stringsFound.append(string)
                                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                    if len(stringsFound) > 0:
                        commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                        entropicDiff = {}
                        entropicDiff['date'] = commit_time
                        entropicDiff['branch'] = branch_name
                        entropicDiff['commit'] = prev_commit.message
                        entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace') 
                        entropicDiff['stringsFound'] = stringsFound
                        output["entropicDiffs"].append(entropicDiff)
                        if printJson:
                            print(json.dumps(output, sort_keys=True, indent=4))
                        else:
                            print(bcolors.OKGREEN + "Date: " + commit_time + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Branch: " + branch_name + bcolors.ENDC)
                            print(bcolors.OKGREEN + "Commit: " + prev_commit.message + bcolors.ENDC)
                            print(printableDiff)

            prev_commit = curr_commit
    output["project_path"] = project_path
    return output

if __name__ == "__main__":
    main()
