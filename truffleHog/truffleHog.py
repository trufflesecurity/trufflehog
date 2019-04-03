#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import math
import datetime
import argparse
import uuid
import hashlib
import tempfile
import os
import re
import json
import stat
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--show-regex", action="store_true", help="prints out regexes that will computed against repo")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--rules", dest="rules", default=str(), help="Ignore default regexes and source from json list file")
    parser.add_argument("--add-rules", default=str(), help="Adds more regex rules along with default ones from a json list file")
    parser.add_argument("--entropy", dest="do_entropy", action='store_true', help="Enable entropy checks")
    parser.add_argument("--entropy-wc", type=int, default=20, help="Segments n-length words to check entropy against [default: 20]")
    parser.add_argument("--entropy-b64-thresh", type=float, default=4.5, help="User defined entropy threshold for base64 strings [default: 4.5]")
    parser.add_argument("--entropy-hex-thresh", type=float, default=3, help="User defined entropy threshold for hex strings [default: 3.0]")
    parser.add_argument("--since-commit", dest="since_commit", default=None, help="Only scan from a given commit hash")
    parser.add_argument("--max-depth", dest="max_depth", default=1000000, help="The max commit depth to go back when searching for secrets")
    parser.add_argument("--branch", dest="branch", default=str(), help="Name of the branch to be scanned")
    parser.add_argument("--repo-path", type=str, dest="repo_path", default=str(), help="Path to the cloned repo. If provided, git_url will not be used")
    parser.add_argument("--cleanup", dest="cleanup", action="store_true", help="Clean up all temporary result files")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    args = parser.parse_args()

    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]

    if args.add_rules:
        try:
            with open(args.add_rules, 'r') as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    regexes[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")

    if args.show_regex:
        print(json.dumps({
            key: value.pattern for key, value in regexes.items()
            }, indent=2))
        exit(0)

    entropy_options = {
        'do_entropy': args.do_entropy, 'entropy_wc': args.entropy_wc,
        'entropy_b64_thresh': args.entropy_b64_thresh,
        'entropy_hex_thresh': args.entropy_hex_thresh
    }
    output = find_strings(args.git_url, args.since_commit, args.max_depth, args.output_json, args.do_regex, entropy_options, surpress_output=False, branch=args.branch, repo_path=args.repo_path)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)

    if args.cleanup:
        clean_up(output)
    if output["foundIssues"]:
        sys.exit(1)
    else:
        sys.exit(0)


def del_rw(action, name, exc):

    if os.path.exists(name):
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
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = str()
    strings = list()
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = str()
            count = 0
    if count > threshold:
        strings.append(letters)

    return strings


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def print_results(printJson, issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    commitHash = issue['commitHash']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")


def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, entropy_options):
    stringsFound = list()
    lines = printableDiff.split("\n")
    entropy_wc = entropy_options.get('entropy_wc')
    entropy_b64_thresh = entropy_options.get('entropy_b64_thresh')
    entropy_hex_thresh = entropy_options.get('entropy_hex_thresh')
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS, entropy_wc)
            hex_strings = get_strings_of_set(word, HEX_CHARS, entropy_wc)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > entropy_b64_thresh:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > entropy_hex_thresh:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)

    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = dict()
        entropicDiff['date'] = commit_time
        entropicDiff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropicDiff['branch'] = branch_name
        entropicDiff['commit'] = prev_commit.message
        entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = printableDiff
        entropicDiff['commitHash'] = prev_commit.hexsha
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff


def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, custom_regexes={}):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = list()
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, bcolors.WARNING + found_string + bcolors.ENDC)

        if found_strings:
            foundRegex = dict()
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commitHash'] = prev_commit.hexsha
            regex_matches.append(foundRegex)
    return regex_matches


def diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes, entropy_options, do_regex, printJson, surpress_output):
    issues = list()
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files"):
            continue
        commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        foundIssues = list()
        if entropy_options.get('do_entropy'):
            entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, entropy_options)
            if entropicDiff:
                foundIssues.append(entropicDiff)
        if do_regex:
            found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, custom_regexes)
            foundIssues += found_regexes
        if not surpress_output:
            for foundIssue in foundIssues:
                print_results(printJson, foundIssue)
        issues += foundIssues
    return issues


def handle_results(output, output_dir, foundIssues):
    for foundIssue in foundIssues:
        result_path = os.path.join(output_dir, str(uuid.uuid4()))
        with open(result_path, "w+") as result_file:
            result_file.write(json.dumps(foundIssue))
        output["foundIssues"].append(result_path)
    return output


def find_strings(git_url, since_commit=None, max_depth=1000000, printJson=False, do_regex=False, entropy_options={}, surpress_output=True, custom_regexes={}, branch=None, repo_path=None):
    output = {"foundIssues": list()}
    if repo_path:
        project_path = repo_path
    else:
        project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    if branch:
        branches = repo.remotes.origin.fetch(branch)
    else:
        branches = repo.remotes.origin.fetch()

    for remote_branch in branches:
        since_commit_reached = False
        branch_name = remote_branch.name
        prev_commit = None
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
            if not prev_commit:
                prev_commit = curr_commit
                continue
            elif diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            # avoid searching the same diffs
            already_searched.add(diff_hash)
            foundIssues = diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes, entropy_options, do_regex, printJson, surpress_output)
            output = handle_results(output, output_dir, foundIssues)
            prev_commit = curr_commit
        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        foundIssues = diff_worker(diff, curr_commit, prev_commit, branch_name, commitHash, custom_regexes, entropy_options, do_regex, printJson, surpress_output)
        output = handle_results(output, output_dir, foundIssues)

    output["project_path"] = project_path
    output["clone_uri"] = git_url
    output["issues_path"] = output_dir

    if not repo_path:
        shutil.rmtree(project_path, onerror=del_rw)
    return output


def clean_up(output):
    issues_path = output.get("issues_path", None)
    if issues_path and os.path.isdir(issues_path):
        shutil.rmtree(output["issues_path"])


if __name__ == "__main__":
    main()
