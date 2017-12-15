#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import json
import stat
from regexChecks import regexes
from git import Repo

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.set_defaults(regex=False)
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    args = parser.parse_args()
    do_entropy = str2bool(args.do_entropy)
    output = find_strings(args.git_url, args.since_commit, args.max_depth, args.output_json, args.do_regex, do_entropy)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)

def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

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
        print(json.dumps(issue, sort_keys=True, indent=4))
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


def merge_ranges(ranges):
    """
    Return a generator over the non-overlapping/non-adjacent ranges, in order.

    >>> ranges = [(-10, -4), (0, 0), (1, 5), (1, 5), (-5, 0), (1, 6), (-10, -5), (9, 10), (2, 6), (6, 8)]
    >>> sorted(ranges)
    [(-10, -5), (-10, -4), (-5, 0), (0, 0), (1, 5), (1, 5), (1, 6), (2, 6), (6, 8), (9, 10)]
    >>> list(merge_ranges(ranges))
    [(-10, 0), (1, 8), (9, 10)]
    >>> list(merge_ranges([]))
    []

    :param ranges: iterable of range pairs in the form (start, stop)
    :return: generator yielding the non-overlapping and non-adjecent range pairs, in order
    """
    ranges = sorted(ranges)
    if not ranges:
        return
    current_start, current_stop = ranges[0]
    for start, stop in ranges[1:]:
        if start > current_stop:
            yield current_start, current_stop
            current_start, current_stop = start, stop
        else:
            current_stop = max(current_stop, stop)
    yield current_start, current_stop


def highlight_diff(printableDiff, ranges):
    ranges = list(merge_ranges(r for r in ranges if r[0] != r[1]))
    prev_end = 0
    highlighted_diff = ''
    for start, end in ranges:
        highlighted_diff += '{unmatched_text}{hl_start}{hl_text}{hl_end}'.format(
            unmatched_text=printableDiff[prev_end:start],
            hl_start=bcolors.WARNING,
            hl_text=printableDiff[start:end],
            hl_end=bcolors.ENDC)
        prev_end = end
    highlighted_diff += printableDiff[prev_end:]
    return highlighted_diff


def get_ranges(string, match):
    match_len = len(match)
    start = string.find(match)
    while start != -1:
        end = start + match_len
        yield start, end
        start = string.find(match, end)


def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
    stringsFound = []
    lines = printableDiff.split("\n")
    index = 0
    finding_ranges = []
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    finding_ranges.extend((s + index, e + index) for s, e in get_ranges(line, string))
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    finding_ranges.extend((s + index, e + index) for s, e in get_ranges(line, string))
        index += len(line) + 1  # account for newline character removed by `split('\n')`
    found_diff = highlight_diff(printableDiff, finding_ranges)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['date'] = commit_time
        entropicDiff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropicDiff['branch'] = branch_name
        entropicDiff['commit'] = prev_commit.message
        entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = found_diff
        entropicDiff['commitHash'] = commitHash
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff


def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
    regex_matches = []
    for key in regexes:
        findings = list(m for m in regexes[key].finditer(printableDiff) if len(m.group()))
        found_strings = ', '.join(m.group() for m in findings)
        found_diff = highlight_diff(printableDiff, ((m.start(), m.end()) for m in findings))
        if found_strings:
            foundRegex = {}
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commitHash'] = commitHash
            regex_matches.append(foundRegex)
    return regex_matches


def find_strings(git_url, since_commit=None, max_depth=None, printJson=False, do_regex=False, do_entropy=True):
    output = {"entropicDiffs": []}
    project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()

    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits(max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
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
                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                    foundIssues = []
                    if do_entropy:
                        entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash)
                        if entropicDiff:
                            foundIssues.append(entropicDiff)
                    if do_regex:
                        found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash)
                        foundIssues += found_regexes
                    for foundIssue in foundIssues:
                        print_results(printJson, foundIssue)

            prev_commit = curr_commit
    output["project_path"] = project_path
    return output

if __name__ == "__main__":
    main()
