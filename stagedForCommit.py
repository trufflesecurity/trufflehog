#!/usr/bin/env python

from truffleHog import truffleHog
from git import Repo


def main():
    repo = Repo('./')

    previous_commit = repo.head.commit
    diff = previous_commit.diff(create_patch=True)
    current_branch = repo.active_branch.name
    output = {'entropicDiffs': []}

    truffleHog.printEntropyForDiff(diff, current_branch, previous_commit, output, False)

    found_entropy = len(output['entropicDiffs']) > 0
    if found_entropy:
        print(truffleHog.bcolors.FAIL + 'There was at least one word in the index that contains too much entropy. '
                                        'Are there secrets that shouldn\'t be committed?' + truffleHog.bcolors.ENDC)

    return found_entropy

if __name__ == '__main__':
    failed = main()
    exit(1 if failed else 0)
