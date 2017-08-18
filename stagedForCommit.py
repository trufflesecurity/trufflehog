#!/usr/bin/env python

from truffleHog import truffleHog
from git import Repo


def main():
    repo = Repo('./')

    previous_commit = repo.head.commit
    diff = previous_commit.diff(create_patch=True)
    current_branch = repo.active_branch.name
    output = {"entropicDiffs": []}

    truffleHog.printEntropyForDiff(diff, current_branch, previous_commit, output, False)

if __name__ == "__main__":
    main()
