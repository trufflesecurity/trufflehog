import hashlib
import os
import json
import re
from collections import namedtuple
from functools import partial, reduce
from datetime import datetime
import shutil


# ref: https://toolz.readthedocs.io/en/latest/index.html
from toolz.itertoolz import concat, unique
from toolz.functoolz import compose

# ref: https://gitpython.readthedocs.io/en/stable/index.html
import git

from truffleHog.shannon import ShannonEntropy
from truffleHog.presenters import simple_presenter, json_presenter


THIS_FILE_PATH = os.path.dirname(__file__)


class IO:
    def __init__(self, io):
        self.unsafePerformIO = io

    def map(self, fn):
        return IO(compose(fn, self.unsafePerformIO))


class RepoProcessor:
    Commit = namedtuple(
        "Commit", "blob_diffs branch commit commit_time diff_hash next_commit"
    )

    DiffBlob = namedtuple(
        "DiffBlob", "file_a file_b text high_entropy_words regexp_matches"
    )

    # process_repo :: repoURL -> [RepoProcessor.Commit]
    @staticmethod
    def process_repo(repo_url: str, max_depth=10):
        def get_repo_from_url(repo_url):
            def fn():
                repo_path = "/tmp/repo-in-analisys"
                shutil.rmtree(repo_path, ignore_errors=True)
                return git.Repo.clone_from(repo_url, repo_path)

            return IO(fn)

        def get_remote_branches(repo):
            return repo.remotes.origin.fetch()

        def expand_branch_commit(repo, branch, max_count=10):
            return {
                "branch": branch.name,
                "commits": list(repo.iter_commits(branch.name, max_count=max_count)),
            }

        def add_shifted_commits(branch):
            return {**branch, "shifted_commits": get_shifted_commits(branch["commits"])}

        def get_shifted_commits(commits):
            return [git.NULL_TREE] + commits[:-1]

        def transform_to_flat_commits(branch):
            return [
                {
                    "branch": branch["branch"],
                    "commit": commit,
                    "next_commit": branch["shifted_commits"][i],
                    "diff_hash": get_diff_hash(commit, branch["shifted_commits"][i]),
                    "commit_time": datetime.fromtimestamp(
                        commit.committed_date
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
                for i, commit in enumerate(branch["commits"])
            ]

        def get_diff_hash(a, b):
            return hashlib.md5((str(a) + str(b)).encode("utf-8")).hexdigest()

        def add_blobs_diffs(commit):
            return {
                **commit,
                "blob_diffs": compose(
                    list,
                    partial(map, to_diff_blob_struct),
                    partial(map, expand_blob_lines),
                    partial(filter, not_binary_blob),
                    get_diff_blobs,
                )(commit),
            }

        def expand_blob_lines(blob):
            return {**blob, "text": blob["text"].split("\n")}

        def not_binary_blob(blobs_diff):
            return not blobs_diff["text"].startswith("Binary files")

        def get_diff_blobs(commit):
            return [
                {
                    "file_a": blob.a_path,
                    "file_b": blob.b_path,
                    "text": blob.diff.decode("utf-8", errors="replace"),
                }
                for blob in commit["commit"].diff(
                    commit["next_commit"], create_patch=True
                )
            ]

        def to_commit_struct(commit_dict):
            return RepoProcessor.Commit(**commit_dict)

        def to_diff_blob_struct(blob_dict):
            return RepoProcessor.DiffBlob(
                **blob_dict, high_entropy_words=[], regexp_matches=[]
            )

        # -- main --

        def fn(repo, max_depth=max_depth):
            return compose(
                list,
                partial(unique, key=lambda x: x.diff_hash),
                partial(map, compose(to_commit_struct, add_blobs_diffs)),
                concat,
                partial(
                    map,
                    compose(
                        transform_to_flat_commits,
                        add_shifted_commits,
                        partial(expand_branch_commit, repo, max_count=max_depth),
                    ),
                ),
                get_remote_branches,
            )

        return get_repo_from_url(repo_url).map(lambda repo: fn(repo, max_depth)(repo))


def update_blob_field(commits, field, update_fn):
    def get_new_blob_diffs(update_fn, commit):
        return [blob._replace(**{field: update_fn(blob)}) for blob in commit.blob_diffs]

    def update_commit_blobs(update_fn, commit):
        return commit._replace(blob_diffs=get_new_blob_diffs(update_fn, commit))

    return [update_commit_blobs(update_fn, commit) for commit in commits]


def find_high_entropy_strings(commits):
    def get_words_entropy(blob):
        return [
            {
                "b64_entropy": ShannonEntropy.find_base64_shannon_entropy(word),
                "hex_entropy": ShannonEntropy.find_hex_shannon_entropy(word),
                "word": word,
            }
            for word in get_blob_words(blob)
        ]

    def get_blob_words(blob):
        return reduce(lambda x, y: x + y.split(), blob.text, [])

    def filter_words_with_entropy(words_results):
        return [x for x in words_results if x["b64_entropy"] or x["hex_entropy"]]

    update_fn = compose(filter_words_with_entropy, get_words_entropy)

    return update_blob_field(commits, "high_entropy_words", update_fn)


def get_regexes_from_file():
    def to_regexes_objects(raw_regexs_dict):
        return [{"name": x, "regex": y} for x, y in raw_regexs_dict.items()]

    def fn():
        with open(os.path.join(THIS_FILE_PATH, "regexes.json"), "r") as f:
            return to_regexes_objects(json.loads(f.read()))

    return IO(fn)


def find_matching_regexps(regexes_objects, commits):
    def get_matching_regexes(text):
        return [
            {
                "found_strings": re.findall(regex["regex"], str(text)),
                "regex": regex["name"],
            }
            for regex in regexes_objects
        ]

    def filter_words_with_regexp_matches(regexp_results):
        return [x for x in regexp_results if x["found_strings"]]

    update_fn = compose(filter_words_with_regexp_matches, get_matching_regexes)

    return update_blob_field(commits, "regexp_matches", update_fn)


def scan_repo(repo_url, use_entropy=True, use_regexps=True):
    # impure
    commits = RepoProcessor.process_repo(repo_url).unsafePerformIO()
    if use_entropy:
        commits = find_high_entropy_strings(commits)
    if use_regexps:
        regexes_objects = get_regexes_from_file().unsafePerformIO()
        commits = find_matching_regexps(regexes_objects, commits)

    return commits


# run with:
#   python -m truffleHog.git_processor

if __name__ == "__main__":
    result = scan_repo("https://github.com/sortigoza/truffleHog.git")
    print(result)
