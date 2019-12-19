import argparse
from truffleHog.git_processor import scan_repo

from truffleHog.presenters import simple_presenter, json_presenter


def get_args():
    parser = argparse.ArgumentParser(
        description="Find secrets hidden in the depths of git."
    )
    parser.add_argument(
        "--regex",
        dest="do_regex",
        action="store_true",
        help="Enable high signal regex checks",
        default=False,
    )
    parser.add_argument(
        "--entropy", dest="do_entropy", help="Enable entropy checks", default=True
    )
    parser.add_argument(
        "--since_commit",
        dest="since_commit",
        help="Only scan from a given commit hash",
        default=None,
    )
    parser.add_argument(
        "--max_depth",
        dest="max_depth",
        help="The max commit depth to go back when searching for secrets",
        default=1000000,
    )
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output in JSON"
    )
    parser.add_argument(
        "--rules",
        dest="rules",
        help="Ignore default regexes and source from json list file",
        default={},
    )
    parser.add_argument(
        "-i",
        "--include_paths",
        type=argparse.FileType("r"),
        metavar="INCLUDE_PATHS_FILE",
        help="File with regular expressions (one per line), at least one of which must match a Git "
        'object path in order for it to be scanned; lines starting with "#" are treated as '
        "comments and are ignored. If empty or not provided (default), all Git object paths "
        "are included unless otherwise excluded via the --exclude_paths option.",
    )
    parser.add_argument(
        "-x",
        "--exclude_paths",
        type=argparse.FileType("r"),
        metavar="EXCLUDE_PATHS_FILE",
        help="File with regular expressions (one per line), none of which may match a Git object "
        'path in order for it to be scanned; lines starting with "#" are treated as comments '
        "and are ignored. If empty or not provided (default), no Git object paths are "
        "excluded unless  effectively excluded via the --include_paths option.",
    )
    parser.add_argument(
        "files_or_git_url",
        nargs="+",
        type=str,
        help="URL or list of files for secret searching",
    )

    return parser.parse_args()


def is_remote_repo(item):
    return True


def is_local_file(item):
    return False


def proces_local_file(args, file_path):
    pass


def proces_remote_repo(args, repo_url):
    commits = scan_repo(repo_url)

    if args.output_json:
        json_presenter(commits)
    else:
        simple_presenter(commits)


def main():
    args = get_args()
    for item in args.files_or_git_url:
        print(f"processing: {item}")
        if is_remote_repo(item):
            proces_remote_repo(args, item)
        if is_local_file(item):
            proces_local_file(args, item)


if __name__ == "__main__":
    main()
