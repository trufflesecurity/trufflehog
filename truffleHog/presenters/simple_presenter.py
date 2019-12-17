from termcolor import colored


def simple_presenter(commits):
    # impure
    for commit in commits:
        print(
            colored(
                f"branch={commit.branch} commit={commit.commit} commit_time={commit.commit_time} diff_hash={commit.diff_hash}",
                "yellow",
            )
        )
        for blob in filter(
            lambda x: x.high_entropy_words or x.regexp_matches, commit.blob_diffs
        ):

            file_name = blob.file_a
            if not file_name:
                file_name = blob.file_b

            print(colored(f"file={file_name}", "red"))
            print("high_entropy_words:")
            for word in blob.high_entropy_words:
                print(f"{word['word']}")
            if not blob.high_entropy_words:
                print(None)

            print("regexp_matches:")
            for match in blob.regexp_matches:
                print(match)
            if not blob.regexp_matches:
                print(None)
