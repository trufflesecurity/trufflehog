import os
from functools import partial, reduce
from typing import List

from pydantic import BaseModel

from truffleHog.utils import IO, replace, get_regexes_from_file
from truffleHog.finders import HighEntropyStringsFinder, RegexpMatchFinder


THIS_FILE_PATH = os.path.dirname(__file__)


class File(BaseModel):
    path: str
    text: List[str]
    high_entropy_words: List[dict]
    regexp_matches: List[dict]


class FileProcessor:
    @staticmethod
    def process_file(file_path: str) -> IO:
        def get_file_content(file_path):
            def fn():
                with open(file_path, "r") as f:
                    return f.read()

            return IO(fn)

        def to_file_model(file_path, text):
            return File(
                path=file_path,
                text=text.split("\n"),
                high_entropy_words=[],
                regexp_matches=[],
            )

        return get_file_content(file_path).map(partial(to_file_model, file_path))


def find_high_entropy_strings(file_obj) -> File:
    return replace(
        file_obj, "high_entropy_words", HighEntropyStringsFinder.apply(file_obj)
    )


def find_matching_regexps(regexes_objects, file_obj) -> File:
    return replace(
        file_obj,
        "regexp_matches",
        RegexpMatchFinder.apply(regexes_objects, file_obj.text),
    )


def scan_file(file_path: str, use_entropy=True, use_regexps=True):
    # impure
    file_obj = FileProcessor.process_file(file_path).unsafePerformIO()
    file_obj = find_high_entropy_strings(file_obj)

    regexes_objects = get_regexes_from_file().unsafePerformIO()
    file_obj = find_matching_regexps(regexes_objects, file_obj)

    return file_obj


# run with:
#   python -m truffleHog.file_processor

if __name__ == "__main__":
    result = scan_file("truffleHog/shannon.py")
    print(result)

    result = scan_file("truffleHog/regexes.json")
    print(result)
