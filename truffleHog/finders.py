import re
from functools import partial, reduce

from toolz.functoolz import compose

from truffleHog.shannon import ShannonEntropy


class HighEntropyStringsFinder:
    @staticmethod
    def get_words_entropy(blob):
        return [
            {
                "b64_entropy": ShannonEntropy.find_base64_shannon_entropy(word),
                "hex_entropy": ShannonEntropy.find_hex_shannon_entropy(word),
                "word": word,
            }
            for word in HighEntropyStringsFinder.get_blob_words(blob)
        ]

    @staticmethod
    def get_blob_words(blob):
        return reduce(lambda x, y: x + y.split(), blob.text, [])

    @staticmethod
    def filter_words_with_entropy(words_results):
        return [x for x in words_results if x["b64_entropy"] or x["hex_entropy"]]

    @staticmethod
    def apply(blob):
        """given a blob (a thing with a `blob.text : List(str)` field) find the high entropy words"""
        return compose(
            HighEntropyStringsFinder.filter_words_with_entropy,
            HighEntropyStringsFinder.get_words_entropy,
        )(blob)


class RegexpMatchFinder:
    @staticmethod
    def get_matching_regexes(regexes_objects, text):
        return [
            {
                "found_strings": re.findall(regex["regex"], str(text)),
                "regex": regex["name"],
            }
            for regex in regexes_objects
        ]

    @staticmethod
    def filter_words_with_regexp_matches(regexp_results):
        return [x for x in regexp_results if x["found_strings"]]

    @staticmethod
    def apply(regexes_objects, text):
        return compose(
            RegexpMatchFinder.filter_words_with_regexp_matches,
            partial(RegexpMatchFinder.get_matching_regexes, regexes_objects),
        )(text)
