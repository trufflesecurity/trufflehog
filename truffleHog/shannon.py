import unittest
import math
from functools import partial

from toolz.functoolz import compose


class ShannonEntropy:
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    HEX_CHARS = "1234567890abcdefABCDEF"

    @staticmethod
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
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
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

    @staticmethod
    def strings_with_high_entropy(key, strings_with_entropy, treshold=4.5):
        return [
            string_with_entropy
            for string_with_entropy in strings_with_entropy
            if string_with_entropy[key] > treshold
        ]

    @staticmethod
    def find_base64_shannon_entropy(word: str, treshold=4.5):
        def build_result(string):
            return {
                "string": string,
                "b64_entropy": ShannonEntropy.shannon_entropy(
                    string, ShannonEntropy.BASE64_CHARS
                ),
            }

        return compose(
            partial(
                ShannonEntropy.strings_with_high_entropy,
                "b64_entropy",
                treshold=treshold,
            ),
            partial(map, build_result),
            partial(
                ShannonEntropy.get_strings_of_set, char_set=ShannonEntropy.BASE64_CHARS
            ),
        )(word)

    @staticmethod
    def find_hex_shannon_entropy(word: str, treshold=3.0):
        def build_result(string):
            return {
                "string": string,
                "hex_entropy": ShannonEntropy.shannon_entropy(
                    string, iterator=ShannonEntropy.HEX_CHARS
                ),
            }

        return compose(
            partial(
                ShannonEntropy.strings_with_high_entropy,
                "hex_entropy",
                treshold=treshold,
            ),
            partial(map, build_result),
            partial(
                ShannonEntropy.get_strings_of_set, char_set=ShannonEntropy.HEX_CHARS
            ),
        )(word)


class TestShannonEntropy(unittest.TestCase):
    def test_shannon(self):
        random_stringB64 = (
            "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        )
        random_stringHex = "b3A0a1FDfe86dcCE945B72"

        self.assertEquals(
            6.022367813028458,
            ShannonEntropy.shannon_entropy(
                random_stringB64, ShannonEntropy.BASE64_CHARS
            ),
        )
        self.assertEquals(
            4.459431618637295,
            ShannonEntropy.shannon_entropy(random_stringHex, ShannonEntropy.HEX_CHARS),
        )

    def test_find_base64_shannon_entropy(self):
        word = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"

        result = ShannonEntropy.find_base64_shannon_entropy(word)
        self.assertEquals(
            [
                {
                    "string": "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva",
                    "b64_entropy": 6.022367813028458,
                }
            ],
            result,
        )

    def test_find_hex_shannon_entropy(self):
        word = "b3A0a1FDfe86dcCE945B72"

        result = ShannonEntropy.find_hex_shannon_entropy(word)
        self.assertEquals(
            [{"string": "b3A0a1FDfe86dcCE945B72", "hex_entropy": 4.459431618637295}],
            result,
        )

    def test_strings_with_high_entropy(self):
        result = ShannonEntropy.strings_with_high_entropy("key", [{"key": 4.6}])
        self.assertEquals([{"key": 4.6}], result)

        result = ShannonEntropy.strings_with_high_entropy("key", [{"key": 4.5}])
        self.assertEquals([], result)

    def test_get_strings_of_set_w_hex(self):
        random_stringHex = "b3A0a1FDfe86dcCE945B72"
        result = ShannonEntropy.get_strings_of_set(
            random_stringHex, ShannonEntropy.HEX_CHARS
        )
        self.assertEquals([random_stringHex], result)

        random_stringHex = "hola"
        result = ShannonEntropy.get_strings_of_set(
            random_stringHex, ShannonEntropy.HEX_CHARS
        )
        self.assertEquals([], result)

    def test_get_strings_of_set_w_b64(self):
        random_stringB64 = (
            "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        )
        result = ShannonEntropy.get_strings_of_set(
            random_stringB64, ShannonEntropy.BASE64_CHARS
        )
        self.assertEquals([random_stringB64], result)

        random_stringB64 = "hola"
        result = ShannonEntropy.get_strings_of_set(
            random_stringB64, ShannonEntropy.BASE64_CHARS
        )
        self.assertEquals([], result)
