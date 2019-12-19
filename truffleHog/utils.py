import os
import json

from toolz.functoolz import compose

THIS_FILE_PATH = os.path.dirname(__file__)


class IO:
    def __init__(self, io):
        self.unsafePerformIO = io

    def map(self, fn):
        return IO(compose(fn, self.unsafePerformIO))


def replace(thing, attribute, value):
    """a simple replace method that will set an attribute and return the object"""
    setattr(thing, attribute, value)
    return thing


def get_regexes_from_file():
    def to_regexes_objects(raw_regexs_dict):
        return [{"name": x, "regex": y} for x, y in raw_regexs_dict.items()]

    def fn():
        with open(os.path.join(THIS_FILE_PATH, "regexes.json"), "r") as f:
            return to_regexes_objects(json.loads(f.read()))

    return IO(fn)
