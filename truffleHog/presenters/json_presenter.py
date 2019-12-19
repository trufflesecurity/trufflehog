import datetime

import simplejson as json
import git

from truffleHog.git_processor import Commit, DiffBlob


def encoder(obj):
    if obj == git.NULL_TREE:
        return None
    if isinstance(obj, (Commit, DiffBlob)):
        return obj.dict()
    if isinstance(obj, datetime.datetime):
        return str(obj)
    if isinstance(obj, git.objects.commit.Commit):
        return str(obj)
    raise TypeError(repr(obj) + " is not JSON serializable D: !!")


def json_presenter(commits):
    # impure
    print(json.dumps(commits, sort_keys=True, indent=2, default=encoder))
