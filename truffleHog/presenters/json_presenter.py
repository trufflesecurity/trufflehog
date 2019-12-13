import simplejson as json

import git


def encoder(obj):
    if obj == git.NULL_TREE:
        return None
    if isinstance(obj, git.objects.commit.Commit):
        return str(obj)
    raise TypeError(repr(obj) + " is not JSON serializable")


def json_presenter(commits):
    # impure
    print(json.dumps(commits, sort_keys=True, indent=2, default=encoder))
