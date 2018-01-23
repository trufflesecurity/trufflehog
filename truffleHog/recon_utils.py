from truffleHog import find_strings
from truffleHog.regexChecks import regexes


def recon(keywords="", repo=""):
    with open(keywords, 'r') as file:
        for line in file.readlines():
            regexes[line] = line

    output = find_strings(repo, print_json=True, do_entropy=False, do_regex=True, max_depth=999999999999999999999999)
    return output
