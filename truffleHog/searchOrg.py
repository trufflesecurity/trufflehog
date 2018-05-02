from urllib.parse import urlparse

import concurrent.futures
import argparse
import json
import shutil

import time
from pprint import pprint

from github import Github

from truffleHog import find_strings, del_rw
from slackNotifications import send2slack

from multiprocessing import Pool


# from truffleHog.recon_utils import recon

def remove_diff(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [remove_diff(v) for v in d]
    return {k: remove_diff(v) for k, v in d.items()
            if k not in {'diff', 'printDiff'}}


def main():
    """Handles argument building and calls analysis"""
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git orgs.')

    parser.add_argument("--org", type=str, dest="orgname", help="Name of organization")
    parser.add_argument("--username", type=str, dest="priv_username", help="Name of user the privtoken belongs to")

    parser.add_argument("--repo", type=str, dest="repo", help="Name of specific repository")

    parser.add_argument("--privtoken", type=str, dest="privtoken", help="Github Token to access private organization")
    parser.add_argument("--pubtoken", type=str, dest="pubtoken",
                        help="Used with --pubrepos, token of account which doesn't have access to the private org")

    parser.add_argument('--notifySlackurl', type=str, dest="slackUrl",
                        help='send the results to slack using the following webhook')

    parser.add_argument('--notifySlackChannel', type=str, dest="slackChannel",
                        help='send the results to slack to the target channel, to be used in conjuction '
                             'with --notifySlackurl')

    parser.add_argument('--pubrepos', dest="pubrepos",
                        help='enable searching for repos in the private org which also exist on public github',
                        action="store_true")
    parser.add_argument('--notifySlackCompletion',
                        help="post on slack when execution complete, if enabled it will print a message on slack instead of the full results",
                        dest="notify_slack",
                        action='store_true')
    parser.add_argument('--delay',
                        help="in case of big orgs, sleep <delay> seconds between repos",
                        dest="delay",
                        type=int)
    parser.add_argument('--outfile',
                        help="write output to outfile",
                        dest="outfile",
                        type=str)
    parser.add_argument('--outfolder',
                        help="write output to target dir, one file per repo",
                        dest="outfolder",
                        type=str)

    parser.add_argument('--notify-per-repo',
                        help="post on slack per repo scanned",
                        dest="notify_per_repo",
                        type=bool, default=False)
    parser.add_argument('-v', help="verbosity, if enabled it will print messages to console", dest="verbose",
                        action='store_true')
    parser.add_argument('-vv',
                        help="very verbose, if enabled it will print issues found in json format", dest="very_verbose",
                        action='store_true')
    parser.add_argument('-vvv',
                        help="Very very verbose, if enabled it will print git diffs and issues found",
                        dest="very_very_verbose",
                        action='store_true')
    parser.add_argument('--debug',
                        help="Debugging info enabled, you probably don't want this",
                        dest="debug",
                        action='store_true')
    parser.add_argument('--regex',
                        help="Check for the regexps found in file regexChecks.py",
                        dest="regex",
                        action='store_true')
    parser.add_argument('--entropy',
                        help="Check for high entropy strings, warning this produces a lot of false positives!",
                        dest="entropy",
                        action='store_true')
    parser.add_argument('--branch',
                        help="specific branch to check",
                        dest="branch")
    parser.add_argument('-p',
                        help="Processes",
                        dest="processes",
                        type=int)
    # parser.add_argument("--recon", dest="recon",
    #                     action='store_true', help="Perform reconnaisance, find if there's anything usefull in the repo")
    # parser.add_argument("--keywords", type=str, dest="keywords",
    #                     help="File with line delimited keywords to search e.g. s3://")

    parser.set_defaults(keywords=None)
    parser.set_defaults(repo=None)
    parser.set_defaults(branch=None)
    parser.set_defaults(delay=0)
    parser.set_defaults(orgname=None)
    parser.set_defaults(privtoken=None)
    parser.set_defaults(pubtoken=None)
    parser.set_defaults(slackUrl=None)
    parser.set_defaults(slackChannel=None)
    parser.set_defaults(entropy=False)
    parser.set_defaults(regex=False)

    args = parser.parse_args()

    verbosity = 0
    if args.verbose:
        verbosity = 1
    if args.very_verbose:
        verbosity = 2
    if args.very_very_verbose:
        verbosity = 3
    if args.debug:
        verbosity = 4

    settings = Options(orgname=args.orgname,
                       private_token=args.privtoken,
                       repo=args.repo,
                       regex=args.regex,
                       entropy=args.entropy,
                       print_str=verbosity,
                       delay=args.delay,
                       public_token=args.pubtoken,
                       notify_per_repo=args.notify_per_repo,
                       slack_url=args.slackUrl,
                       outfolder=args.outfolder,
                       slack_channel=args.slackChannel,
                       notify_slack=args.notify_slack,
                       branch=args.branch)

    analyze_org_repos(parallelism=args.processes, options=settings)


def create_file(outfolder=None, file_path=None, msg=None):
    """Creates results file
    :param outfolder type:str path (absolute or relative) where the results should be dumped
    :param file_path type:str the file relative to the outfolder
    :param msg      type: JSON the json output to dump in the file
    """
    with open(outfolder + "/" + file_path, "w+") as f:
        f.writelines(json.dumps(msg, indent=4, sort_keys=True))


def count_issues(strings):
    """Helper function to count issues found
    :param strings find_strings output dictionary, must have the keys: entropicDiffs and found_regexes
    :returns number of regex_issues found and number of entropy_issues found
    """
    entropic_issues = len(strings["entropicDiffs"])
    regex_issues = len(strings["found_regexes"])
    return regex_issues, entropic_issues


def gather_repos(options=None):
    """Builds the repo object for every repo in the org
    :param options the settings object
    :returns list of type Helper containing repo objects with repo url, clone url and options for each object
    """
    single_repo = options.repo
    org_name = options.orgname
    private = Github(login_or_token=options.private_token)
    repos = list()
    all_repos = list()
    result = list()
    if single_repo is not None:
        all_repos.append(private.get_organization(org_name).get_repo(single_repo))
    else:
        all_repos.extend(private.get_organization(org_name).get_repos(type='all'))
    print("%s has %s repos, this might take a while" % (org_name, len(all_repos)))

    for repo in all_repos:
        repos.append(repo)
        repo_url = urlparse(repo.html_url)
        clone_url = build_repo_auth_clone_url(token=options.private_token, repo_url=repo_url)

        h = Helper(url=clone_url, repo_url=repo_url, options=options)
        result.append(h)

    print("Gathered %s repos" % len(result))
    return result


def build_repo_auth_clone_url(token='', repo_url=None):
    return repo_url.scheme + "://" + token + ":x-oauth-basic@" + repo_url.netloc + repo_url.path


class Helper:
    def __init__(self, url=None, repo_url=None, options=None):
        self.url = url
        self.repo_url = repo_url
        self.options = options


class Options:
    def __init__(self, orgname=None, private_token=None, repo=None, entropy=False, regex=False, delay=0, print_str=0,
                 public_token=None, notify_per_repo=None, slack_url=None,
                 outfolder=None, slack_channel=None, notify_slack=False, branch=None):
        self.orgname = orgname
        self.private_token = private_token
        self.repo = repo
        self.do_entropy = entropy
        self.do_regex = regex
        self.delay = delay
        self.verbosity = print_str
        self.public_token = public_token
        self.notify_per_repo = notify_per_repo
        self.slack_url = slack_url
        self.outfolder = outfolder
        self.slack_channel = slack_channel
        self.notify_slack = notify_slack
        self.branch = branch


def analyze(args):
    """Calls Trufflehog's find_strings
    :param args :type Helper, contains a repo with the specific trufflehog settings for this particular repo
    :returns the repo_url scanned and the dictionary with the issues found
    """
    repo_url = args.repo_url
    url = args.url
    entropy = args.options.do_entropy
    regex = args.options.do_regex
    verbosity = args.options.verbosity
    delay = args.options.delay

    if verbosity > 0:
        print("Checking ", repo_url.path)
    if delay > 0:
        time.sleep(delay)

    strings = find_strings(url, printJson=True, do_entropy=entropy, do_regex=regex,
                           max_depth=999999999999999999999999, print_str=verbosity, specific_branch=args.options.branch)
    result = {"entropicDiffs": list(filter(lambda x: x is not None, strings["entropicDiffs"])),
              "found_regexes": list(filter(lambda x: x is not None, strings["found_regexes"])),
              "project_path": strings["project_path"]}
    return repo_url, result


def analyze_org_repos(parallelism=1, options=None):
    """main orchestrator function
    builds list of repo details and calls trufflehog for each
    :param parallelism how many threads to use
    :param options an Options object containing all the options the script was called with"""
    result = dict()
    repos = gather_repos(options=options)

    # with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as executor:
        future_to_repo = {executor.submit(analyze, repo): repo for repo in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            something = future_to_repo[future]
            repo_url, strings = future.result()
            # repo_url, strings = analyze(repo)

            # for repo_url, strings in zip(repos, executor.map(__helper, repos)):
            result.update(
                {repo_url.path: {'entropicDiffs': strings["entropicDiffs"], "found_regexes": strings["found_regexes"]}})

            project_path = strings["project_path"]
            pprint(project_path)
            shutil.rmtree(project_path, onerror=del_rw)

            regexp_issues, entropic_issues = count_issues(strings)
            if options.verbosity > 0:
                print("Found " + str(regexp_issues + entropic_issues) + " issues in: " + repo_url.path)

            if options.notify_per_repo:
                slack_message = "Finished checking %s found %s" % (
                    repo_url.path, regexp_issues + entropic_issues)
                send2slack(webhook_url=options.slack_url, channel=options.slack_channel,
                           msg=slack_message)
            if options.outfolder is not None:
                create_file(options.outfolder, repo_url.path.split("/")[-1], strings)

    if options.verbosity >= 2:
        result = remove_diff(json.loads(json.dumps(result, indent=4, sort_keys=True)))
        print(json.dumps(result, indent=4, sort_keys=True))

    if options.slack_url is not None:
        send2slack(webhook_url=options.slack_url, channel=options.slack_channel,
                   msg="Trufflehog execution complete")


if __name__ == "__main__":
    main()
