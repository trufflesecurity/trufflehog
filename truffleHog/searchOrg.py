import argparse
import pprint
import shutil
from urllib.parse import quote_plus, urlparse
from github import Github

import truffleHog


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git orgs.')
    parser.add_argument('--privuser', dest="privusername", action="store_true",
                        help="Github username to access private org")
    parser.add_argument("--privpass", dest="privpass", action="store_true",
                        help="Github password to access private org")
    parser.add_argument("--org", dest="orgname", help="Name of organization")
    parser.add_argument("--privtoken", dest="privtoken", help="Github Token to access private organization")
    parser.add_argument("--pubtoken", dest="pubtoken",
                        help="Used with --pubrepos, token of account which doesn't have access to the private org")

    parser.add_argument('--pubrepos', type=bool, dest="pubrepos",
                        help='enable searching for repos in the private org which also exist on public github')
    parser.add_argument('--notifySlackurl', type=str, dest="slackUrl",
                        help='send the results to slack using the following webhook')
    parser.add_argument('--notifySlackChannel', type=str, dest="slackChannel",
                        help='send the results to slack to the target channel, to be used in conjuction '
                             'with --notifySlackurl')

    parser.set_defaults(privusername='')
    parser.set_defaults(privpass='')
    parser.set_defaults(orgname='')
    parser.set_defaults(privtoken='')
    parser.set_defaults(pubtoken='')
    parser.set_defaults(pubrepos=False)
    parser.set_defaults(slackUrl='')
    parser.set_defaults(slackChannel='')

    args = parser.parse_args()
    output = get_org_repos(orgname=args.orgname, public_token=args.pubtoken, private_username=args.privusername,
                           private_password=args.privpass, private_token=args.privtoken)
    if args.slackUrl is not "":
        send2slack(webhook_url=args.slackUrl, channel=args.slackChannel, msg=output)
    pprint.pprint(output)


def get_org_repos(orgname='', private_password=None, public_token=None, private_username=None, private_token=None):


    public = Github(login_or_token=public_token)
    private = Github(login_or_token=private_token)

    user = private.get_user(private_username)

    repos = list()
    for repo in private.get_organization(orgname).get_repos():
        repos.append(repo)
        repo_url = urlparse(repo.html_url)

        url = repo_url.scheme + "://" + quote_plus(private_username) + ":" + quote_plus(
            private_password) + "@" + repo_url.netloc + repo_url.path
        print("Checking " + repo_url.path)
        output = truffleHog.find_strings(url, printJson=True, do_entropy=True, do_regex=True)
        project_path = output["project_path"]
        shutil.rmtree(project_path, onerror=del_rw)
        return output


if __name__ == "__main__":
    main()
