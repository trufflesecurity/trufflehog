"""
Credit for this code goes to https://github.com/ryanbaxendale 
via https://github.com/dxa4481/truffleHog/pull/9
"""
import pprint
import shutil
import urllib

from urllib.parse import quote_plus, urlparse

import requests
import time
from truffleHog import truffleHog, regexChecks

from github import Github

from truffleHog.truffleHog import del_rw


def get_org_repos(orgname):
    private_password = ""
    public_token = ""
    private_username = ""
    private_token = ""
    public = Github(login_or_token=public_token)
    private = Github(login_or_token=private_token)

    user = private.get_user(private_username)

    repos = list()
    for repo in private.get_organization(orgname).get_repos():
        repos.append(repo)
        repo_url = urlparse(repo.html_url)

        url = repo_url.scheme + "://" + quote_plus(private_username) + ":" + quote_plus(
            private_password) + "@" + repo_url.netloc + repo_url.path
        print("Checking "+repo_url.path)
        output = truffleHog.find_strings(url, printJson=True, do_entropy=True, do_regex=True)
        pprint.pprint(output)
        project_path = output["project_path"]
        shutil.rmtree(project_path, onerror=del_rw)
get_org_repos("")
