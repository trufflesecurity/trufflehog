"""
Credit for this code goes to https://github.com/ryanbaxendale 
via https://github.com/dxa4481/truffleHog/pull/9
"""
import requests
from truffleHog import truffleHog

def get_org_repos(orgname, page):
    response = requests.get(url='https://api.github.com/users/' + orgname + '/repos?page={}'.format(page))
    json = response.json()
    if not json:
        return None
    for item in json:
        if item['private'] == False:
            print('searching ' + item["html_url"])
            truffleHog.find_strings(item["html_url"], do_regex=True, do_entropy=False, max_depth=100000)
    get_org_repos(orgname, page + 1)
get_org_repos("twitter", 1)
