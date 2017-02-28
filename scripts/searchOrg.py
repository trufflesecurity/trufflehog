"""
Credit for this code goes to https://github.com/ryanbaxendale 
via https://github.com/dxa4481/truffleHog/pull/9
"""
import requests
import truffleHog

def get_org_repos(orgname):
    response = requests.get(url='https://api.github.com/users/' + orgname + '/repos')
    json = response.json()
    for item in json:
        if item['private'] == False:
            print('searching ' + item["html_url"])
            truffleHog.find_strings(item["html_url"])

get_org_repos("Netflix")
