import os
import pprint

import sys
import traceback

from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def main():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    # Since / isn't a python package, can't import from /scripts, but /scripts doesn't belong in /web so
    # adding /scripts in the python path so we can import it
    # TODO: fix this ugly hack
    scripts_path = os.path.abspath(os.path.dirname(__file__) + '..')
    sys.path.append(scripts_path)
    pprint.pprint(scripts_path)
    from scripts.searchOrg import get_org_repos
    from scripts.slackNotifications import send2slack

    _ptoken = request.form['public_token']
    _username = request.form['username']
    _token = request.form['token']
    _password = request.form['password']
    _organization = request.form['orgname']
    _slackUrl = request.form['slackUrl']
    _slackChannel = request.form['slackChannel']

    try:
        result = get_org_repos(orgname=_organization, private_password=_password, public_token=_ptoken,
                               private_username=_username,
                               private_token=_token)
        # pprint.pprint(result)
        if _slackUrl is not "":
            send2slack(webhook_url=_slackUrl, channel=_slackChannel, msg=result)

        return render_template("results.html", results=result)
    except Exception as e:
        return render_template("error.html", error=traceback.format_exc())


if __name__ == "__main__":
    app.run(port=8080)
