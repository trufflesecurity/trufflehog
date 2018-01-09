import traceback

from flask import Flask, render_template, request

from truffleHog.searchOrg import get_org_repos
from truffleHog.slackNotifications import send2slack

app = Flask(__name__)


@app.route("/")
def main():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
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
    app.run(host='0.0.0.0',port=8080)
