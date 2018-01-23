import pprint
import threading
import traceback
from logging.handlers import RotatingFileHandler

import logging
from time import strftime

from flask import Flask, render_template, request

from truffleHog.searchOrg import get_org_repos
from truffleHog.slackNotifications import send2slack

app = Flask(__name__)


@app.route("/")
def main():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    pprint.pprint(request.form)
    _ptoken = request.form['public_token']
    _username = request.form['username']
    _token = request.form['token']
    _password = request.form['password']
    _organization = request.form['orgname']
    _slackUrl = request.form['webhook']
    _slackChannel = request.form['channel']

    try:
        truffle_thread = threading.Thread(target=get_org_repos, args=[_organization,_password,_ptoken,_username,_token])
        truffle_thread.start()
        # result = get_org_repos(orgname=_organization, private_password=_password, public_token=_ptoken,
        #                        private_username=_username,
        #                        private_token=_token)
        # pprint.pprint(result)
        if _slackUrl is not "":
            send2slack(webhook_url=_slackUrl, channel=_slackChannel, msg=truffle_thread.isAlive())

        return render_template("results.html", results=truffle_thread.isAlive())
    except Exception as e:
        return render_template("error.html", error=traceback.format_exc())


#
# @app.errorhandler(Exception)
# def exceptions(e):
#     ts = strftime('[%Y-%b-%d %H:%M]')
#     tb = traceback.format_exc()
#     logger.error('%s %s %s %s %s 5xx INTERNAL SERVER ERROR\n%s',
#                  ts,
#                  request.remote_addr,
#                  request.method,
#                  request.scheme,
#                  request.full_path,
#                  tb)
#     return "Internal Server Error", 500


if __name__ == '__main__':
    # handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
    # logger = logging.getLogger('__name__')
    # logger.setLevel(logging.INFO)
    # logger.addHandler(handler)
    app.run(host='0.0.0.0', port=8080)
