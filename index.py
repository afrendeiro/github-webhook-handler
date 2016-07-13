#!/usr/bin/env python

import io
import os
import re
import sys
import json
import subprocess
import hmac
from hashlib import sha1
from flask import Flask, request, abort


app = Flask(__name__)
app.debug = os.environ.get('DEBUG') == 'true'

# The repos.json file should be readable by the user running the Flask app,
# and the absolute path should be given by this environment variable.
REPOS_JSON_PATH = os.environ['REPOS_JSON_PATH']


@app.route("/payload", methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return 'OK'
    elif request.method == 'POST':

        if request.headers.get('X-GitHub-Event') == "ping":
            return json.dumps({'msg': 'Hi!'})
        if request.headers.get('X-GitHub-Event') != "push":
            print("Not a push request")
            return json.dumps({'msg': "wrong event type"})

        print("Loading request")
        repos = json.loads(io.open(REPOS_JSON_PATH, 'r').read())

        payload = json.loads(request.data)
        repo_meta = {
            'name': payload['repository']['name'],
            'owner': payload['repository']['owner']['name'],
        }

        print("Matching branches")
        # Try to match on branch as configured in repos.json
        match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
        if match:
            repo_meta['branch'] = match.groupdict()['branch']
            repo = repos.get(
                '{owner}/{name}/branch:{branch}'.format(**repo_meta), None)

            # Fallback to plain owner/name lookup
            if not repo:
                repo = repos.get('{owner}/{name}'.format(**repo_meta), None)

        print("Checking keys")
        if repo and repo.get('path', None):
            # Check if POST request signature is valid
            key = repo.get('key', None)
            if key:
                signature = request.headers.get('X-Hub-Signature').split('=')[1]
                if type(key) == unicode:
                    key = key.encode()
                mac = hmac.new(key, msg=request.data, digestmod=sha1)
                if not compare_digest(mac.hexdigest(), signature):
                    print("Failed keys")
                    abort(403)

        print("passed all checks")
        if repo.get('action', None):
            for action in repo['action']:
                print("Doing action %s" % " ".join(action))

                subp = subprocess.Popen(action, cwd=repo.get('path', '.'))
                subp.wait()

                # Assess if all pass
                # else:
                # Send user an email
                # email = ["commits"]["author"]["email"]
                # display_name = ["commits"]["author"]["name"]
                # commit = ["head_commit"]["id"]

        return 'OK'

# Check if python version is less than 2.7.7
if sys.version_info < (2, 7, 7):
    # http://blog.turret.io/hmac-in-go-python-ruby-php-and-nodejs/
    def compare_digest(a, b):
        """
        ** From Django source **

        Run a constant time comparison against two strings

        Returns true if a and b are equal.

        a and b must both be the same length, or False is
        returned immediately
        """
        if len(a) != len(b):
            return False

        result = 0
        for ch_a, ch_b in zip(a, b):
            result |= ord(ch_a) ^ ord(ch_b)
        return result == 0
else:
    compare_digest = hmac.compare_digest

if __name__ == "__main__":
    try:
        port_number = int(sys.argv[1])
    except:
        port_number = 80

    app.run(host='0.0.0.0', port=port_number)
