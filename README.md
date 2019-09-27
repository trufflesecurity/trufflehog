# TruffleHog
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

# How it works
Trufflehog looks for secrets in commits using regex. The regex rule can be found in testRules.json
You may exclude files from trufflehog scan by adding a file at `trufflehog/exclude-patterns.txt` in your repository. Files listed in this file will be excluded from the scan.
We strongly recommend to not list directories in the `exclude-patterns.txt` to avoid the situation where someone accidentally commits secrets to an excluded directory.


# How to integrate trufflehog into your pipeline:

add this section of code to your pipeline.yml file (or the equivalent yml file)
```
- command: "sh /app/secret_scan.sh"
    label: ":face_with_monocle: scan for secrets"
    plugins:
      - ecr#v2.0.0:
          login: true
      - docker#v3.3.0:
          image: "841746791860.dkr.ecr.us-east-1.amazonaws.com/trufflehog:latest"
          mount-ssh-agent: true
          propagate-environment: true
    agents:
    - "queue=na" 
```

# Trufflehog found secrets so my build failed. What should I do?

says that trufflehog found a secret in one of your commits. You either
- know that you are not committing secret and trufflehog is reporting false-positive result. report to #developer-support channel
- know that you are committing secret but you have reason to do so, then you would have to add the file contains secrets to `trufflehog/exclude-patterns.txt`. You would also need to get approval from Eng Sec and Devtools team.
- realize you accidentally committed secrets, In this case, you would have to rewrite your commit history to eliminate secrets. Just reverting a commit does not remove secrets from Github commit history. Follow these steps to rewrite your commit history to eliminate secret

**example**

this secret is found
```
~~~~~~~~~~~~~~~~~~~~~
Reason: RSA private key
Date: 2019-09-19 14:53:36
Hash: 3a01a42397faa7021e6425373c3b6e06ec136c76
Filepath: moresecret.txt
Branch: refs/pull/1949/head
Commit: bad commit, contains bad secrets

-----BEGIN RSA PRIVATE KEY-----
~~~~~~~~~~~~~~~~~~~~~
```
1. `git rebase --interactive '3a01a42397faa7021e6425373c3b6e06ec136c76^'` (remember to add `^` because you need to actually rebase back to the commit before the one you wish to modify)
2. In your editor, modify `pick` to `edit` in the line of the mentioned commit 

```
edit 3a01a42 bad commit, contains bad secrets
pick 039c8fc Update and rename derp to derpp
pick bd47335 Create stuff.txt
pick 9af8ee8 Create morestuff.txt
pick 82bb2cb Create asdf.txt
```

3. Save. Now your `HEAD` is the commit mention above. We can now make changes to it then amend it. In this case I would modify the content of `moresecret.txt` to omit the secret.
4. Amend the commit `git commit --all --amend --no-edit`
5. Continue the rebase process with `git rebase --continue` to return to the previous `HEAD` commit

**WARNING** Note that this will change the SHA-1 of that commit as well as all children -- in other words, this rewrites the history from that point forward.

6. `git push --force`