#!/bin/bash

GIT_UPSTREAM_REPO="$(git config --get remote.origin.url)"
HEAD_SHA="$(git rev-parse HEAD)"
COMMITS="$(git log --format=%H HEAD ^origin/master | awk -vORS=, '{print}' | sed  's/,$/\n/')"

if [ "$BUILDKITE_PULL_REQUEST" = "false" ]; then
    REF="$(git ls-remote origin 'tags/submitqueue/integration/*'| grep $HEAD_SHA | awk  '{print $2}' | sed -e "s/^refs\///")"
else
    REF="$(git ls-remote origin 'pull/*/head'| grep $HEAD_SHA | awk  '{print $2}' | sed -e "s/^refs\///")"
fi

if [ -z $REF ]; then   
    echo "REF is not set so use $BUILDKITE_BRANCH"
    REF="${BUILDKITE_BRANCH}"
fi

echo "\e[34mrunning trufflehug on $REF from $GIT_UPSTREAM_REPO repo on commits $COMMITS \e[0m"
echo "\e[32mBuild fail if secrets are found in these commits. To remove secrets please see https://github.com/uber-atg/truffleHog?organization=uber-atg&organization=uber-atg#trufflehog-found-secrets-so-my-build-failed-what-should-i-do
Secrets type we scan for can be found at https://github.com/uber-atg/truffleHog/blob/dev/testRules.json.
If there exist a trufflehog/exclude-patterns.txt under repo $GIT_UPSTREAM_REPO then these files will be excluded from the scan. \e[0m"

if [ -e /workdir/trufflehog/exclude-patterns.txt ]
then
    python /app/truffleHog.py --entropy=False --regex --rules /app/testRules.json  --branch $REF --exclude_paths /workdir/trufflehog/exclude-patterns.txt --commits "${COMMITS}" "${GIT_UPSTREAM_REPO}"
else
    python /app/truffleHog.py --entropy=False --regex --rules /app/testRules.json  --branch $REF --commits "${COMMITS}" "${GIT_UPSTREAM_REPO}"
fi
