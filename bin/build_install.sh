#!/bin/bash

set -ex

rm -rf /tmp/truffleHog
mkdir -p /tmp/truffleHog

cp -rf ./ /tmp/truffleHog

pushd /tmp/truffleHog

echo "local install"
python3 setup.py install --force

echo "build wheel"
python3 setup.py bdist_wheel -d dist

trufflehog -h
