#!/bin/bash

set -ex

nose2 --with-coverage truffleHog.shannon -v
coverage report -m

python -m truffleHog.interface https://github.com/sortigoza/truffleHog.git
