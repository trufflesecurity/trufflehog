# Lyft trufflehog
###### A Lyft Python library

This is compatible with Python 2.7 and Python 3.4+.

## Features
This package is Used to look for secrets in source code .

It does X, Y and Z.

## Installing

### Install from command line

```bash
pip install --extra-index-url https://pypi.lyft.net/pypi/ lyft-trufflehog
```

### Install to a Python service

##### 1. add to requirements.in
```
lyft-trufflehog==X.Y.Z
```

##### 2. pip compile

```bash
# on your laptop
control run piptools.compile <directory-name>
```

Commit the changes to requirements.txt and requirements.in to the repo.

##### 3. Install in container

```bash
# in container
service_venv pip install -r requirements.txt
```

## Developing lyft-trufflehog

### Environment

Create a virtual environment. This is easiest with
[virtualenvwrapper](http://virtualenvwrapper.readthedocs.org/en/latest/index.html).

```bash
mkvirtualenv lyft-trufflehog
```

If you run into errors while trying to install virtualenvwrapper with pip six-1.4.1 on Mac OSX 10.11, use the following before creating your virtual environment:

```bash
install virtualenvwrapper --ignore-installed
```

Then, install the development requirements:

```bash
pip install -r requirements.txt
pip3 install -r requirements.txt  # python 3
```

#### Developing with another service

To install a local copy of this package into consuming projects run the following command in that services' container:

```bash
# in container
pip install -e /code/python-lyft-trufflehog
```

This will allow any changes you make in python-lyft-trufflehog to be picked up automatically in other projects without having to re-install.

### Testing

Unit tests are run with `py.test`. They are located in `tests/unit`. 100% code coverage is required. Make sure to test both python 2 & 3. Type checks are run with `mypy`. Linting is `flake8`. There are friendly `make` targets for each of these tests.

```bash
# after setting up environment
make test  # unit tests in Python 2 & 3
make lint  # flake8
make mypy  # type checks
```

## Distributing lyft-trufflehog
Follow these three easy steps to update the lyft-trufflehog package:

1. Increment the version number in `setup.py` so that the package index picks up the change. This should be done as part of your commit.

   The version is a dot-separated string of the format, `M.m.b`, where `M` is
   a major release, `m` is a minor release, and `b` is a bugfix release.
   See [Semantic Versioning](http://semver.org/).

2. Use Submit Queue to merge your branch :rocket:

3. Create a [release](https://github.com/lyft/python-lyft-trufflehog/releases/new) in github for the new version. Prefix the tag version with `v`, e.g. `v1.2.3`.

This will trigger a deploy in Jenkins (https://deploy.lyft.net/view/yourlibraryname-deploy-view). When the deploy finishes, your code will be released automatically to Lyft's pypi.
