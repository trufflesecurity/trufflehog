# Truffle Hog
Searches through git repositories for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.

```
truffleHog https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

![Example](https://i.imgur.com/YAXndLD.png)

## Install
Automatically install via the [Python Package Indexer, PIP](https://pypi.python.org/pypi/pip)
```
pip install truffleHog
```

or manually install by via clone/download the repository and install with setup.py

```
git clone https://github.com/dxa4481/truffleHog.git
cd truffleHog.git
python setup.py install --record files.txt
```

## Uninstall
```
pip uninstall truffleHog
```

or manually uninstall if installed locally via repo
```
cat files.txt | xargs rm -rf
```

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

## Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
