# Truffle Hog
Searches through git repositories and Github accounts for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.

For arbitrary git repositories:
```
python truffleHog.py https://github.com/dxa4481/truffleHog.git
```

For searching entire github accounts:
```
python truffleHog.py --github-user dxa4481 --github-access b4e1a6f7eb77f43e69bf0d53ac136b9613026a71
```

![Example](https://i.imgur.com/NTvjvEX.png)

## Setup
The only requirements are GitPython and PyGithub, which can be installed with the following
```
pip install -r requirements.txt
```

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

It is best to provide a Github personal access token with --github-access when searching accounts, but it is not required. Not providing an API key will significantly reduce your request allowance.

![Example](https://i.imgur.com/W5hO7Xj.png)

## Wishlist

- A way to detect and not scan binary diffs
- Don't rescan diffs if already looked at in another branch
