# Truffle Hog
Searches through git repositories for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.

```
python truffleHog.py https://github.com/dxa4481/truffleHog.git
```

![Example](https://i.imgur.com/YAXndLD.png)

## Setup (run natively)
The only requirement is GitPython, which can be installed with the following
```
pip install -r app/requirements.txt
```

## Setup (run in Docker)

Clone down the repo and build the container image:

```
cd truffleHog && docker build -t truffle-hog .
```

Next, run the container image, using the git URL as an argument:

```
docker run -it --rm truffle-hog https://github.com/dxa4481/truffleHog.git
```

The container will exit with non-zero status if any issues are found, which
makes automation in the CI pipeline a little easier.


## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

## Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
