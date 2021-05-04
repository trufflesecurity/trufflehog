

# truffleHog
[![codecov](https://codecov.io/gh/trufflesecurity/truffleHog/branch/master/graph/badge.svg)](https://codecov.io/gh/trufflesecurity/truffleHog)

Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

## Join The Slack
Have questions? Feedback? Jump in slack and hang out with me 

https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ

## NEW
truffleHog previously functioned by running entropy checks on git diffs. This functionality still exists, but high signal regex checks have been added, and the ability to suppress entropy checking has also been added.


```
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

With the `--include_paths` and `--exclude_paths` options, it is also possible to limit scanning to a subset of objects in the Git history by defining regular expressions (one per line) in a file to match the targeted object paths. To illustrate, see the example include and exclude files below:

_include-patterns.txt:_
```ini
src/
# lines beginning with "#" are treated as comments and are ignored
gradle/
# regexes must match the entire path, but can use python's regex syntax for
# case-insensitive matching and other advanced options
(?i).*\.(properties|conf|ini|txt|y(a)?ml)$
(.*/)?id_[rd]sa$
```

_exclude-patterns.txt:_
```ini
(.*/)?\.classpath$
.*\.jmx$
(.*/)?test/(.*/)?resources/
```

These filter files could then be applied by:
```bash
trufflehog --include_paths include-patterns.txt --exclude_paths exclude-patterns.txt file://path/to/my/repo.git
```
With these filters, issues found in files in the root-level `src` directory would be reported, unless they had the `.classpath` or `.jmx` extension, or if they were found in the `src/test/dev/resources/` directory, for example. Additional usage information is provided when calling `trufflehog` with the `-h` or `--help` options.

These features help cut down on noise, and makes the tool easier to shove into a devops pipeline.

![Example](https://i.imgur.com/YAXndLD.png)

## Install
```
pip install truffleHog
```

## Customizing

Custom regexes can be added with the following flag `--rules /path/to/rules`. This should be a json file of the following format:
```
{
    "RSA private key": "-----BEGIN EC PRIVATE KEY-----"
}
```
Things like subdomain enumeration, s3 bucket detection, and other useful regexes highly custom to the situation can be added.

Feel free to also contribute high signal regexes upstream that you think will benefit the community. Things like Azure keys, Twilio keys, Google Compute keys, are welcome, provided a high signal regex can be constructed.

trufflehog's base rule set sources from https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json

To explicitly allow particular secrets (e.g. self-signed keys used only for local testing) you can provide an allow list `--allow /path/to/allow` in the following format:
```
{
    "local self signed test key": "-----BEGIN EC PRIVATE KEY-----\nfoobar123\n-----END EC PRIVATE KEY-----",
    "git cherry pick SHAs": "regex:Cherry picked from .*",
}
```

Note that values beginning with `regex:` will be used as regular expressions. Values without this will be literal, with some automatic conversions (e.g. flexible newlines).

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and check for secrets. This is both by regex and by entropy. For entropy checks, truffleHog will evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

## Help

```
usage: trufflehog [-h] [--json] [--regex] [--rules RULES] [--allow ALLOW]
                  [--entropy DO_ENTROPY] [--since_commit SINCE_COMMIT]
                  [--max_depth MAX_DEPTH]
                  git_url

Find secrets hidden in the depths of git.

positional arguments:
  git_url               URL for secret searching

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --regex               Enable high signal regex checks
  --rules RULES         Ignore default regexes and source from json list file
  --allow ALLOW         Explicitly allow regexes from json list file
  --entropy DO_ENTROPY  Enable entropy checks
  --since_commit SINCE_COMMIT
                        Only scan from a given commit hash
  --branch BRANCH       Scans only the selected branch
  --max_depth MAX_DEPTH
                        The max commit depth to go back when searching for
                        secrets
  -i INCLUDE_PATHS_FILE, --include_paths INCLUDE_PATHS_FILE
                        File with regular expressions (one per line), at least
                        one of which must match a Git object path in order for
                        it to be scanned; lines starting with "#" are treated
                        as comments and are ignored. If empty or not provided
                        (default), all Git object paths are included unless
                        otherwise excluded via the --exclude_paths option.
  -x EXCLUDE_PATHS_FILE, --exclude_paths EXCLUDE_PATHS_FILE
                        File with regular expressions (one per line), none of
                        which may match a Git object path in order for it to
                        be scanned; lines starting with "#" are treated as
                        comments and are ignored. If empty or not provided
                        (default), no Git object paths are excluded unless
                        effectively excluded via the --include_paths option.
```

## Running with Docker

First, enter the directory containing the git repository

```
cd /path/to/git
```

To launch the trufflehog with the docker image, run the following"

```
docker run --rm -v "$(pwd):/proj" dxa4481/trufflehog file:///proj
```

`-v` mounts the current working dir (`pwd`) to the `/proj` dir in the Docker container

`file:///proj` references that very same `/proj` dir in the container (which is also set as the default working dir in the Dockerfile)

## Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
- ~~A since commit X feature~~
- ~~Print the file affected~~
