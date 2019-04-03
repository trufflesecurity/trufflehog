# truffleHog
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

## NEW
truffleHog previously functioned by running entropy checks on git diffs. This functionality still exists, but high signal regex checks have been added, and the ability to surpress entropy checking has also been added.

These features help cut down on noise, and makes the tool easier to shove into a devops pipeline.


```
truffleHog --regex https://github.com/dxa4481/truffleHog.git
```

You can also check a repo directly from your file system:

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

To enable entropy check, use following:
```
truffleHog --regex --entropy https://github.com/dxa4481/truffleHog.git
```

![Example](https://i.imgur.com/YAXndLD.png)

## Install
```
pip install truffleHog
```

## Customizing

Custom regexes can be added with the following flag `--rules /path/to/rules`. You can also add regexes along with default ones using `--add-rules /path/to/rules` flag. It makes it easier to extend the rule checks while using default and custom rules both. File provided by `--rules` or `--add-rules` should be a json file of the following format:
```
{
    "RSA private key": "-----BEGIN EC PRIVATE KEY-----"
}
```
Things like subdomain enumeration, s3 bucket detection, and other useful regexes highly custom to the situation can be added.

Feel free to also contribute high signal regexes upstream that you think will benefit the community. Things like Azure keys, Twilio keys, Google Compute keys, are welcome, provided a high signal regex can be constructed.

trufflehog's base rule set sources from https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json  

You can also check what regexes will the program check against before actually running it against your repo. This is a helpful check to make sure your custom rules/regexes are detected successfully:
```
truffleHog --regex --show-regex <git_url>
```
A json response will be returned. A sample is shown below:
```
{
  "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
  ...
}
```
  
Entropy is checked at a minimum of 20-letter words. You can control the word-length and threshold value for the entropy checks to your liking.  
`--entropy-wc` controls the word-length. [default: 20]  
`--entropy-hex-thresh` controls the threshold for entropy calculated for hex strings. [default: 3.0]  
`--entropy-b64-thresh` controls the threshold for entropy calculated for base64 strings. [default: 4.5]  

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and check for secrets. This is both by regex and by entropy. For entropy checks, truffleHog will evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than `--entropy-wc` characters comprised of those character sets in each diff. If at any point an entropy crosses the thresholds defined by `--entropy-hex-thresh` and `--entropy-b64-thresh` for a string greater than `--entropy-wc` characters, it will print to the screen.

## Help

```
usage: truffleHog.py [-h] [--json] [--show-regex] [--regex] [--rules RULES]
                     [--add-rules ADD_RULES] [--entropy]
                     [--entropy-wc ENTROPY_WC]
                     [--entropy-b64-thresh ENTROPY_B64_THRESH]
                     [--entropy-hex-thresh ENTROPY_HEX_THRESH]
                     [--since-commit SINCE_COMMIT] [--max-depth MAX_DEPTH]
                     [--branch BRANCH] [--repo-path REPO_PATH] [--cleanup]
                     git_url

Find secrets hidden in the depths of git.

positional arguments:
  git_url               URL for secret searching

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --show-regex          prints out regexes that will computed against repo
  --regex               Enable high signal regex checks
  --rules RULES         Ignore default regexes and source from json list file
  --add-rules ADD_RULES
                        Adds more regex rules along with default ones from a
                        json list file
  --entropy             Enable entropy checks
  --entropy-wc ENTROPY_WC
                        Segments n-length words to check entropy against
                        [default: 20]
  --entropy-b64-thresh ENTROPY_B64_THRESH
                        User defined entropy threshold for base64 strings
                        [default: 4.5]
  --entropy-hex-thresh ENTROPY_HEX_THRESH
                        User defined entropy threshold for hex strings
                        [default: 3.0]
  --since-commit SINCE_COMMIT
                        Only scan from a given commit hash
  --max-depth MAX_DEPTH
                        The max commit depth to go back when searching for
                        secrets
  --branch BRANCH       Name of the branch to be scanned
  --repo-path REPO_PATH
                        Path to the cloned repo. If provided, git_url will not
                        be used
  --cleanup             Clean up all temporary result files
```

## Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
- ~~A since commit X feature~~
- ~~Print the file affected~~
