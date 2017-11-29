# Truffle Hog
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

## NEW
Trufflehog previously functioned by running entropy checks on git diffs. This functionality still exists, but high signal regex checks have been added, and the ability to surpress entropy checking has also been added.


```
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

With the `--include` and `--exclude` options, it is also possible to limit scanning to a subset of objects in the Git history by defining regular expressions (one per line) in a file to match the targeted object paths. To illustrate, see the example include and exclude files below:

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
trufflehog --include include-patterns.txt --exclude exclude-patterns.txt file://path/to/my/repo.git
```
With these filters, issues found in files in the root-level `src` directory would be reported, unless they had the `.classpath` or `.jmx` extension, or if they were found in the `src/test/dev/resources/` directory, for example. Additional usage information is provided when calling `trufflehog` with the `-h` or `--help` options.

These features help cut down on noise, and makes the tool easier to shove into a devops pipeline.

![Example](https://i.imgur.com/YAXndLD.png)

## Install
```
pip install truffleHog
```

## Customizing

Custom regexes can be added to the following file:
```
truffleHog/truffleHog/regexChecks.py
```
Things like subdomain enumeration, s3 bucket detection, and other useful regexes highly custom to the situation can be added.

Feel free to also contribute high signal regexes upstream that you think will benifit the community. Things like Azure keys, Twilio keys, Google Compute keys, are welcome, provided a high signal regex can be constructed.

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and check for secrets. This is both by regex and by entropy. For entropy checks, trufflehog will evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

## Help

```
Find secrets hidden in the depths of git.

positional arguments:
  git_url               URL for secret searching

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --regex               Enable high signal regex checks
  --entropy DO_ENTROPY  Enable entropy checks
  --since_commit SINCE_COMMIT
                        Only scan from a given commit hash
  --max_depth MAX_DEPTH
                        The max commit depth to go back when searching for
                        secrets
```

## Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
- ~~A since commit X feature~~
- ~~Print the file affected~~
