# TruffleHog Pre-Commit Hooks

Pre-commit hooks are scripts that run automatically before a commit is completed, allowing you to check your code for issues before sharing it with others. TruffleHog can be integrated as a pre-commit hook to prevent credentials from leaking before they ever leave your computer.

This guide covers how to set up TruffleHog as a pre-commit hook using two popular frameworks:

1. [Git's hooksPath feature](#global-setup-using-gits-hookspath-feature) - A built-in Git feature for managing hooks globally
2. [Using Pre-commit framework](#using-the-pre-commit-framework) - A language-agnostic framework for managing pre-commit hooks
3. [Using Husky](#using-husky) - A Git hooks manager for JavaScript/Node.js projects

## Prerequisites

All of the methods require TruffleHog to be installed.

1. Install TruffleHog:

```bash
# Using Homebrew (macOS)
brew install trufflehog

# Using installation script for Linux, macOS, and Windows (and WSL)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Global setup using Git's hooksPath feature

This approach uses Git's `core.hooksPath` to apply hooks to all repositories without requiring any per-repository setup:

1. Create a global hooks directory:

```bash
mkdir -p ~/.git-hooks
```

2. Create a pre-commit hook file:

```bash
touch ~/.git-hooks/pre-commit
chmod +x ~/.git-hooks/pre-commit
```

3. Add the following content to `~/.git-hooks/pre-commit`:

```bash
#!/bin/sh

trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail
```

If you are using Docker, use this instead:

```bash
#!/bin/sh

docker run --rm -v "$(pwd):/workdir" -i --rm trufflesecurity/trufflehog:latest git file:///workdir --since-commit HEAD --results=verified,unknown --fail
```

4. Configure Git to use this hooks directory globally:

```bash
git config --global core.hooksPath ~/.git-hooks
```

Now all your repositories will automatically use this pre-commit hook without any additional setup.

## Using the Pre-commit Framework

The [pre-commit framework](https://pre-commit.com) is a powerful, language-agnostic tool for managing Git hooks.

### Installation of Pre-commit

1. Install the pre-commit framework:

```bash
# Using pip (Python)
pip install pre-commit

# Using Homebrew (macOS)
brew install pre-commit

# Using conda
conda install -c conda-forge pre-commit
```

### Repository-Specific Setup

To set up TruffleHog as a pre-commit hook for a specific repository:

1. Create a `.pre-commit-config.yaml` file in the root of your repository:

```yaml
repos:
  - repo: local
    hooks:
      - id: trufflehog
        name: TruffleHog
        description: Detect secrets in your data.
        entry: bash -c 'trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail'
        language: system
        stages: ["commit", "push"]
```

2. Install the pre-commit hook:

```bash
pre-commit install
```

## Using Husky

[Husky](https://typicode.github.io/husky/) is a popular tool for managing Git hooks in JavaScript/Node.js projects.

### Installation of Husky

1. Install Husky in your project:

```bash
# npm
npm install husky --save-dev

# yarn
yarn add husky --dev
```

2. Enable Git hooks:

```bash
# npm
npx husky init
```

### Setting Up TruffleHog with Husky

1. Add the following content to `.husky/pre-commit`:

```bash
echo "trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail" > .husky/pre-commit
```

3. For Docker users, use this content instead:

```bash
echo 'docker run --rm -v "$(pwd):/workdir" -i --rm trufflesecurity/trufflehog:latest git file:///workdir --since-commit HEAD --results=verified,unknown --fail' > .husky/pre-commit
```

## Best Practices

### Commit Process

For optimal hook efficacy:

1. Execute `git add` followed by `git commit` separately. This ensures TruffleHog analyzes all intended changes.
2. Avoid using `git commit -am`, as it might bypass pre-commit hook execution for unstaged modifications.

### Skipping Hooks

In rare cases, you may need to bypass pre-commit hooks:

```bash
git commit --no-verify -m "Your commit message"
```

## Troubleshooting

### Hook Not Running

If your pre-commit hook isn't running:

1. Ensure the hook is executable:

   ```bash
   chmod +x .git/hooks/pre-commit
   ```

2. Check if hooks are enabled:

   ```bash
   git config --get core.hooksPath
   ```

### False Positives

If you're getting false positives:

1. Use the `--results=verified` flag to only show verified secrets
2. Add `trufflehog:ignore` comments on lines with known false positives or risk-accepted findings

## Conclusion

By integrating TruffleHog into your pre-commit workflow, you can prevent credential leaks before they happen. Choose the setup method that best fits your project's needs and development workflow.

For more information on TruffleHog's capabilities, refer to the [main documentation](README.md).
