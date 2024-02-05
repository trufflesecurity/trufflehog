# Testing

Most testing is handled automatically by our GitHub Actions workflows.

## Local GitHub Action Testing

In some cases you may wish to submit changes to the Trufflehog GitHub Action. Unfortunately GitHub does not provide a 1st-party testing environment for testing actions outside of GitHub Actions.

Fortunately [nektos/act](https://github.com/nektos/act) enables local testing of GitHub Actions.

### Instructions

1. Please follow [the installation instructions](http://https://github.com/nektos/act#installation) for your OS.
2. The first run of `act` will ask you to specify an image. `Medium` should suffice.
3. You'll need to configure a personal-access-token(PAT) with: `repo:status`, `repo_deployment`, and `public_repo` permissions.
4. Set an environment variable named `GITHUB_TOKEN` with the PAT from the previous step as the value: `$ export GITHUB_TOKEN=<your_PAT>`
5. Run the following command from the repository root: `act pull_request -j test -W .github/workflows/secrets.yml -s GITHUB_TOKEN --defaultbranch main`
6. If the job was successful, you should expect to see output from the scanner showing several detected secrets.
7. If you want to omit the context of a pull request event and just test that the action starts successfully, run: `act -j test -W .github/workflows/secrets.yml -s GITHUB_TOKEN --defaultbranch main`
