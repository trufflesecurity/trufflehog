# Secret Detectors

Secret Detectors have these two major functions:

1. Given some bytes, extract possible secrets, typically using a regex.
2. Validate the secrets against the target API, typically using a HTTP client.

The purpose of Secret Detectors is to discover secrets with exceptionally high signal. High rates of false positives are not accepted.

## Table of Contents

- [Secret Detectors](#secret-detectors)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
    - [Sourcing Guidelines](#sourcing-guidelines)
    - [Development Guidelines](#development-guidelines)
    - [Development Dependencies](#development-dependencies)
    - [Creating a new Secret Scanner](#creating-a-new-secret-detector)
  - [Addendum](#addendum)
    - [Managing Test Secrets](#managing-test-secrets)
    - [Setting up Google Cloud SDK](#setting-up-google-cloud-sdk)

## Getting Started

### Sourcing Guidelines

We are interested in detectors for services that meet at least one of these criteria
- host data (they store any sort of data provided)
- have paid services (having a free or trial tier is okay though)

If you think that something should be included outside of these guidelines, please let us know.

### Development Guidelines

- When reasonable, favor using the `net/http` library to make requests instead of bringing in another library.
- Use the [`common.SaneHttpClient`](pkg/common/http.go) for the `http.Client` whenever possible.
- We recommend an editor with gopls integration (such as Vscode with Go plugin) for benefits like easily running tests, autocompletion, linting, type checking, etc.

### Development Dependencies

- A GitLab account
- A Google account
- [Google Cloud SDK installed](#setting-up-google-cloud-sdk)
- Go 1.17+
- Make

### Creating a new Secret Scanner

1. Identify the Secret Detector name from the [/proto/detectors.proto](/proto/detectors.proto) `DetectorType` enum.

2. Generate the Secret Detector

   ```bash
   go run hack/generate/generate.go detector <DetectorType enum name>
   ```

3. Complete the secret detector.

   The previous step templated a boilerplate + some example code as a package in the `pkg/detectors` folder for you to work on.
   The secret detector can be completed with these general steps:

   1. Add the test secret to GCP Secrets. See [managing test secrets](#managing-test-secrets)
   2. Update the pattern regex and keywords. Try iterating with [regex101.com](http://regex101.com/).
   3. Update the verifier code to use a non-destructive API call that can determine whether the secret is valid or not.
   4. Update the tests with these test cases at minimum:
      1. Found and verified (using a credential loaded from GCP Secrets)
      2. Found and unverified
      3. Not found
      4. Any false positive cases that you come across
   5. Create a merge request for review. CI tests must be passing.

## Addendum

### Managing Test Secrets

Do not embed test credentials in the test code. Instead, use GCP Secrets Manager.

1. Access the latest secret version for modification.

   Note: `/tmp/s` is a valid path on Linux. You will need to change that for Windows or OSX, otherwise you will see an error. On Windows you will also need to install [WSL](https://docs.microsoft.com/en-us/windows/wsl/install).

   ```bash
   gcloud secrets versions access --project trufflehog-testing --secret detectors3 latest > /tmp/s
   ```

2. Add the secret that you need for testing.

   The command above saved it to `/tmp/s`.

   The format is standard env file format,

   ```bash
   SECRET_TYPE_ONE=value
   SECRET_TYPE_ONE_INACTIVE=v@lue
   ```

3. Update the secret version with your modification.

   ```bash
   gcloud secrets versions add --project trufflehog-testing detectors3 --data-file /tmp/s
   ```

4. Access the secret value as shown in the [example code](pkg/detectors/heroku/heroku_test.go).

### Setting up Google Cloud SDK

1. Install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install
2. Authenticate with `gcloud auth login --update-adc` using your Google account

### Adding Protos in Windows

1. Install Ubuntu App in Microsoft Store https://www.microsoft.com/en-us/p/ubuntu/9nblggh4msv6.
2. Install Docker Desktop https://www.docker.com/products/docker-desktop. Enable WSL integration to Ubuntu. In Docker app, go to Settings->Resources->WSL INTEGRATION->enable Ubuntu.
3. Open Ubuntu cli and install `dos2unix`.
   ```bash
   sudo apt install dos2unix
   ```
4. Identify the `trufflehog` local directory and convert `scripts/gen_proto.sh` file in Unix format.
   ```bash
   dos2unix ./scripts/gen_proto.sh
   ```
5. Open [/proto/detectors.proto](/proto/detectors.proto) file and add new detectors then save it. Make sure Docker is running and run this in Ubuntu command line.
   ```bash
   make protos
   ```
### Testing a detector
```bash
   go test ./pkg/detectors/<detector> -tags=detectors
   ```
