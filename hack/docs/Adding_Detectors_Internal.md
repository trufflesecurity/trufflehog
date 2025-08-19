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

### Adding New Token Formats to an Existing Scanner

In some instances, services will update their token format, requiring a new regex to properly detect secrets in addition to supporting the previous token format. Accommodating this can be done without adding a net-new detector. [We provide a `Versioner` interface](https://github.com/trufflesecurity/trufflehog/blob/e18cfd5e0af1469a9f05b8d5732bcc94c39da49c/pkg/detectors/detectors.go#L30) that can be implemented.

1. Create two new directories `v1` and `v2`. Move the existing detector and tests into `v1`, and add new files to `v2`.
Ex: `<packagename>/<old_files>` -> `<packagename>/v1/<old_files>`, `<packagename>/v2/<new_files>`

Note: Be sure to update the tests to reference the new secret values in GSM, or the tests will fail.

2. Implement the `Versioner` interface. [GitHub example implementation.](/pkg/detectors/github/v1/github_old.go#L23)

3. Add a 'version' field in ExtraData for both existing and new detector versions.

4. Update the existing detector in DefaultDetectors in `/pkg/engine/defaults/defaults.go`

5. Proceed from step 3 of [Creating a new Secret Scanner](#creating-a-new-secret-scanner)

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
      * Make sure you understand [verification indeterminacy](#verification-indeterminacy).
   4. Update the tests with these test cases at minimum:
      1. Found and verified (using a credential loaded from GCP Secrets)
      2. Found and unverified (determinately, i.e. the secret is invalid)
      3. Found and unverified (indeterminately due to timeout)
      4. Found and unverified (indeterminately due to an unexpected API response)
      5. Not found
      6. Any false positive cases that you come across
   5. Add your new detector to DefaultDetectors in `/pkg/engine/defaults/defaults.go`
   6. Create a merge request for review. CI tests must be passing.

## Addendum

### Verification indeterminacy

There are two types of reasons that secret verification can fail:
* The candidate secret is not actually a valid secret.
* Something went wrong in the process unrelated to the candidate secret, such as a transient network error or an unexpected API response.

In TruffleHog parlance, the first type of verification response is called _determinate_ and the second type is called _indeterminate_. Verification code should distinguish between the two by returning an error object in the result struct **only** for indeterminate failures. In general, a verifier should return an error (indicating an indeterminate failure) in all cases that haven't been explicitly identified as determinate failure states.

For example, consider a hypothetical authentication endpoint that returns `200 OK` for valid credentials and `403 Forbidden` for invalid credentials. The verifier for this endpoint could make an HTTP request and use the response status code to decide what to return:
* A `200` response would indicate that verification succeeded. (Or maybe any `2xx` response.)
* A `403` response would indicate that verification failed **determinately** and no error object should be returned.
* Any other response would indicate that verification failed **indeterminately** and an error object should be returned.

### Managing Test Secrets

Do not embed test credentials in the test code. Instead, use GCP Secrets Manager.

1. Access the latest secret version for modification.

   Note: `/tmp/s` is a valid path on Linux. You will need to change that for Windows or OSX, otherwise you will see an error. On Windows you will also need to install [WSL](https://docs.microsoft.com/en-us/windows/wsl/install).

   ```bash
   gcloud secrets versions access --project trufflehog-testing --secret detectors5 latest > /tmp/s
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
   gcloud secrets versions add --project trufflehog-testing detectors5 --data-file /tmp/s
   ```
   Note: We increment the detectors file name `detectors(n+1)` once the previous one exceeds the max size allowed by GSM (65kb).

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
