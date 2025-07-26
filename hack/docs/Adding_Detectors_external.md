# Secret Detectors

Secret Detectors have these two major functions:

1. Given some bytes, extract possible secrets, typically using a regex.
2. Validate the secrets against the target API, typically using a HTTP client.

The purpose of Secret Detectors is to discover secrets with exceptionally high signal. High rates of false positives are not accepted.

## Table of Contents

- [Secret Detectors](#secret-detectors)
  * [Table of Contents](#table-of-contents)
  * [Getting Started](#getting-started)
    + [Sourcing Guidelines](#sourcing-guidelines)
    + [Development Guidelines](#development-guidelines)
    + [Development Dependencies](#development-dependencies)
    + [Creating a new Secret Detector](#creating-a-new-secret-detector)
    + [Testing the Detector](#testing-the-detector)
  * [Addendum](#addendum)
    + [Adding Protos in Windows](#adding-protos-in-windows)

## Getting Started

### Sourcing Guidelines

We are interested in detectors for services that meet at least one of these criteria
- host data (they store any sort of data provided)
- have paid services (having a free or trial tier is okay though)

If you think that something should be included outside of these guidelines, please let us know.

### Development Guidelines

- When reasonable, favor using the `net/http` library to make requests instead of bringing in another library.
- Use the [`common.SaneHttpClient`](/pkg/common/http.go) for the `http.Client` whenever possible.

### Development Dependencies

- Go 1.17+
- Make

### Adding New Token Formats to an Existing Scanner

In some instances, services will update their token format, requiring a new regex to properly detect secrets in addition to supporting the previous token format. Accommodating this can be done without adding a net-new detector. [We provide a `Versioner` interface](https://github.com/trufflesecurity/trufflehog/blob/e18cfd5e0af1469a9f05b8d5732bcc94c39da49c/pkg/detectors/detectors.go#L30) that can be implemented.

1. Create two new directories `v1` and `v2`. Move the existing detector and tests into `v1`, and add new files to `v2`.
Ex: `<packagename>/<old_files>` -> `<packagename>/v1/<old_files>`, `<packagename>/v2/<new_files>`

Note: Be sure to update the tests to reference the new secret values in GSM, or the tests will fail.

2. Implement the `Versioner` interface. [GitHub example implementation.](https://github.com/trufflesecurity/trufflehog/blob/2964b3b2d2edf2b60b1f71443338c6534720b67a/pkg/detectors/github/v1/github_old.go#L23))

3. Add a 'version' field in ExtraData for both existing and new detector versions.

4. Update the existing detector in DefaultDetectors in `/pkg/engine/defaults/defaults.go`

5. Proceed from step 3 of [Creating a new Secret Scanner](#creating-a-new-secret-scanner)

### Creating a new Secret Detector

1. Add a new Secret Detector enum to the [`DetectorType` list here](/proto/detectors.proto).

2. Run `make protos` to update the `.pb` files.

3. Generate the Secret Detector

   ```bash
   go run hack/generate/generate.go detector <DetectorType enum name>
   example: go run hack/generate/generate.go detector SampleAPI
   ```
4. Add the Secret Detector to TruffleHog's Default Detectors

   Add the secret scanner to the [`pkg/engine/defaults/defaults.go`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/engine/defaults/defaults.go) file like [`github.com/trufflesecurity/trufflehog/v3/pkg/detectors/<detector_name>`](https://github.com/trufflesecurity/trufflehog/blob/b71ea27a696bdf1c3141f637fda4ee4936c2f2d6/pkg/engine/defaults/defaults.go#L9) and 
   [`<detector_name>.Scanner{}`](https://github.com/trufflesecurity/trufflehog/blob/b71ea27a696bdf1c3141f637fda4ee4936c2f2d6/pkg/engine/defaults/defaults.go#L1546)

5. Complete the Secret Detector.

   The previous step templated a boilerplate + some example code as a package in the `pkg/detectors` folder for you to work on.
   The Secret Detector can be completed with these general steps:

   1. Update the pattern regex and keywords. Try iterating with [regex101.com](http://regex101.com/).
   2. Update the verifier code to use a non-destructive API call that can determine whether the secret is valid or not.
      * Make sure you understand [verification indeterminacy](#verification-indeterminacy).
   3. Create a [test for the detector](#testing-the-detector).
   4. Add your new detector to DefaultDetectors in `/pkg/engine/defaults/defaults.go`.
   5. Create a pull request for review.

### Testing the Detector
To ensure the quality of your PR, make sure your tests are passing with verified credentials.

1. Create a file called `.env` with this env file format:

   ```bash
   SECRET_TYPE_ONE=value
   SECRET_TYPE_ONE_INACTIVE=v@lue
   ```

2. Export the `TEST_SECRET_FILE` variable, pointing to the env file:

   ```bash
   export TEST_SECRET_FILE=".env"
   ```
   The `.env` file should be in the new detector's directory like this:
   ```
   ├── tailscale
   │   ├── .env
   │   ├── tailscale.go
   │   └── tailscale_test.go
   ```
   Now that a `.env` file is present, the test file can load secrets locally.

3. Next, update the tests as necessary. A test file has already been generated by the `go run hack/generate/generate.go` command from earlier. There are 5 cases that have been generated:
   1. Found and verified (using a credential loaded from the .env file)
   2. Found and unverified (determinately, i.e. the secret is invalid)
   3. Found and unverified (indeterminately due to timeout)
   4. Found and unverified (indeterminately due to an unexpected API response)
   5. Not found

    Make any necessary updates to the tests. Note there might not be any changes required as the tests generated by the `go run hack/generate/generate.go` command are pretty good. 
   [Here is an exemplary test file for a detector which covers all 5 test cases](https://github.com/trufflesecurity/trufflehog/blob/6f9065b0aae981133a7fa3431c17a5c6213be226/pkg/detectors/browserstack/browserstack_test.go).

4. Now run the tests and check to make sure they are passing ✔️!
```bash
   go test ./pkg/detectors/<detector> -tags=detectors
   ```

If the tests are passing, feel free to open a PR! 




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

