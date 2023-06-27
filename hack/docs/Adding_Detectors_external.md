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
    + [Creating a new Secret Scanner](#creating-a-new-secret-scanner)
  * [Addendum](#addendum)
    + [Using a test secret file](#using-a-test-secret-file)
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

### Creating a new Secret Scanner

1. Identify the Secret Detector name from the [/proto/detectors.proto](/proto/detectors.proto) `DetectorType` enum. If necessary, run `make protos` when adding new ones.

2. Generate the Secret Detector

   ```bash
   go run hack/generate/generate.go detector <DetectorType enum name>
   ```
3. Add Secret Scanner

   Add the secret scanner to the `pkg/engine/defaults.go` file like `github.com/trufflesecurity/trufflehog/v3/pkg/detectors/<detector_name>` and 
   `<detector_name>.Scanner{},`

4. Complete the secret detector.

   The previous step templated a boilerplate + some example code as a package in the `pkg/detectors` folder for you to work on.
   The secret detector can be completed with these general steps:

   1. Create a [test secrets file, and export the variable](#using-a-test-secret-file)
   2. Update the pattern regex and keywords. Try iterating with [regex101.com](http://regex101.com/).
   3. Update the verifier code to use a non-destructive API call that can determine whether the secret is valid or not.
   4. Update the tests with these test cases at minimum:
      1. Found and verified (using a credential loaded from GCP Secrets)
      2. Found and unverified
      3. Not found
      4. Any false positive cases that you come across
   5. Create a pull request for review.

## Addendum

### Using a test secret file

1. Create a file called `.env` with this env file format:

   ```bash
   SECRET_TYPE_ONE=value
   SECRET_TYPE_ONE_INACTIVE=v@lue
   ```

2. Export the `TEST_SECRET_FILE` variable, pointing to the env file:

   ```bash
   export TEST_SECRET_FILE=".env"
   ```

Now, the detector test should attempt to load the given env key from that file.

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
