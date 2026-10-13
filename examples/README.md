# Examples
This folder contains various examples like custom detectors, scripts, etc. Feel free to contribute!

### Generic Detector
An often requested feature for TruffleHog is a generic detector. By default, we do not support generic detection as it would result in lots of false positives. However, if you want to attempt detect generic secrets you can use a custom detector. 

#### Try it out:
```
wget https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/examples/generic.yml
trufflehog filesystem --config=$PWD/generic.yml $PWD

# to filter so that _only_ generic credentials are logged:
trufflehog filesystem --config=$PWD/generic.yml --json --no-verification $PWD | awk '/generic-api-key/{print $0}'
```

### Encrypted AWS credentials

The built-in AWS detector only reports an access key ID when it also finds a 40-character secret it can send to STS. Encrypted secrets (SOPS, KMS, and similar) do not match that pattern, so the finding is dropped. `encrypted_aws.yml` is a custom detector config that still surfaces those IDs as unverified results.

```
wget https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/examples/encrypted_aws.yml
trufflehog filesystem --config=$PWD/encrypted_aws.yml $PWD
```

Prefer the SOPS or KMS detectors in that file when you know the ciphertext format. The ID-only detector will also match ordinary plaintext AWS keys.

