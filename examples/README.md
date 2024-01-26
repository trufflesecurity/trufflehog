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
