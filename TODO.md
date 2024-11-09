# TruffleHog TODOs

📊 **Statistics**
- Total TODOs: 111
- Last Updated: 2024-11-09 13:31:13

## Table of Contents
- [♻️ Refactor](#�️-refactor) (3 items)
- [✨ Enhancement](#�-enhancement) (18 items)
- [📝 Documentation](#��-documentation) (3 items)
- [🔄 General](#��-general) (82 items)
- [🧪 Testing](#��-testing) (5 items)

---

## ♻️ Refactor

### 📦 root

- [`main.go:357`](https://github.com/trufflesecurity/trufflehog/blob/main/main.go#L357): refactor to better pass credentials

### 📦 sources

- [`filesystem_test.go:127`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/filesystem/filesystem_test.go#L127): refactor to allow a virtual filesystem.
- [`git.go:1076`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L1076): refactor with PrepareRepo to remove duplicated logic

## ✨ Enhancement

### 📦 analyzer

- [`cli.go:34`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/cli.go#L34): Add list of supported key types.

### 📦 custom_detectors

- [`custom_detectors_test.go:75`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors_test.go#L75): Support both template and webhook.

### 📦 detectors

- [`azure.go:35`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/azure/azure.go#L35): support old patterns
- [`coinbase_waas_test.go:64`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/coinbase_waas/coinbase_waas_test.go#L64): Is it worth supporting case-insensitive headers?
- [`github_old.go:36`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/github/v1/github_old.go#L36): Add secret context?? Information about access, ownership etc
- [`mongodb.go:33`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mongodb/mongodb.go#L33): Add support for sharded cluster, replica set and Atlas Deployment.
- [`mongodb_test.go:86`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mongodb/mongodb_test.go#L86): These fail because the Go driver doesn't explicitly support `authMechanism=DEFAULT`[1].
- [`paystack.go:22`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/paystack/paystack.go#L22): support live key
- [`privatekey.go:31`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/privatekey/privatekey.go#L31): add base64 encoded key support
- [`uri.go:28`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/uri/uri.go#L28): make local addr opt-out

### 📦 root

- [`main.go:121`](https://github.com/trufflesecurity/trufflehog/blob/main/main.go#L121): Add more GitLab options
- [`main.go:134`](https://github.com/trufflesecurity/trufflehog/blob/main/main.go#L134): Add more filesystem scan options. Currently only supports scanning a list of directories.
- [`main.go:306`](https://github.com/trufflesecurity/trufflehog/blob/main/main.go#L306): Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15

### 📦 sources

- [`github.go:596`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L596): Replace loop below with a call to s.addReposForMembers(ctx, reporter)
- [`source_manager.go:337`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/source_manager.go#L337): Catch panics and add to report.
- [`source_manager.go:364`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/source_manager.go#L364): Catch panics and add to report.

### 📦 tui

- [`source_component.go:35`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_component.go#L35): Add a focus variable.
- [`trufflehog_component.go:34`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/trufflehog_component.go#L34): Add a focus variable.

## 📝 Documentation

### 📦 sources

- [`gitlab.go:512`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/gitlab/gitlab.go#L512): Use keyset pagination (https://docs.gitlab.com/ee/api/rest/index.html#keyset-based-pagination)

### 📦 tui

- [`source_select.go:15`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_select/source_select.go#L15): Review light theme styling
- [`syslog.go:14`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/sources/syslog/syslog.go#L14): review fields

## 🔄 General

### 📦 analyzer

- [`client.go:48`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/client.go#L48): io.Writer
- [`client.go:60`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/client.go#L60): JSON
- [`finegrained.go:914`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/github/finegrained/finegrained.go#L914): Log error.
- [`finegrained.go:1243`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/github/finegrained/finegrained.go#L1243): Log error.
- [`finegrained.go:1266`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/github/finegrained/finegrained.go#L1266): Log error.
- [`github.go:63`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/github/github.go#L63): Unbound resources
- [`mysql.go:555`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/analyzers/mysql/mysql.go#L555): How to deal with error here?
- [`cli.go:58`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/cli.go#L58): Log error.
- [`config.go:3`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/config/config.go#L3): separate CLI configuration from analysis configuration.
- [`form.go:80`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/tui/form.go#L80): Check form focus.
- [`form.go:93`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/tui/form.go#L93): Set Config
- [`tui.go:108`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/analyzer/tui/tui.go#L108): Responsive pages.

### 📦 common

- [`http.go:18`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/common/http.go#L18): Expires Monday, June 4, 2035 at 4:04:38 AM Pacific
- [`http.go:53`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/common/http.go#L53): Expires September 17, 2040 at 9:00:00 AM Pacific Daylight Time

### 📦 custom_detectors

- [`custom_detectors.go:40`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors.go#L40): Return all validation errors.
- [`custom_detectors.go:57`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors.go#L57): Copy only necessary data out of pb.
- [`custom_detectors.go:121`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors.go#L121): Log we're possibly leaving out results.
- [`custom_detectors.go:156`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors.go#L156): Log we're possibly leaving out results.
- [`custom_detectors.go:189`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/custom_detectors/custom_detectors.go#L189): handle different content-type responses seperatly when implement custom detector configurations

### 📦 detectors

- [`azure.go:28`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/azure/azure.go#L28): Azure storage access keys and investigate other types of creds.
- [`freshbooks.go:27`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/freshbooks/freshbooks.go#L27): this domain pattern is too restrictive
- [`generic.go:87`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/generic/generic.go#L87): run them through again?
- [`github_old.go:32`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/github/v1/github_old.go#L32): Oauth2 client_id and client_secret
- [`github.go:39`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/github/v2/github.go#L39): Oauth2 client_id and client_secret
- [`jdbc.go:105`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/jdbc/jdbc.go#L105): specialized redaction
- [`mailgun_test.go:30`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mailgun/mailgun_test.go#L30): Confirm that this is actually an "original token".
- [`mongodb_test.go:103`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mongodb/mongodb_test.go#L103): `%2Ftmp%2Fmongodb-27017.sock` fails with url.Parse.
- [`mongodb_test.go:118`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mongodb/mongodb_test.go#L118): Figure out how to handle `mongodb+srv`. It performs a DNS lookup, which fails if the host doesn't exist.
- [`okta.go:26`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/okta/okta.go#L26): Oauth client secrets
- [`onelogin.go:26`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/onelogin/onelogin.go#L26): Legacy API tokens
- [`ringcentral.go:28`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/ringcentral/ringcentral.go#L28): this domain pattern is too restrictive
- [`signable.go:75`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/signable/signable.go#L75): Skip lock files altogether. (https://github.com/trufflesecurity/trufflehog/issues/1517)
- [`splunkobservabilitytoken_test.go:26`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/splunkobservabilitytoken/splunkobservabilitytoken_test.go#L26): rename
- [`voiceflow.go:28`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/voiceflow/voiceflow.go#L28): This includes Workspace and Legacy Workspace API keys; I haven't validated whether these actually work.

### 📦 engine

- [`engine.go:1184`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/engine/engine.go#L1184): Is this a legitimate use case?

### 📦 gitparse

- [`gitparse.go:533`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/gitparse/gitparse.go#L533): Why do we care about this? It creates empty lines in the diff. If there are no plusLines, it's just newlines.
- [`gitparse.go:666`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/gitparse/gitparse.go#L666): Improve the implementation of this and isMessageEndLine
- [`gitparse.go:951`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/gitparse/gitparse.go#L951): Can this also be `\n\r`?

### 📦 handlers

- [`handlers_test.go:38`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/handlers/handlers_test.go#L38): Embed a zip without making an HTTP request.

### 📦 root

- [`main_test.go:20`](https://github.com/trufflesecurity/trufflehog/blob/main/scripts/todo/main_test.go#L20): Another todo

### 📦 sources

- [`filesystem.go:249`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/filesystem/filesystem.go#L249): Finer grain error tracking of individual chunks.
- [`filesystem.go:252`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/filesystem/filesystem.go#L252): Finer grain error tracking of individual
- [`git.go:327`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L327): Figure out why we skip directories ending in "git".
- [`git.go:743`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L743): Return error.
- [`git.go:763`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L763): Return error.
- [`git.go:787`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L787): Return error.
- [`git.go:1250`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/git.go#L1250): Develop a more robust mechanism to ensure consistent timeout behavior between the command execution
- [`unit.go:43`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/git/unit.go#L43): Is this possible? We should maybe canonicalize
- [`connector_app.go:82`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/connector_app.go#L82): Check rate limit for this call.
- [`github.go:491`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L491): This modifies s.memberCache but it doesn't look like
- [`github.go:639`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L639): set progress complete is being called concurrently with i
- [`github.go:727`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L727): Can this be set once or does it need to be set on every iteration? Is |s.scanOptions| set every clone?
- [`github.go:773`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L773): Will we ever receive a |RateLimitError| when remaining > 0?
- [`github.go:792`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L792): Use exponential backoff instead of static retry time.
- [`github.go:856`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github.go#L856): Check rate limit for this call.
- [`repo.go:119`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/repo.go#L119): It's possible to exclude forks when making the API request rather than doing post-request filtering
- [`gitlab.go:171`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/gitlab/gitlab.go#L171): is it okay if there is no client id and secret? Might be an issue when marshalling config to proto
- [`gitlab.go:813`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/gitlab/gitlab.go#L813): Handle error returned from UnitErr.
- [`huggingface.go:529`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/huggingface/huggingface.go#L529): set progress complete is being called concurrently with i
- [`job_progress.go:197`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/job_progress.go#L197): Comment all this mess. They are mostly implementing JobProgressHook but
- [`job_progress.go:231`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/job_progress.go#L231): Record time.
- [`job_progress.go:235`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/job_progress.go#L235): Record time.
- [`job_progress.go:242`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/job_progress.go#L242): Record time.
- [`job_progress.go:247`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/job_progress.go#L247): Record time.
- [`source_manager.go:348`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/source_manager.go#L348): Maybe switch to using a semaphore.Weighted.

### 📦 tui

- [`contact_enterprise.go:53`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/contact_enterprise/contact_enterprise.go#L53): actually return something
- [`contact_enterprise.go:58`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/contact_enterprise/contact_enterprise.go#L58): actually return something
- [`run_component.go:111`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/run_component.go#L111): actually return something
- [`run_component.go:116`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/run_component.go#L116): actually return something
- [`source_component.go:64`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_component.go#L64): actually return something
- [`source_component.go:69`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_component.go#L69): actually return something
- [`source_configure.go:94`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_configure.go#L94): Use actual messages or something?
- [`source_configure.go:132`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_configure.go#L132): actually return something
- [`source_configure.go:137`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/source_configure.go#L137): actually return something
- [`trufflehog_component.go:59`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/trufflehog_component.go#L59): actually return something
- [`trufflehog_component.go:64`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_configure/trufflehog_component.go#L64): actually return something
- [`source_select.go:164`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_select/source_select.go#L164): actually return something
- [`source_select.go:169`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/source_select/source_select.go#L169): actually return something
- [`view_oss.go:52`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/view_oss/view_oss.go#L52): actually return something
- [`view_oss.go:57`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/view_oss/view_oss.go#L57): actually return something
- [`wizard_intro.go:111`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/pages/wizard_intro/wizard_intro.go#L111): actually return something
- [`tui.go:191`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/tui/tui.go#L191): Print normal help message.

## 🧪 Testing

### 📦 engine

- [`filesystem_integration_test.go:57`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/engine/filesystem_integration_test.go#L57): Test include configuration.

### 📦 root

- [`main_test.go:18`](https://github.com/trufflesecurity/trufflehog/blob/main/scripts/todo/main_test.go#L18): This is a test todo

### 📦 sources

- [`filesystem_test.go:72`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/filesystem/filesystem_test.go#L72): this is kind of bad, if it errors right away we don't see it as a test failure.
- [`github_test.go:82`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/github/github_test.go#L82): test error case
- [`jenkins_integration_test.go:91`](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/sources/jenkins/jenkins_integration_test.go#L91): this is kind of bad, if it errors right away we don't see it as a test failure.

