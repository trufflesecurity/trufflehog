# TruffleHog Custom Detector Setup Guide

This guide will walk you through setting up a custom detector in TruffleHog to identify specific patterns unique to your project. For users of Trufflehog Enterprise, this guide applies to that environment as well.

## Steps to Set Up a Custom Detector

1. **Create a Configuration File**:
   - TruffleHog uses a configuration file, typically named `config.yaml`, to manage custom detector configuration.
   - If this file doesn't exist, create it in your system.

2. **Define the Custom Detector**:
   - Open `config.yaml` with a text editor.
   - Add a new detector under the `detectors` section.

   Here's a template for a custom detector:

   ```yaml
   # config.yaml
   detectors:
     - name: HogTokenDetector
       keywords:
         - hog
       regex:
         token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
       verify:
         - endpoint: http://localhost:8000/
           # 'unsafe' must be set to true if the endpoint uses HTTP
           unsafe: true
           headers:
             - "Authorization: super secret authorization header"
   ```

   **Explanation**:
   - **`name`**: A unique identifier for your custom detector.
   - **`keywords`**: An array of strings that, when found, trigger the regex search. If multiple keywords are specified, the presence of any one of them will initiate the regex search.
   - **`regex`**: Defines the patterns to identify potential secrets. You can specify one or more named regular expressions. For a detection to be successful, each named regex must find a match. Capture groups `()` within these regular expressions are used to extract specific portions of the matched text, enabling the detector to process and report on particular segments of the identified patterns.

   - **`verify`**: An optional section to validate detected secrets. If you want to verify or unverify detected secrets, this section needs to be configured. If not configured, all detected secrets will be marked as unverified. Read [verification server examples](#verification-server-examples)
     - **`successRanges`**: A list of HTTP status codes (or ranges) that indicate the secret is **live** (active). When the verification server responds with a matching status code, the secret is marked as verified. Each entry can be a single code (`"200"`) or an inclusive range (`"200-202"`). If omitted (along with `rotatedRanges`), only `200` is treated as verified (backward compatible).
     - **`rotatedRanges`**: A list of HTTP status codes (or ranges) that indicate the secret has been **rotated** (no longer active). When the verification server responds with a matching status code, the secret is definitively marked as unverified.

     When only one of the two fields is configured, non-matching responses are treated as the opposite state (e.g., if only `successRanges` is set, any response that doesn't match is treated as rotated; if only `rotatedRanges` is set, any non-matching response is treated as live). When both fields are configured and the response matches neither, the result is treated as unknown/inconclusive. If no endpoint returns a response at all (for example a network error or an [auth](#authenticating-verification-requests) failure), the result carries a verification error rather than being reported as simply unverified.

     Since `verify` is optional, Custom Detectors can also be used without a webhook to flag generic hardcoded secrets (e.g. `*.password=`, `*.secret=`) in config files such as `.properties`, `.env`, or `.yaml`. [Here](/examples/generic_config_secrets.yml) is an example config tuned for that use case.

   Here's an example with configurable verification ranges:

   ```yaml
   # config.yaml
   detectors:
     - name: HogTokenDetector
       keywords:
         - hog
       regex:
         token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
       verify:
         - endpoint: http://localhost:8000/
           unsafe: true
           headers:
             - "Authorization: super secret authorization header"
           successRanges:
             - "200"
           rotatedRanges:
             - "401"
             - "403"
   ```

   In this example, a `200` response from the verification server means the secret is live and needs rotation. A `401` or `403` means the secret has been rotated and is no longer active. Any other response is treated as inconclusive.

   #### Authenticating verification requests

   If the verification endpoint sits behind an OAuth2-protected proxy, add an `auth` block. TruffleHog obtains an access token from the identity provider and sends it as `Bearer <token>` on every request to that endpoint's host.

   The only supported grant type is the Resource Owner Password Credentials (ROPC) grant ([RFC 6749 section 4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)), configured under `ropc`. TruffleHog logs in with a service account's username and password plus the OAuth2 client's credentials, and repeats that login whenever the token expires. Other grants, such as client credentials or refresh tokens, are not supported.

   ```yaml
       verify:
         - endpoint: https://verifier.example.com/
           # Must be true if endpoint or tokenEndpoint uses HTTP
           unsafe: false
           auth:
             oauth2:
               tokenEndpoint: https://idp.example.com/oauth2/token
               tokenHeader: X-Proxy-Authorization # optional, defaults to Authorization
               ropc:
                 username: scanner
                 password: scanner-password
                 clientId: trufflehog
                 clientSecret: client-secret # optional
                 scope: verify # optional, space-separated
   ```

   - The token is fetched on first use, reused until shortly before it expires, and never sent to any other host. If the identity provider doesn't say when the token expires, it is treated as valid for 5 minutes.
   - `headers` may not set the `tokenHeader`; the config is rejected at startup if it does.
   - If a token can't be obtained, affected results carry a verification error and the scan continues. Failed logins are retried with backoff (5 seconds, doubling up to 5 minutes) to avoid account lockouts.

   **Other allowed parameters:**
   - **`primary_regex_name`**: This parameter allows you designate the primary regex pattern when multiple regex patterns are defined in the regex section. If a match is found, the match for the designated primary regex will be used to determine the line number. The value must be one of the names specified in the regex section. If not provided, the first regex name in sorted order will be used as the primary regex by default.
   - **`exclude_regexes_capture`**: This parameter allows you to define regex patterns to exclude specific parts of a detected secret. If a match is found within the detected secret, the portion matching this regex is excluded from the result.
   - **`exclude_regexes_match`**: This parameter enables you to define regex patterns to exclude entire matches from being reported as secrets. This applies to the entire matched string, not just the token.
   - **`entropy`**: This parameter is used to assess the randomness of detected strings. High entropy often indicates that a string is a potential secret, such as an API key or password, due to its complexity and unpredictability. It helps in filtering false-positives. While an entropy threshold of `3` can be a starting point, it's essential to adjust this value based on your project's specific requirements and the nature of the data you have.
   - **`exclude_words`**: This parameter allows you to specify a list of words that, if present in a detected string, will cause TruffleHog to ignore that string. This is a substring match and does not enforce word boundaries. It applies only to the token.
   - **`validations`**: This parameter lets you define extra validation rules for each regex specified in the regex option. These rules address limitations of Go's RE2 engine, such as the lack of lookahead support, and are applied after a regex match to help reduce false positives.
   Available validation options:
     - **`contains_digit`**: Ensures the match contains at least one numeric digit (0-9). Useful for API keys or tokens that must include numbers.
     - **`contains_lowercase`**: Ensures the match contains at least one lowercase letter (a-z). Common requirement for passwords and mixed-case tokens.
     - **`contains_uppercase`**: Ensures the match contains at least one uppercase letter (A-Z). Helps validate tokens that follow mixed-case conventions.
     - **`contains_special_char`**: Ensures the match contains at least one special character from the set `!@#$%^&*()_+-=[]{}|;:,.<>?`. Useful for complex passwords or encoded tokens.
    

    [Here](/examples/generic_with_filters.yml) is an example of a custom detector using these parameters. 

3. **Run TruffleHog with the Custom Detector**:
   - Execute TruffleHog, specifying your configuration file:

     ```bash
     trufflehog filesystem <path_to_folder_or_file> --config=<path_to_file>/config.yaml
     ```

   - Replace `<path_to_folder_or_file>` with the path to the directory or file you want to scan, and `<path_to_file>` with the path to your `config.yaml`.
   - TruffleHog will scan the specified file or folder using the custom detector you've defined.

4. **Example**:

   Let's use the template config provided above to search a file.

   Assume you have a file `/tmp/data.txt` with the following content:

   ```text
   // this is a custom example
   this file has some random text and maybe a secret
   hog token: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
   // end of file
   ```

   In this file, the keyword `hog` exists, which will trigger the regex search. The string `pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn` matches the regex pattern, so it should be detected.

   Run the following command:

   ```bash
   trufflehog filesystem /tmp --config=config.yaml
   ```

   The output should be similar to:

   ```
   🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

   Found verified result 🐷🔑
   Detector Type: CustomRegex
   Decoder Type: PLAIN
   Raw result: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
   File: /tmp/data.txt
   Line: 3
   ```

   The `Raw result` contains the matched string. `File` is the file name where secret was detected and `Line` is the exact line in the file where that was found.


## Verification Server Examples
Unless you run a verification server, secrets found by the custom regex detector will be unverified. Here is an example Python and Go implementation of a verification server for the above config.yaml file.

### Python:

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

AUTH_HEADER = 'super secret authorization header'

class Verifier(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        try:
            if self.headers['Authorization'] != AUTH_HEADER:
                self.send_response(401)
                self.end_headers()
                return

            length = int(self.headers['Content-Length'])
            request = json.loads(self.rfile.read(length))
            self.log_message("%s", request)

            if not validateTokens(request['HogTokenDetector']['token']):
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(403)
                self.end_headers()
        except Exception:
            self.send_response(400)
            self.end_headers()

def validateTokens(token):
    return False  # Implement actual validation logic

with HTTPServer(('', 8000), Verifier) as server:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
```

### Go
```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

const authHeader = "super secret authorization header"

type HogTokenDetector struct {
	Token string `json:"token"`
}

type RequestBody struct {
	HogTokenDetector HogTokenDetector `json:"HogTokenDetector"`
}

func validateTokens(token string) bool {
	return false // Implement actual validation logic
}

func verifierHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != authHeader {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var requestBody RequestBody
	if err := json.Unmarshal(body, &requestBody); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("Received Request: %+v", requestBody)

	if validateTokens(requestBody.HogTokenDetector.Token) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	http.HandleFunc("/", verifierHandler)
	serverAddr := ":8000"
	fmt.Printf("Starting server on %s...\n", serverAddr)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
```
