Please report security issues to security@trufflesec.com and include `trufflehog` in the subject line. If your vulnerability involves SSRF or outbound requests, please see our policy for that specific class of vulnerability below.

## Blind SSRF & Outbound Request Policy
Truffle Security treats blind SSRF (the ability to induce outbound requests without data retrieval) as a hardening opportunity rather than a vulnerability. We do not issue CVEs or formal advisories for reports showing outbound interactions unless they demonstrate a tangible security risk to users.

#### Policy Criteria
**Vulnerability (CVE Issued):** We will issue a CVE if a researcher demonstrates a clear exploit chain. For example:
- Credential Exfiltration: Forcing TruffleHog to send third-party secrets (discovered during a scan) or the host's own environment credentials (e.g., IAM metadata) to an attacker-controlled endpoint.
- Internal Exploitation: Using a blind request to trigger secondary vulnerabilities (e.g. RCE) on restricted internal services configured for defense-in-depth.

**Hardening (No CVE):** We generally will not issue a CVE for:
- Reflected Payloads: Inducing a request to an attacker-controlled URL that was already present in the scanned source code (i.e., the attacker receiving their own data back).
- Basic Outbound Control: Demonstrating control over the request URL, Path, or Body, without demonstrating a path to credential leakage or internal system exploitation.
- Service Probing: Simple open/closed port verification or basic interaction with internal services (e.g., triggering a GET request to a local web server) without a demonstrated compromise of data or system integrity.
- Secondary Vulnerability Dependencies: Where the impact relies entirely on the pre-existing lack of authentication, misconfiguration, or known vulnerabilities of a third-party internal service.

### Submission Guidelines
To help us evaluate your report, please specify:
- Level of Control: Which request components are controllable (Method, Host, Path, Headers, or Body)?
- Secret Context: Can you prove that a legitimate secret (not the attacker's payload) is attached to or contained within the outbound request?
- Target Reach: Can the request reach restricted internal IPs (e.g., 127.0.0.1 or 169.254.169.254)?
- Demonstrated Impact: What is the specific risk to a user or environment beyond a simple DNS/HTTP interaction?
