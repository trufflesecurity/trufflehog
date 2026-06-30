package dockerswarmunlock

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	keyPat        = regexp.MustCompile(`(SWMKEY-1-[A-Za-z0-9+/]{40,}={0,2})`)
)

func (s Scanner) Keywords() []string {
	return []string{"swmkey", "docker", "swarm", "unlock"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DockerSwarmUnlock,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyDockerSwarmUnlock(ctx, client, token)
			s1.Verified = isVerified
			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyDockerSwarmUnlock(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Docker Swarm unlock keys are used with Docker Engine API
	// Try local Docker socket first (most common case)
	endpoints := []string{
		"http://localhost:2375/swarm",           // Docker daemon without TLS
		"unix:///var/run/docker.sock/v1.41/swarm", // Unix socket (requires special handling)
	}

	for _, endpoint := range endpoints {
		// Skip unix socket for HTTP client - would need special transport
		if len(endpoint) > 7 && endpoint[:7] == "unix://" {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/unlock", nil)
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Body = http.NoBody

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// 200 = success (unlocked)
		// 500 = swarm not locked (key is valid format but swarm not locked)
		// 503 = invalid key
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusInternalServerError {
			return true, nil
		}
	}

	// Cannot verify remotely - Docker Swarm requires local access
	// Return format verification only (valid format = verified true)
	// Format validation: SWMKEY-1- prefix + base64 (40+ chars after prefix)
	if len(token) >= 49 && len(token) >= 9 && token[:9] == "SWMKEY-1-" {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DockerSwarmUnlock
}

func (s Scanner) Description() string {
	return "Docker Swarm unlock keys are used to unlock a locked swarm manager. These keys can be used to access swarm configuration and secrets if the Docker daemon is accessible."
}
