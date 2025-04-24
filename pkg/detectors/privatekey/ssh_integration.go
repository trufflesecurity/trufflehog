package privatekey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
var githubFingerprints = map[string]string{
	"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s": "RSA",
	"SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ": "DSA - deprecated",
	"SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM": "ECDSA",
	"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU": "ED25519",
}

// https://docs.gitlab.com/ee/user/gitlab_com/index.html#ssh-host-keys-fingerprints
var gitlabFingerprints = map[string]string{
	"SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw": "ECDSA",
	"SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8": "ED25519",
	"SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ": "RSA",
}

func firstResponseFromSSH(ctx context.Context, parsedKey any, username, hostport string) (string, error) {
	signer, err := ssh.NewSignerFromKey(parsedKey)
	if err != nil {
		return "", err
	}

	// Verify the server fingerprint to ensure that there is no MITM replay attack
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			switch hostname {
			case "github.com:22":
				fingerprint := fingerprintSSHPublicKey(key)
				if _, ok := githubFingerprints[fingerprint]; !ok {
					return fmt.Errorf("unknown host fingerprint for github.com, got %s", fingerprint)
				}
			case "gitlab.com:22":
				fingerprint := fingerprintSSHPublicKey(key)
				if _, ok := gitlabFingerprints[fingerprint]; !ok {
					return fmt.Errorf("unknown host fingerprint for gitlab.com, got %s", fingerprint)
				}
			default:
				return errors.New("unknown host in fingerprint db")
			}
			return nil
		},
	}

	client, err := sshDialWithContext(ctx, "tcp", hostport, config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return "", errPermissionDenied
		}
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var output bytes.Buffer
	session.Stderr = &output

	err = session.Shell()
	if err != nil {
		return "", err
	}
	_ = session.Wait()

	return output.String(), err
}

func sshDialWithContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("error dialing %s: %w", addr, err)
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("error creating SSH connection to %s: %w", addr, err)
	}

	client := ssh.NewClient(ncc, chans, reqs)
	return client, nil
}

var errPermissionDenied = errors.New("permission denied")

func VerifyGitHubUser(ctx context.Context, parsedKey any) (*string, error) {
	output, err := firstResponseFromSSH(ctx, parsedKey, "git", "github.com:22")
	if err != nil {
		return nil, err
	}

	if strings.Contains(output, "Permission denied") {
		return nil, errPermissionDenied
	}

	if strings.Contains(output, "successfully authenticated") {
		username := strings.TrimSuffix(strings.Split(output, " ")[1], "!")
		// This hack is because it's probably one of the most widely distributed github keys
		// and a frequent annoyance.
		// It is active at the time of this commit, but the developer is unresponsive.
		if username == "aaron1234567890123" {
			return nil, nil
		}
		return &username, nil
	}

	return nil, nil
}

func VerifyGitLabUser(ctx context.Context, parsedKey any) (*string, error) {
	output, err := firstResponseFromSSH(ctx, parsedKey, "git", "gitlab.com:22")
	if err != nil {
		return nil, err
	}

	if strings.Contains(output, "Permission denied") {
		return nil, errPermissionDenied
	}

	if strings.Contains(output, "Welcome to GitLab") {
		split := strings.Split(output, " ")
		username := strings.TrimPrefix(strings.TrimSuffix(split[len(split)-1], "!"), "@")
		return &username, nil
	}

	return nil, nil
}
