//go:build detectors && integration
// +build detectors,integration

package ldap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		panic(err)
	}
	os.Exit(code)
}

func runMain(m *testing.M) (int, error) {
	if err := startOpenLDAP(); err != nil {
		return 0, err
	}
	defer stopOpenLDAP()
	return m.Run(), nil
}

func dockerLogLine(hash string, needle string) chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for {
			out, err := exec.Command("docker", "logs", hash).CombinedOutput()
			if err != nil {
				panic(err)
			}
			if strings.Contains(string(out), needle) {
				ch <- struct{}{}
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return ch
}

func TestLdap_Integration_FromChunk(t *testing.T) {
	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found with URI and separate user+password usage, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(`
		ldap://localhost:1389
		binddn="cn=admin,dc=example,dc=org"
		pass="P@55w0rd"`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with URI and separate user+password usage, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(`
		ldap://localhost:1389
		binddn="cn=someuser,dc=example,dc=org"
		pass="P@55w0rd"`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found with IAD lib usage, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`Set ou = dso.OpenDSObject("LDAP://localhost:1389", "cn=admin,dc=example,dc=org", "P@55w0rd", 1)`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with IAD lib usage, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`Set ou = dso.OpenDSObject("LDAP://localhost:1389", "cn=admin,dc=example,dc=org", "P@55w0rd", 1)`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found with IAD lib usage, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(`Set ou = dso.OpenDSObject("LDAP://localhost:1389", "cn=admin,dc=example,dc=org", "invalid", 1)`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "inaccessible host",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(`
		ldap://badhost:1389
		binddn="cn=admin,dc=example,dc=org"
		pass="P@55w0rd"`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_LDAP,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Ldap.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Ldap.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

var containerID string

func startOpenLDAP() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", "1389:1389",
		"-e", "LDAP_ROOT=dc=example,dc=org",
		"-e", "LDAP_ADMIN_USERNAME=admin",
		"-e", "LDAP_ADMIN_PASSWORD=P@55w0rd",
		"-d", "bitnami/openldap:latest",
	)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	containerID = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(containerID, "slapd starting"):
		return nil
	case <-time.After(30 * time.Second):
		stopOpenLDAP()
		return errors.New("timeout waiting for ldap service to be ready")
	}
}

func stopOpenLDAP() {
	exec.Command("docker", "kill", containerID).Run()
}
