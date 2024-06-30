package engine

import (
	"errors"
	"runtime"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/jenkins"
)

type JenkinsConfig struct {
	Endpoint              string
	Username              string
	Password              string
	Header                string
	InsecureSkipVerifyTLS bool
}

// ScanJenkins scans Jenkins logs.
func (e *Engine) ScanJenkins(ctx context.Context, jenkinsConfig JenkinsConfig) error {
	var connection *sourcespb.Jenkins
	switch {
	case jenkinsConfig.Username != "" && jenkinsConfig.Password != "":
		connection = &sourcespb.Jenkins{
			Credential: &sourcespb.Jenkins_BasicAuth{
				BasicAuth: &credentialspb.BasicAuth{
					Username: jenkinsConfig.Username,
					Password: jenkinsConfig.Password,
				},
			},
		}
	case jenkinsConfig.Header != "":
		splits := strings.Split(jenkinsConfig.Header, ":")
		if len(splits) != 2 {
			return errors.New("invalid header format, expected key: value")
		}
		key := splits[0]
		value := splits[1]

		connection = &sourcespb.Jenkins{
			Credential: &sourcespb.Jenkins_Header{
				Header: &credentialspb.Header{
					Key:   key,
					Value: value,
				},
			},
		}
	default:
		connection = &sourcespb.Jenkins{
			Credential: &sourcespb.Jenkins_Unauthenticated{
				Unauthenticated: &credentialspb.Unauthenticated{},
			},
		}
	}

	connection.Endpoint = jenkinsConfig.Endpoint
	connection.InsecureSkipVerifyTls = jenkinsConfig.InsecureSkipVerifyTLS

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Jenkins connection")
		return err
	}

	sourceName := "trufflehog - Jenkins"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, jenkins.SourceType)

	jenkinsSource := &jenkins.Source{}
	if err := jenkinsSource.Init(ctx, "trufflehog - Jenkins", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, jenkinsSource)
	return err
}
