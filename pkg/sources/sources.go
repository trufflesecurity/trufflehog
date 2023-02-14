package sources

import (
	"sync"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// Chunk contains data to be decoded and scanned along with context on where it came from.
type Chunk struct {
	// SourceName is the name of the Source that produced the chunk.
	SourceName string
	// SourceID is the ID of the source that the Chunk originated from.
	SourceID int64
	// SourceType is the type of Source that produced the chunk.
	SourceType sourcespb.SourceType
	// SourceMetadata holds the context of where the Chunk was found.
	SourceMetadata *source_metadatapb.MetaData

	// Data is the data to decode and scan.
	Data []byte
	// Verify specifies whether any secrets in the Chunk should be verified.
	Verify bool
}

// Source defines the interface required to implement a source chunker.
type Source interface {
	// Type returns the source type, used for matching against configuration and jobs.
	Type() sourcespb.SourceType
	// SourceID returns the initialized source ID used for tracking relationships in the DB.
	SourceID() int64
	// JobID returns the initialized job ID used for tracking relationships in the DB.
	JobID() int64
	// Init initializes the source.
	Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error
	// Chunks emits data over a channel that is decoded and scanned for secrets.
	Chunks(ctx context.Context, chunksChan chan *Chunk) error
	// GetProgress is the completion progress (percentage) for Scanned Source.
	GetProgress() *Progress
}

// GitConfig defines the optional configuration for a git source.
type GitConfig struct {
	// RepoPath is the path to the repository to scan.
	RepoPath,
	// HeadRef is the head reference to use to scan from.
	HeadRef,
	// BaseRef is the base reference to use to scan from.
	BaseRef string
	// MaxDepth is the maximum depth to scan the source.
	MaxDepth int
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// GithubConfig defines the optional configuration for a github source.
type GithubConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint,
	// Token is the token to use to authenticate with the source.
	Token string
	// IncludeForks indicates whether to include forks in the scan.
	IncludeForks,
	// IncludeMembers indicates whether to include members in the scan.
	IncludeMembers bool
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
	// Repos is the list of repositories to scan.
	Repos,
	// Orgs is the list of organizations to scan.
	Orgs,
	// ExcludeRepos is a list of repositories to exclude from the scan.
	ExcludeRepos,
	// IncludeRepos is a list of repositories to include in the scan.
	IncludeRepos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// GitlabConfig defines the optional configuration for a gitlab source.
type GitlabConfig struct {
	// Endpoint is the endpoint of the source.
	Endpoint,
	// Token is the token to use to authenticate with the source.
	Token string
	// Repos is the list of repositories to scan.
	Repos []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// FilesystemConfig defines the optional configuration for a filesystem source.
type FilesystemConfig struct {
	// Directories is the list of directories to scan.
	Directories []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// S3Config defines the optional configuration for an S3 source.
type S3Config struct {
	// CloudCred determines whether to use cloud credentials.
	// This can NOT be used with a secret.
	CloudCred bool
	// Key is any key to use to authenticate with the source.
	Key,
	// Secret is any secret to use to authenticate with the source.
	Secret string
	// Buckets is the list of buckets to scan.
	Buckets []string
}

// SyslogConfig defines the optional configuration for a syslog source.
type SyslogConfig struct {
	// Address used to connect to the source.
	Address,
	// Protocol used to connect to the source.
	Protocol,
	// CertPath is the path to the certificate to use to connect to the source.
	CertPath,
	// Format is the format used to connect to the source.
	Format,
	// KeyPath is the path to the key to use to connect to the source.
	KeyPath string
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency int
}

// Progress is used to update job completion progress across sources.
type Progress struct {
	mut               sync.Mutex
	PercentComplete   int64
	Message           string
	EncodedResumeInfo string
	SectionsCompleted int32
	SectionsRemaining int32
}

// SetProgressComplete sets job progress information for a running job based on the highest level objects in the source.
// i is the current iteration in the loop of target scope
// scope should be the len(scopedItems)
// message is the public facing user information about the current progress
// encodedResumeInfo is an optional string representing any information necessary to resume the job if interrupted
func (p *Progress) SetProgressComplete(i, scope int, message, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	p.SectionsCompleted = int32(i)
	p.SectionsRemaining = int32(scope)

	// If the iteration and scope are both 0, completion is 100%.
	if i == 0 && scope == 0 {
		p.PercentComplete = 100
		return
	}

	p.PercentComplete = int64((float64(i) / float64(scope)) * 100)
}

// GetProgress gets job completion percentage for metrics reporting.
func (p *Progress) GetProgress() *Progress {
	p.mut.Lock()
	defer p.mut.Unlock()
	return p
}
