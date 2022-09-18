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

// Config defines the optional configuration for a source.
type Config struct {
	// Endpoint is the endpoint of the source.
	Endpoint,
	// Repo is the repository to scan.
	Repo,
	// Token is the token to use to authenticate with the source.
	Token,
	// Key is any key to use to authenticate with the source. (ex: S3)
	Key,
	// Secret is any secret to use to authenticate with the source. (ex: S3)
	Secret,
	// Address used to connect to the source. (ex: syslog)
	Address,
	// Protocol used to connect to the source.
	Protocol,
	// CertPath is the path to the certificate to use to connect to the source.
	CertPath,
	// KeyPath is the path to the key to use to connect to the source.
	KeyPath,
	// Format is the format used to connect to the source.
	Format,
	// RepoPath is the path to the repository to scan.
	RepoPath,
	// HeadRef is the head reference to use to scan from.
	HeadRef,
	// BaseRef is the base reference to use to scan from.
	BaseRef string
	// Concurrency is the number of concurrent workers to use to scan the source.
	Concurrency,
	// MaxDepth is the maximum depth to scan the source.
	MaxDepth int
	// IncludeForks indicates whether to include forks in the scan.
	IncludeForks,
	// IncludeMembers indicates whether to include members in the scan.
	IncludeMembers,
	// CloudCred determines whether to use cloud credentials.
	// This can NOT be used with a secret.
	CloudCred bool
	// Repos is the list of repositories to scan.
	Repos,
	// Orgs is the list of organizations to scan.
	Orgs,
	// Buckets is the list of buckets to scan.
	Buckets,
	// Directories is the list of directories to scan.
	Directories []string
	// Filter is the filter to use to scan the source.
	Filter *common.Filter
}

// NewConfig returns a new Config with optional values.
func NewConfig(opts ...func(*Config)) Config {
	c := &Config{}
	for _, opt := range opts {
		opt(c)
	}
	return *c
}

// Counter is a simple monotonically-increasing counter for tracking progress.
// It includes a successCnt that records the number of successful scans.
// It also includes a totalCnt that records the total number of scans.
// This is necessary in order to display the number of concurrent scans
// regardless of whether they are successful or not.
// successCnt is the only field used when calculating the percentage complete.
type Counter struct {
	successCnt, totalCnt uint32
	mu                   sync.Mutex
}

// IncTotal increments the total field of counter and returns the new value.
func (c *Counter) IncTotal() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalCnt++
	return int(c.totalCnt)
}

// IncSuccess increments the success field of counter and returns the new value.
func (c *Counter) IncSuccess() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.successCnt++
	return int(c.successCnt)
}

// Get returns the current successCnt.
func (c *Counter) Get() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.successCnt
}

// Progress is used to update job completion progress across sources.
type Progress struct {
	SectionsCompleted int32
	SectionsRemaining int32
	PercentComplete   int64
	Message           string
	EncodedResumeInfo string
	mut               sync.Mutex
	Counter           Counter
}

// Update sets job progress information for a running job based on the highest level objects in the source.
// scope should be the len(scopedItems)
// message is the public facing user information about the current progress
// encodedResumeInfo is an optional string representing any information necessary to resume the job if interrupted
func (p *Progress) Update(scope int, message, encodedResumeInfo string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	i := p.Counter.Get()

	p.Message = message
	p.EncodedResumeInfo = encodedResumeInfo
	p.SectionsCompleted = int32(i)
	p.SectionsRemaining = int32(scope)

	p.PercentComplete = int64((float64(i) / float64(scope)) * 100)
}

// Complete sets job progress information for a completed job.
func (p *Progress) Complete(msg string) {
	p.mut.Lock()
	defer p.mut.Unlock()

	p.SectionsRemaining = 0
	p.SectionsCompleted = int32(p.Counter.Get())
	p.Message = msg
	p.EncodedResumeInfo = ""
	p.PercentComplete = 100
}

// GetProgress gets job completion percentage for metrics reporting.
func (p *Progress) GetProgress() *Progress {
	p.mut.Lock()
	defer p.mut.Unlock()
	return p
}
