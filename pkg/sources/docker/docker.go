package docker

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	gzip "github.com/klauspost/pgzip"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common/glob"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_DOCKER

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	conn        sourcespb.Docker
	globFilter  *glob.Filter // Filter for excluding files based on glob patterns
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init initializes the source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency

	// Reset metrics for this source at initialization time.
	dockerImagesScanned.WithLabelValues(s.name).Set(0)
	dockerLayersScanned.WithLabelValues(s.name).Set(0)

	if err := anypb.UnmarshalTo(connection, &s.conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	// Extract exclude paths from connection and compile glob patterns
	if paths := s.conn.GetExcludePaths(); len(paths) > 0 {
		var err error
		s.globFilter, err = glob.NewGlobFilter(glob.WithExcludeGlobs(paths...))
		if err != nil {
			return fmt.Errorf("error creating glob filter for exclude paths: %w", err)
		}
	}

	return nil
}

// imageInfo holds information about a Docker image being processed
type imageInfo struct {
	image v1.Image // The image object from go-containerregistry
	base  string   // Base name of the image (without tag/digest)
	tag   string   // Tag or digest of the image
}

// historyEntryInfo represents a single entry from the image's build history
type historyEntryInfo struct {
	index       int        // Position in the history array
	entry       v1.History // The history entry containing build commands
	layerDigest string     // SHA256 digest of the associated layer (empty for empty layers)
	base        string     // Base name of the image
	tag         string     // Tag or digest of the image
}

// layerInfo contains identifying information for a Docker image layer
type layerInfo struct {
	digest v1.Hash // SHA256 digest uniquely identifying the layer
	base   string  // Base name of the image
	tag    string  // Tag or digest of the image
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	ctx = context.WithValues(ctx, "source_type", s.Type(), "source_name", s.name)

	workers := new(errgroup.Group)
	workers.SetLimit(s.concurrency)

	// if namespace is set and no images are specified, fetch all images in that namespace.
	registryNamespace := s.conn.GetNamespace()
	if registryNamespace != "" && len(s.conn.Images) == 0 {
		start := time.Now()
		namespaceImages, err := GetNamespaceImages(ctx, registryNamespace, s.conn.GetRegistryToken())
		if err != nil {
			return fmt.Errorf("failed to list namespace: %s images: %w", registryNamespace, err)
		}

		dockerListImagesAPIDuration.WithLabelValues(s.name).Observe(time.Since(start).Seconds())

		s.conn.Images = append(s.conn.Images, namespaceImages...)
	}

	for _, image := range s.conn.GetImages() {
		if common.IsDone(ctx) {
			return nil
		}

		imgInfo, err := s.processImage(ctx, image)
		if err != nil {
			ctx.Logger().Error(err, "error processing image", "image", image)
			continue
		}

		imageCtx := context.WithValues(ctx, "image", imgInfo.base, "tag", imgInfo.tag)

		imageCtx.Logger().V(2).Info("scanning image history")

		layers, err := imgInfo.image.Layers()
		if err != nil {
			imageCtx.Logger().Error(err, "error getting image layers")
			continue
		}

		// Get history entries and associate them with layers
		historyEntries, err := getHistoryEntries(imageCtx, imgInfo, layers)
		if err != nil {
			imageCtx.Logger().Error(err, "error getting image history entries")
			continue
		}

		// Scan each history entry for secrets in build commands
		for _, historyEntry := range historyEntries {
			if err := s.processHistoryEntry(imageCtx, historyEntry, chunksChan); err != nil {
				imageCtx.Logger().Error(err, "error processing history entry")
				continue
			}
			dockerHistoryEntriesScanned.WithLabelValues(s.name).Inc()
		}

		imageCtx.Logger().V(2).Info("scanning image layers")

		// Process each layer concurrently
		for _, layer := range layers {
			workers.Go(func() error {
				if err := s.processLayer(imageCtx, layer, imgInfo, chunksChan); err != nil {
					imageCtx.Logger().Error(err, "error processing layer")
					return nil
				}
				dockerLayersScanned.WithLabelValues(s.name).Inc()

				return nil
			})
		}

		if err := workers.Wait(); err != nil {
			imageCtx.Logger().Error(err, "error processing layers")
			continue
		}

		dockerImagesScanned.WithLabelValues(s.name).Inc()
	}

	return nil
}

// processImage processes an individual image and prepares it for further processing.
// It handles three image source types: remote registry, local daemon, and tarball file.
func (s *Source) processImage(ctx context.Context, image string) (imageInfo, error) {
	ctx.Logger().V(5).Info("Processing individual Image")
	var (
		imgInfo   imageInfo
		imageName name.Reference
		err       error
	)

	remoteOpts, err := s.remoteOpts()
	if err != nil {
		return imgInfo, err
	}

	const filePrefix = "file://"
	const dockerPrefix = "docker://"

	// Handle tarball file images
	if image, ok := strings.CutPrefix(image, filePrefix); ok {
		imgInfo.base = image
		imgInfo.image, err = tarball.ImageFromPath(image, nil)
		if err != nil {
			return imgInfo, err
		}
		// Handle local Docker daemon images
	} else if image, ok := strings.CutPrefix(image, dockerPrefix); ok {
		imgInfo, imageName, err = s.extractImageNameTagDigest(image)
		if err != nil {
			return imgInfo, err
		}
		imgInfo.image, err = daemon.Image(imageName)
		if err != nil {
			return imgInfo, err
		}
		// Handle remote registry images (default)
	} else {
		imgInfo, imageName, err = s.extractImageNameTagDigest(image)
		if err != nil {
			return imgInfo, err
		}
		imgInfo.image, err = remote.Image(imageName, remoteOpts...)
		if err != nil {
			return imgInfo, err
		}
	}

	ctx.Logger().WithValues("image", imgInfo.base, "tag", imgInfo.tag).V(2).Info("scanning image")

	return imgInfo, nil
}

// extractImageNameTagDigest parses the provided Docker image string and returns a name.Reference
// representing either the image's tag or digest, and any error encountered during parsing.
func (*Source) extractImageNameTagDigest(image string) (imageInfo, name.Reference, error) {
	var (
		hasDigest bool
		imgInfo   imageInfo
		imgName   name.Reference
		err       error
	)
	imgInfo.base, imgInfo.tag, hasDigest = baseAndTagFromImage(image)

	// Parse as digest reference (e.g., nginx@sha256:abc123...)
	if hasDigest {
		imgName, err = name.NewDigest(image)
		// Parse as tag reference (e.g., nginx:latest)
	} else {
		imgName, err = name.NewTag(image)
	}
	if err != nil {
		return imgInfo, imgName, err
	}

	return imgInfo, imgName, nil
}

// getHistoryEntries collates an image's configuration history together with the
// corresponding layer digests for any non-empty layers.
func getHistoryEntries(ctx context.Context, imgInfo imageInfo, layers []v1.Layer) ([]historyEntryInfo, error) {
	ctx.Logger().V(5).Info("Getting history entries")
	config, err := imgInfo.image.ConfigFile()
	if err != nil {
		return nil, err
	}

	history := config.History
	entries := make([]historyEntryInfo, len(history))

	layerIndex := 0
	for historyIndex, entry := range history {
		e := historyEntryInfo{
			base:  imgInfo.base,
			tag:   imgInfo.tag,
			entry: entry,
			index: historyIndex,
		}

		// Associate with a layer if possible. Some history entries don't create layers (e.g., ENV, LABEL)
		// Failing to associate won't affect scanning, just reduces traceability
		if !entry.EmptyLayer {
			if layerIndex < len(layers) {
				digest, err := layers[layerIndex].Digest()

				if err == nil {
					e.layerDigest = digest.String()
				} else {
					ctx.Logger().Error(err, "cannot associate layer with history entry: layer digest failed",
						"layerIndex", layerIndex, "historyIndex", historyIndex)
				}
			} else {
				ctx.Logger().V(2).Info("cannot associate layer with history entry: no correlated layer exists at this index",
					"layerIndex", layerIndex, "historyIndex", historyIndex)
			}

			layerIndex++
		}

		entries[historyIndex] = e
	}

	return entries, nil
}

// processHistoryEntry processes a history entry from the image configuration metadata.
// It scans the CreatedBy field which contains the command used to create that layer.
func (s *Source) processHistoryEntry(ctx context.Context, historyInfo historyEntryInfo, chunksChan chan *sources.Chunk) error {
	ctx.Logger().V(5).Info("Processing history entries")
	// Create a descriptive identifier for this history entry
	// There's no file name here, so we use a synthetic path
	entryPath := fmt.Sprintf("image-metadata:history:%d:created-by", historyInfo.index)

	chunk := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Docker{
				Docker: &source_metadatapb.Docker{
					File:  entryPath,
					Image: historyInfo.base,
					Tag:   historyInfo.tag,
					Layer: historyInfo.layerDigest,
				},
			},
		},
		Verify: s.verify,
		Data:   []byte(historyInfo.entry.CreatedBy),
	}

	ctx.Logger().V(2).Info("scanning image history entry", "index", historyInfo.index, "layer", historyInfo.layerDigest)

	return common.CancellableWrite(ctx, chunksChan, chunk)
}

// processLayer processes an individual layer of an image.
// It decompresses the layer and extracts all files for scanning.
func (s *Source) processLayer(ctx context.Context, layer v1.Layer, imgInfo imageInfo, chunksChan chan *sources.Chunk) error {
	ctx.Logger().V(5).Info("Processing layer")

	layerInfo := layerInfo{
		base: imgInfo.base,
		tag:  imgInfo.tag,
	}

	var err error
	layerInfo.digest, err = layer.Digest()
	if err != nil {
		return err
	}

	ctx.Logger().WithValues("layer", layerInfo.digest.String()).V(2).Info("scanning layer")

	rc, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer rc.Close()

	// Configure parallel gzip decompression for better performance
	const (
		defaultBlockSize = 1 << 24 // 16MB blocks
		defaultBlocks    = 8       // Process 8 blocks in parallel
	)

	gzipReader, err := gzip.NewReaderN(rc, defaultBlockSize, defaultBlocks)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	// Layers are tar archives, so we read them as tar files
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		info := chunkProcessingInfo{size: header.Size, name: header.Name, reader: tarReader, layer: layerInfo}
		if err := s.processChunk(ctx, info, chunksChan); err != nil {
			return err
		}
	}

	return nil
}

// chunkProcessingInfo holds information needed to process a single file from a layer
type chunkProcessingInfo struct {
	size   int64     // Size of the file in bytes
	name   string    // Full path of the file within the layer
	reader io.Reader // Reader for the file contents
	layer  layerInfo // Information about the layer this file belongs to
}

// processChunk processes an individual chunk of a layer.
// It applies file size limits and exclusion patterns before scanning.
func (s *Source) processChunk(ctx context.Context, info chunkProcessingInfo, chunksChan chan *sources.Chunk) error {
	// Skip files that are too large to avoid memory issues
	const filesizeLimitBytes int64 = 50 * 1024 * 1024 // 50MB
	if info.size > filesizeLimitBytes {
		ctx.Logger().V(2).Info("skipping file: size exceeds max allowed", "file", info.name, "size", info.size, "limit", filesizeLimitBytes)
		return nil
	}

	// Check if the file matches any exclude patterns
	filePath := "/" + info.name
	if s.isExcluded(ctx, filePath) {
		return nil
	}

	// Read the file in chunks to handle large files efficiently
	chunkReader := sources.NewChunkReader(sources.WithFileSize(int(info.size)))
	chunkResChan := chunkReader(ctx, info.reader)

	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk.")
			continue
		}

		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Docker{
					Docker: &source_metadatapb.Docker{
						File:  "/" + info.name,
						Image: info.layer.base,
						Tag:   info.layer.tag,
						Layer: info.layer.digest.String(),
					},
				},
			},
			Verify: s.verify,
		}
		chunk.Data = data.Bytes()

		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

// isExcluded checks if a given filePath should be excluded based on the configured glob patterns.
func (s *Source) isExcluded(ctx context.Context, filePath string) bool {
	if s.globFilter == nil {
		return false // No filter configured, so nothing is excluded
	}

	// ShouldInclude returns true if the file should be scanned (not excluded)
	// If it returns false, the file matches an exclude pattern
	isIncluded := s.globFilter.ShouldInclude(filePath)

	if !isIncluded {
		ctx.Logger().V(2).Info("skipping file: matches an exclude pattern", "file", filePath, "configured_exclude_paths", s.conn.GetExcludePaths())
	}
	return !isIncluded
}

// remoteOpts configures the options for fetching images from remote registries.
// It sets up HTTP transport and authentication based on the connection configuration.
func (s *Source) remoteOpts() ([]remote.Option, error) {
	// Configure HTTP transport with reasonable timeouts and connection pooling
	defaultTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          s.concurrency * 4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   s.concurrency * 2,
	}

	var opts []remote.Option
	opts = append(opts, remote.WithTransport(common.NewInstrumentedTransport(common.NewCustomTransport(defaultTransport))))

	// Configure authentication based on credential type
	switch s.conn.GetCredential().(type) {
	case *sourcespb.Docker_Unauthenticated:
		return nil, nil
	case *sourcespb.Docker_BasicAuth:
		opts = append(opts, remote.WithAuth(&authn.Basic{
			Username: s.conn.GetBasicAuth().GetUsername(),
			Password: s.conn.GetBasicAuth().GetPassword(),
		}))
	case *sourcespb.Docker_BearerToken:
		opts = append(opts, remote.WithAuth(&authn.Bearer{
			Token: s.conn.GetBearerToken(),
		}))
	case *sourcespb.Docker_DockerKeychain:
		// Use credentials from ~/.docker/config.json
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	default:
		return nil, fmt.Errorf("unknown credential type: %T", s.conn.Credential)
	}

	return opts, nil
}

func GetNamespaceImages(ctx context.Context, namespace, registryToken string) ([]string, error) {
	ctx.Logger().V(5).Info("Getting namespace images")

	registry := MakeRegistryFromNamespace(namespace)

	// attach the registry authentication token, if one is available.
	if registryToken != "" {
		registry.WithRegistryToken(registryToken)
	}

	ctx.Logger().Info(fmt.Sprintf("using registry: %s", registry.Name()))

	namespaceImages, err := registry.ListImages(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespace images: %w", err)
	}

	ctx.Logger().Info(fmt.Sprintf("namespace: %s has %d images", namespace, len(namespaceImages)))

	return namespaceImages, nil
}

// baseAndTagFromImage extracts the base name and tag/digest from an image reference string.
// It handles both digest-based references (image@sha256:...) and tag-based references (image:tag).
func baseAndTagFromImage(image string) (base, tag string, hasDigest bool) {
	if base, tag, hasDigest = extractDigest(image); hasDigest {
		return base, tag, true
	}

	base, tag = extractTagOrUseDefault(image)
	return base, tag, false
}

// extractDigest tries to split the image string on the digest delimiter (@).
// If successful, it means the image has a digest reference.
func extractDigest(image string) (base, tag string, hasDigest bool) {
	const digestDelim = "@"

	if parts := strings.SplitN(image, digestDelim, 2); len(parts) > 1 {
		return parts[0], parts[1], true
	}
	return "", "", false
}

// extractTagOrUseDefault extracts the tag from the image string.
// If no tag is found, it defaults to "latest".
func extractTagOrUseDefault(image string) (base, tag string) {
	const (
		tagDelim     = ":"
		regRepoDelim = "/"
	)

	parts := strings.Split(image, tagDelim)

	// Check if the last part is a tag (not a hostname with port)
	// We use a weak validation: if it contains "/" it's likely part of a registry hostname
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], regRepoDelim) {
		return strings.Join(parts[:len(parts)-1], tagDelim), parts[len(parts)-1]
	}
	return image, "latest"
}
