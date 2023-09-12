package docker

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
func (s *Source) Init(_ context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
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

	return nil
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	workers := new(errgroup.Group)
	workers.SetLimit(s.concurrency)

	scanErrs := sources.NewScanErrors()
	err := s.parseImages(ctx, s.conn.GetImages(), s.conn.GetAllTags(), workers, scanErrs, chunksChan)
	if err != nil {
		return err
	}

	_ = workers.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Error(nil, "scan errors", "errors", scanErrs.String())
	}

	return nil
}

const filePrefix = "file://"

func (s *Source) parseImages(ctx context.Context, images []string, allTags bool, workers *errgroup.Group, scanErrs *sources.ScanErrors, chunksChan chan *sources.Chunk) error {
	remoteOpts, err := s.remoteOpts()
	if err != nil {
		return err
	}

	// Validate images before we start scanning.
	var imageRefs []name.Reference
	for _, image := range images {
		// TODO: Test whether this validates images and fails when expected.
		ref, err := name.ParseReference(image)
		if err != nil {
			return err
		}

		if allTags {
			if strings.HasPrefix(ref.String(), filePrefix) {
				// This isn't supported & should explicitly fail.
				return fmt.Errorf("--all-tags can't be used with a local file:// reference")
			} else if ref.Identifier() != "latest" {
				// Specifying a tag and using --all-tags is mutually exclusive.
				// "latest" is the default tag when none is explicitly specified.
				return fmt.Errorf("tag or digest can't be used with --all-tags (%s)", ref.Name())
			}
		}
		imageRefs = append(imageRefs, ref)
	}

	for _, imgRef := range imageRefs {
		workers.Go(func() error {
			imgCtx := context.WithValues(ctx, "image", imgRef.String())
			if strings.HasPrefix(imgRef.String(), filePrefix) {
				path := strings.TrimPrefix(imgRef.Context().Name(), filePrefix)
				img, err := tarball.ImageFromPath(path, nil)
				if err != nil {
					scanErrs.Add(err)
					return nil
				}

				imgInfo := &imageInfo{
					base:  path,
					image: img,
				}
				err = s.processImage(imgCtx, imgInfo, chunksChan)
				if err != nil {
					scanErrs.Add(err)
					return nil
				}
			} else {
				if allTags {
					// Fetch all tags for the specified image.
					tags, err := remote.List(imgRef.Context(), remoteOpts...)
					if err != nil {
						scanErrs.Add(err)
						return nil
					}

					for _, t := range tags {
						tag := imgRef.Context().Tag(t)
						imgInfo, err := newImageInfo(tag, remoteOpts)
						if err != nil {
							// Skip old v1 images (for now?)
							// https://github.com/google/go-containerregistry/issues/377
							if strings.HasPrefix(err.Error(), "unsupported MediaType: ") {
								imgCtx.Logger().V(0).Error(err, "skipping unsupported v1 image")
								continue
							}

							scanErrs.Add(err)
							return nil
						}

						imgCtx := context.WithValues(ctx, "image", tag.Name())
						err = s.processImage(imgCtx, imgInfo, chunksChan)
						if err != nil {
							scanErrs.Add(err)
							return nil
						}
					}
				} else {
					imgCtx := context.WithValues(ctx, "image", imgRef.Name())
					imgInfo, err := newImageInfo(imgRef, remoteOpts)
					if err != nil {
						scanErrs.Add(err)
						return nil
					}

					err = s.processImage(imgCtx, imgInfo, chunksChan)
					if err != nil {
						scanErrs.Add(err)
						return nil
					}
				}
			}
			return nil
		})
	}
	return nil
}

func newImageInfo(ref name.Reference, remoteOpts []remote.Option) (*imageInfo, error) {
	image, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, err
	}

	info := &imageInfo{
		base:  ref.Context().Name(),
		tag:   ref.Identifier(),
		image: image,
	}
	return info, nil
}

type imageInfo struct {
	image v1.Image
	base  string
	tag   string
}

// processImage processes an individual image and prepares it for further processing.
func (s *Source) processImage(ctx context.Context, imgInfo *imageInfo, chunksChan chan *sources.Chunk) error {
	ctx.Logger().V(0).Info("scanning image")
	layers, err := imgInfo.image.Layers()
	if err != nil {
		return err
	}

	for _, layer := range layers {
		if err := s.processLayer(ctx, imgInfo, layer, chunksChan); err != nil {
			return err
		}
		dockerLayersScanned.WithLabelValues(s.name).Inc()
	}

	dockerImagesScanned.WithLabelValues(s.name).Inc()
	return nil
}

type layerInfo struct {
	digest v1.Hash
	base   string
	tag    string
}

// processLayer processes an individual layer of an image.
func (s *Source) processLayer(ctx context.Context, imgInfo *imageInfo, layer v1.Layer, chunksChan chan *sources.Chunk) error {
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

	gzipReader, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

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

type chunkProcessingInfo struct {
	size   int64
	name   string
	reader io.Reader
	layer  layerInfo
}

// processChunk processes an individual chunk of a layer.
func (s *Source) processChunk(ctx context.Context, info chunkProcessingInfo, chunksChan chan *sources.Chunk) error {
	const filesizeLimitBytes int64 = 50 * 1024 * 1024 // 50MB
	if info.size > filesizeLimitBytes {
		ctx.Logger().V(4).Info("skipping large file", "file", info.name, "size", info.size)
		return nil
	}

	chunkReader := sources.NewChunkReader()
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

func (s *Source) remoteOpts() ([]remote.Option, error) {
	switch s.conn.GetCredential().(type) {
	case *sourcespb.Docker_Unauthenticated:
		return nil, nil
	case *sourcespb.Docker_BasicAuth:
		return []remote.Option{
			remote.WithAuth(&authn.Basic{
				Username: s.conn.GetBasicAuth().GetUsername(),
				Password: s.conn.GetBasicAuth().GetPassword(),
			}),
		}, nil
	case *sourcespb.Docker_BearerToken:
		return []remote.Option{
			remote.WithAuth(&authn.Bearer{
				Token: s.conn.GetBearerToken(),
			}),
		}, nil
	case *sourcespb.Docker_DockerKeychain:
		return []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		}, nil
	default:
		return nil, fmt.Errorf("unknown credential type: %T", s.conn.Credential)
	}
}

func baseAndTagFromImage(image string) (base, tag string, hasDigest bool) {
	if base, tag, hasDigest = extractDigest(image); hasDigest {
		return base, tag, true
	}

	base, tag = extractTagOrUseDefault(image)
	return base, tag, false
}

// extractDigest tries to split the image string on the digest delimiter.
// If successful, it means the image has a digest.
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

	// Check if the last part is not a hostname with a port (for weak validation)
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], regRepoDelim) {
		return strings.Join(parts[:len(parts)-1], tagDelim), parts[len(parts)-1]
	}
	return image, "latest"
}
