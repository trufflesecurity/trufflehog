package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/jpillora/overseer/fetcher"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

func Fetcher(version string) fetcher.Interface {
	return &OSS{
		CurrentVersion: version,
	}
}

type OSS struct {
	Interval       time.Duration
	CurrentVersion string
	Updated        bool
}

// Init validates the provided config
func (g *OSS) Init() error {
	// initiate OSS connection
	return nil
}

const url = "https://oss.trufflehog.org/updates"

type FormData struct {
	OS             string
	Arch           string
	CurrentVersion string
	Timezone       string
	Binary         string
}

// Fetch binary from URL via OSS client
func (g *OSS) Fetch() (io.Reader, error) {
	if g.Updated {
		select {} // block until exit
	}
	g.Updated = true

	zone, _ := time.Now().Zone()
	data := &FormData{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		CurrentVersion: version.BuildVersion,
		Timezone:       zone,
		Binary:         "trufflehog",
	}

	dataByte, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(dataByte)
	resp, err := http.Post(url, "application/json", reader)
	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, errors.New("already up to date")
	}

	context.Background().Logger().V(2).Info("fetching trufflehog update")

	newBinBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewReader(newBinBytes)
	switch runtime.GOOS {
	case "windows":
		zipReader, err := zip.NewReader(buffer, int64(len(newBinBytes)))
		if err != nil {
			return nil, errors.Errorf("Failed to read zip archive: %s", err)
		}
		for _, f := range zipReader.File {
			if strings.HasPrefix(f.Name, "trufflehog") {
				return f.Open()
			}
		}
	default:
		gzipReader, err := gzip.NewReader(buffer)
		if err != nil {
			return nil, errors.Errorf("Failed to read gzip archive: %s", err)
		}
		defer gzipReader.Close()
		tarReader := tar.NewReader(gzipReader)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				return nil, errors.New("unable to get update")
			}

			if header.Typeflag == tar.TypeReg {
				if strings.HasPrefix(header.Name, "trufflehog") {
					return tarReader, nil
				}
			}
		}
	}
	return nil, errors.New("unable to get update")
}
