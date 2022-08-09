package common

import (
	"bufio"
	"errors"
	"io"

	log "github.com/sirupsen/logrus"
)

const (
	ChunkSize = 10 * 1024
	PeekSize  = 3 * 1024
)

func ChunkReader(r io.Reader) chan []byte {
	chunkChan := make(chan []byte)
	go func() {
		defer close(chunkChan)
		reader := bufio.NewReaderSize(bufio.NewReader(r), ChunkSize)
		for {
			chunk := make([]byte, ChunkSize)
			n, err := reader.Read(chunk)
			if err != nil && !errors.Is(err, io.EOF) {
				log.WithError(err).Error("Error chunking reader.")
			}
			peekData, _ := reader.Peek(PeekSize)
			chunkChan <- append(chunk[:n], peekData...)
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}()
	return chunkChan
}
