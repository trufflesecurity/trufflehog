package decoders

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Base64 struct{}

var (
	b64Charset  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	b64EndChars = "+/="
)

func getSubstringsOfCharacterSet(data []byte, charset []byte, threshold int) []string {
	count := 0
	substrings := []string{}
	letters := strings.Builder{}
	if len(data) == 0 {
		return nil
	}
	for _, char := range string(data) {
		if bytes.ContainsRune(charset, char) {
			letters.WriteRune(char)
			count++
		} else {
			if count > threshold {
				substrings = appendB64Substring(letters, substrings)
			}
			letters.Reset()
			count = 0
		}
	}

	if count > threshold && len(letters.String()) > 0 {
		substrings = appendB64Substring(letters, substrings)
	}

	return substrings
}

func appendB64Substring(letters strings.Builder, substrings []string) []string {

	substring := strings.TrimLeft(letters.String(), b64EndChars)
	// handle key=value
	if strings.Contains(strings.TrimRight(substring, b64EndChars), "=") {
		split := strings.SplitN(substring, "=", 2)
		substrings = append(substrings, split[len(split)-1])
	} else {
		substrings = append(substrings, substring)
	}
	return substrings
}

func (d *Base64) FromChunk(chunk *sources.Chunk) *sources.Chunk {

	encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, b64Charset, 20)
	decodedSubstrings := map[string][]byte{}

	for _, str := range encodedSubstrings {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 {
			decodedSubstrings[str] = dec
		}
	}

	if len(decodedSubstrings) > 0 {
		for substring, dec := range decodedSubstrings {
			chunk.Data = bytes.Replace(chunk.Data, []byte(substring), dec, 1)
		}
		return chunk
	}

	return nil
}
