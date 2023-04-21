package decoders

import (
	"bytes"
	"encoding/base64"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Base64 struct{}

var (
	b64Charset  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	b64EndChars = "+/="
)

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
			chunk.Data = bytes.ReplaceAll(chunk.Data, []byte(substring), dec)
		}
		return chunk
	}

	return nil
}

func getSubstringsOfCharacterSet(data []byte, charset []byte, threshold int) []string {
	count := 0
	var substrings []string
	letters := bytes.Buffer{}

	if len(data) == 0 {
		return nil
	}

	for _, char := range data {
		if bytes.Contains(charset, []byte{char}) {
			letters.WriteByte(char)
			count++
		} else {
			if count > threshold {
				substrings = appendB64Substring(&letters, substrings)
			}
			letters.Reset()
			count = 0
		}
	}

	if count > threshold && letters.Len() > 0 {
		substrings = appendB64Substring(&letters, substrings)
	}

	return substrings
}

func appendB64Substring(letters *bytes.Buffer, substrings []string) []string {
	substring := bytes.TrimLeft(letters.Bytes(), b64EndChars)

	// handle key=value
	if bytes.Contains(bytes.TrimRight(substring, b64EndChars), []byte("=")) {
		split := bytes.SplitN(substring, []byte("="), 2)
		substrings = append(substrings, string(split[len(split)-1]))
	} else {
		substrings = append(substrings, string(substring))
	}
	return substrings
}
