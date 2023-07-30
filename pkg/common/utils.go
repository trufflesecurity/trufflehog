package common

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/go-logr/logr"
)

func AddStringSliceItem(item string, slice *[]string) {
	for _, i := range *slice {
		if i == item {
			return
		}
	}
	*slice = append(*slice, item)
}

func RemoveStringSliceItem(item string, slice *[]string) {
	for i, listItem := range *slice {
		if item == listItem {
			(*slice)[i] = (*slice)[len(*slice)-1]
			*slice = (*slice)[:len(*slice)-1]
		}
	}
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func BytesEqual(a, b []byte, numBytes int) bool {
	limit := MinInt(numBytes, MinInt(len(a), len(b))-1)
	return bytes.Equal(a[:limit], b[:limit])
}

func ResponseContainsSubstring(reader io.ReadCloser, target string) (bool, error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), target) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// RandomID returns a random string of the given length.
func RandomID(length int) string {
	b := make([]rune, length)
	for i := range b {
		randInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[randInt.Int64()]
	}

	return string(b)
}

// LogFatalFunc returns a log.Fatal style function. Calling the returned
// function will terminate the program without cleanup.
func LogFatalFunc(logger logr.Logger) func(error, string, ...any) {
	return func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}
}
