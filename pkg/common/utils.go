package common

import (
	"bufio"
	"fmt"
	"io"
	"strings"
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
func ParseResponseForKeywords(reader io.ReadCloser, keywords []string) (bool, error) {
	for _, keyword := range keywords {
		if keyword == "" {
			continue
		}

		found, err := containsSubstring(reader, keyword)

		if err != nil {
			return false, err
		}
		return found, nil
	}

	return false, nil
}

func containsSubstring(reader io.ReadCloser, target string) (bool, error) {
	r := bufio.NewReader(reader)

	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}

		// Check if the current line contains the target substring
		if strings.Contains(line, target) {
			fmt.Println("Found", target, "in response", line)
			return true, nil
		}

		// Break if the reader reached EOF (end of the file)
		if err == io.EOF {
			break
		}
	}

	return false, nil
}
