package sanitizer

import (
	"strings"
)

func UTF8(in string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(in, "❗"), "\x00", "")
}
