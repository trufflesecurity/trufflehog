package sanitizer

import (
	"strings"
)

func UTF8(in string) string {
	return strings.Replace(strings.ToValidUTF8(in, "❗"), "\x00", "", -1)
}
