package privatekey

import (
	"strings"
)

func normalize(in string) string {
	in = strings.ReplaceAll(in, `"`, "")
	in = strings.ReplaceAll(in, `'`, "")
	in = strings.ReplaceAll(in, "\t", "")
	in = strings.ReplaceAll(in, `\t`, "")
	in = strings.ReplaceAll(in, `\\t`, "")
	in = strings.ReplaceAll(in, `\n`, "\n")
	in = strings.ReplaceAll(in, `\\r\\n`, "\n")
	in = strings.ReplaceAll(in, `\r\n`, "\n")
	in = strings.ReplaceAll(in, "\r\n", "\n")
	in = strings.ReplaceAll(in, `\\r`, "\n")
	in = strings.ReplaceAll(in, "\r", "\n")
	in = strings.ReplaceAll(in, `\r`, "\n")
	in = strings.ReplaceAll(in, `\\n`, "\n")
	in = strings.ReplaceAll(in, `\n\n`, "\n")
	in = strings.ReplaceAll(in, "\n\n", "\n")
	in = strings.ReplaceAll(in, `\\`, "\n")

	cleaned := strings.Builder{}
	parts := strings.Split(in, "\n")
	for _, line := range parts {
		cleaned.WriteString(strings.TrimSpace(line) + "\n")
	}
	return cleaned.String()
}
