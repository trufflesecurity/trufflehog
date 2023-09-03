package privatekey

import (
	"bytes"
)

func normalize(in []byte) []byte {
	in = bytes.ReplaceAll(in, []byte(`"`), []byte(""))
	in = bytes.ReplaceAll(in, []byte(`'`), []byte(""))
	in = bytes.ReplaceAll(in, []byte("\t"), []byte(""))
	in = bytes.ReplaceAll(in, []byte(`\t`), []byte(""))
	in = bytes.ReplaceAll(in, []byte(`\\t`), []byte(""))
	in = bytes.ReplaceAll(in, []byte(`\n`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\\r\\n`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\r\n`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte("\r\n"), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\\r`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte("\r"), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\r`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\\n`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\n\n`), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte("\n\n"), []byte("\n"))
	in = bytes.ReplaceAll(in, []byte(`\\`), []byte("\n"))

	cleaned := bytes.Buffer{}
	parts := bytes.Split(in, []byte("\n"))
	for _, line := range parts {
		cleaned.Write(bytes.TrimSpace(line))
		cleaned.WriteByte('\n')
	}
	return cleaned.Bytes()
}
