package output

import "fmt"

// extractFileLine walks over the metadata map created by structToMap and
// extracts the file name and line number when present. This logic is shared by
// multiple printers so that they stay consistent.
func extractFileLine(meta map[string]map[string]any) (file string, hasFile bool, line string, lineNum int, hasLine bool) {
	file = "n/a"
	line = "n/a"

	for _, data := range meta {
		for k, v := range data {
			if k == "line" {
				if l, ok := v.(float64); ok {
					lineNum = int(l)
					line = fmt.Sprintf("%d", lineNum)
					hasLine = true
				}
			}
			if k == "file" {
				if filename, ok := v.(string); ok {
					file = filename
					hasFile = true
				}
			}
		}
	}

	return
}
