package postman

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
)

type ArchiveJSON struct {
	Collection  map[string]bool `json:"collection"`
	Environment map[string]bool `json:"environment"`
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func verifyPostmanExportZip(filepath string) ArchiveJSON {
	var archiveData ArchiveJSON

	// Open the ZIP archive.
	r, err := zip.OpenReader(filepath)
	if err != nil {
		fmt.Println("Error opening ZIP file:", err)
		return archiveData
	}
	defer r.Close()

	// Iterate through the files in the ZIP archive.
	for _, file := range r.File {
		if strings.HasSuffix(file.Name, "archive.json") {
			// Open the file within the ZIP archive.
			rc, err := file.Open()
			if err != nil {
				fmt.Println("Error opening archive.json:", err)
				return archiveData
			}
			defer rc.Close()

			// Read the contents of archive.json.
			contents, err := io.ReadAll(rc)
			if err != nil {
				fmt.Println("Error reading archive.json:", err)
				return archiveData
			}

			// Unmarshal the JSON contents into the ArchiveJSON struct.
			if err := json.Unmarshal(contents, &archiveData); err != nil {
				fmt.Println("Error decoding JSON:", err)
				return archiveData
			}

			// Check if the structure matches your requirements.
			return archiveData
		}
	}
	return archiveData
}
