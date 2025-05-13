package postman

import (
	"archive/zip"
	"io"
	"strings"
)

type PostmanProcessedFile struct {
	Collections  []PostmanCollection
	Environments []PostmanEnvironment
}

// unpackWorkspace unzips the provided zip file and scans the inflated files
// for collections and environments. It populates the CollectionsRaw and
// EnvironmentsRaw fields of the Workspace object.
func unpackWorkspace(workspacePath string) (PostmanProcessedFile, error) {
	var postmanFileReadOutput PostmanProcessedFile
	reader, err := zip.OpenReader(workspacePath)
	if err != nil {
		return postmanFileReadOutput, err
	}
	defer reader.Close()
	for _, file := range reader.File {
		readCloser, err := file.Open()
		if err != nil {
			return postmanFileReadOutput, err
		}
		defer readCloser.Close()
		contents, err := io.ReadAll(readCloser)
		if err != nil {
			return postmanFileReadOutput, err
		}
		if strings.Contains(file.Name, "collection") {
			collection, err := GetCollectionFromJsonBytes(contents)
			if err != nil {
				return PostmanProcessedFile{}, err
			}
			postmanFileReadOutput.Collections = append(postmanFileReadOutput.Collections, collection)
		}
		if strings.Contains(file.Name, "environment") {
			environment, err := GetEnvironmentFromJsonBytes(contents)
			if err != nil {
				return PostmanProcessedFile{}, err
			}
			postmanFileReadOutput.Environments = append(postmanFileReadOutput.Environments, environment)
		}
	}
	return postmanFileReadOutput, nil
}
