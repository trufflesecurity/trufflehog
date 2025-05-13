package postman

import (
	"archive/zip"
	"encoding/json"
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
			// read in the collection then scan it
			var collectionJson PostmanCollectionJson
			if err = json.Unmarshal(contents, &collectionJson); err != nil {
				return postmanFileReadOutput, err
			}
			postmanFileReadOutput.Collections = append(postmanFileReadOutput.Collections, collectionJson.GetCollection())
		}
		if strings.Contains(file.Name, "environment") {
			var environmentJson PostmanEnvironmentJson
			if err = json.Unmarshal(contents, &environmentJson); err != nil {
				return postmanFileReadOutput, err
			}
			postmanFileReadOutput.Environments = append(postmanFileReadOutput.Environments, environmentJson.GetEnvironment())
		}
	}
	return postmanFileReadOutput, nil
}
