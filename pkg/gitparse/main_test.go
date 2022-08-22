package gitparse

import (
	"fmt"
	"testing"
	"time"

	glgo "github.com/zricethezav/gitleaks/v8/detect/git"
)

func TestMain(t *testing.T) {
	source := "/home/hrich/go/src/github.com/hashicorp/terraform"
	start := time.Now()
	commitChan := BillParser(source)
	for _ = range commitChan {
	}
	fmt.Printf("BillParser took %f seconds.", time.Now().Sub(start).Seconds())
	start = time.Now()
	logOpts := glgo.LogOpts{
		DisableSafeDir: true,
	}
	errChan := make(chan error)
	fileChan, err := glgo.GitLog(source, logOpts, errChan)
	if err != nil {
		//errs(err)
	}
	for _ = range fileChan {
	}
	fmt.Printf("GitLeaksParser took %f seconds.", time.Now().Sub(start).Seconds())
}
