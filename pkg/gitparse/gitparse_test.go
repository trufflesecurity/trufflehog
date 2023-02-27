package gitparse

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type testCase struct {
	pass     []byte
	fails    [][]byte
	function func([]byte) bool
}

func TestIsIndexLine(t *testing.T) {
	tests := map[string]testCase{
		"indexLine": {
			pass:     []byte("index 1ed6fbee1..aea1e643a 100644"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isIndexLine,
		},
		"modeLine": {
			pass:     []byte("new file mode 100644"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isModeLine,
		},
		"minusFileLine": {
			pass:     []byte("--- a/internal/addrs/move_endpoint_module.go"),
			fails:    [][]byte{[]byte("notcorrect"), []byte("--- s"), []byte("short")},
			function: isMinusFileLine,
		},
		"plusFileLine": {
			pass:     []byte("+++ b/internal/addrs/move_endpoint_module.go"),
			fails:    [][]byte{[]byte("notcorrect"), []byte("+++ s"), []byte("short")},
			function: isPlusFileLine,
		},
		"plusDiffLine": {
			pass:     []byte("+fmt.Println"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isPlusDiffLine,
		},
		"minusDiffLine": {
			pass:     []byte("-fmt.Println"),
			function: isMinusDiffLine,
		},
		"messageLine": {
			pass:     []byte("    committed"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isMessageLine,
		},
		"binaryLine": {
			pass:     []byte("Binary files /dev/null and b/plugin.sig differ"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isBinaryLine,
		},
		"lineNumberLine": {
			pass:     []byte("@@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)"),
			fails:    [][]byte{[]byte("notcorrect")},
			function: isLineNumberDiffLine,
		},
	}

	for name, test := range tests {
		if !test.function(test.pass) {
			t.Errorf("%s: Parser did not recognize correct line.", name)
		}
		for _, fail := range test.fails {
			if test.function(fail) {
				t.Errorf("%s: Parser did not recognize incorrect line.", name)
			}
		}
	}
}

func TestBinaryPathParse(t *testing.T) {
	filename := pathFromBinaryLine([]byte("Binary files /dev/null and b/plugin.sig differ"))
	expected := "plugin.sig"
	if filename != expected {
		t.Errorf("Expected: %s, Got: %s", expected, filename)
	}

}

func TestSingleCommitSingleDiff(t *testing.T) {
	r := bytes.NewReader([]byte(singleCommitSingleDiff))
	commitChan := make(chan Commit)
	parser := NewParser()
	date, _ := time.Parse(parser.dateFormat, "Mon Mar 15 23:27:16 2021 -0700")
	content := bytes.NewBuffer([]byte(singleCommitSingleDiffDiff))
	builder := strings.Builder{}
	builder.Write([]byte(singleCommitSingleDiffMessage))
	expected := []Commit{
		{
			Hash:    "70001020fab32b1fcf2f1f0e5c66424eae649826",
			Author:  "Dustin Decker <humanatcomputer@gmail.com>",
			Date:    date,
			Message: builder,
			Diffs: []Diff{
				{
					PathB:     "aws",
					LineStart: 1,
					Content:   *content,
					IsBinary:  false,
				},
			},
		},
	}
	go func() {
		parser.fromReader(context.TODO(), r, commitChan)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) < i {
			t.Errorf("Commit does not match. Wrong number of commits.")
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match. Got: %v, expected: %v", commit, expected)
		}
		i++
	}
}

func TestMultiCommitContextDiff(t *testing.T) {
	r := bytes.NewReader([]byte(multiCommitContextDiff))
	parser := NewParser()
	commitChan := make(chan Commit)
	dateOne, _ := time.Parse(parser.dateFormat, "Mon Mar 15 23:27:16 2021 -0700")
	dateTwo, _ := time.Parse(parser.dateFormat, "Wed Dec 12 18:19:21 2018 -0800")
	diffOneA := bytes.NewBuffer([]byte(singleCommitContextDiffDiffOneA))
	diffTwoA := bytes.NewBuffer([]byte(singleCommitContextDiffDiffTwoA))
	// diffTwoB := bytes.NewBuffer([]byte(singleCommitContextDiffDiffTwoB))
	messageOne := strings.Builder{}
	messageOne.Write([]byte(singleCommitContextDiffMessageOne))
	messageTwo := strings.Builder{}
	messageTwo.Write([]byte(singleCommitContextDiffMessageTwo))
	expected := []Commit{
		{
			Hash:    "70001020fab32b1fcf2f1f0e5c66424eae649826",
			Author:  "Dustin Decker <humanatcomputer@gmail.com>",
			Date:    dateOne,
			Message: messageOne,
			Diffs: []Diff{
				{
					PathB:     "aws",
					LineStart: 1,
					Content:   *diffOneA,
					IsBinary:  false,
				},
			},
		},
		{
			Hash:    "84e9c75e388ae3e866e121087ea2dd45a71068f2",
			Author:  "Dylan Ayrey <dxa4481@rit.edu>",
			Date:    dateTwo,
			Message: messageTwo,
			Diffs: []Diff{
				{
					PathB:     "aws",
					LineStart: 1,
					Content:   *diffTwoA,
					IsBinary:  false,
				},
			},
		},
	}
	go func() {
		NewParser().fromReader(context.TODO(), r, commitChan)
	}()
	i := 0
	for commit := range commitChan {
		if len(expected) < i {
			t.Errorf("Commit does not match. Wrong number of commits.")
		}

		if !commit.Equal(&expected[i]) {
			t.Errorf("Commit does not match. Got: %v, expected: %v", commit, expected[i])
		}
		i++
	}
}

func TestMaxDiffSize(t *testing.T) {
	parser := NewParser()
	bigBytes := bytes.Buffer{}
	bigBytes.WriteString(singleCommitSingleDiff)
	for i := 0; i <= parser.maxDiffSize/1024+10; i++ {
		bigBytes.WriteString("+")
		for n := 0; n < 1024; n++ {
			bigBytes.Write([]byte("0"))
		}
		bigBytes.WriteString("\n")
	}
	bigReader := bytes.NewReader(bigBytes.Bytes())

	commitChan := make(chan Commit)
	go func() {
		parser.fromReader(context.TODO(), bigReader, commitChan)
	}()

	commit := <-commitChan
	if commit.Diffs[0].Content.Len() > parser.maxDiffSize+1024 {
		t.Errorf("diff did not match MaxDiffSize. Got: %d, expected (max): %d", commit.Diffs[0].Content.Len(), parser.maxDiffSize+1024)
	}

}

func TestMaxCommitSize(t *testing.T) {
	parser := NewParser(WithMaxCommitSize(1))
	commitText := bytes.Buffer{}
	commitText.WriteString(singleCommitMultiDiff)
	commitChan := make(chan Commit)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1)*time.Second)
	defer cancel()
	go func() {
		parser.fromReader(ctx, &commitText, commitChan)
	}()
	commitCount := 0
	for range commitChan {
		commitCount++
	}
	if commitCount != 2 {
		t.Errorf("Commit count does not match. Got: %d, expected: %d", commitCount, 2)
	}

}

const singleCommitSingleDiff = `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
Date:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2
`
const singleCommitSingleDiffMessage = `Update aws
`

const singleCommitSingleDiffDiff = `[default]
aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
aws_secret_access_key = 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
output = json
region = us-east-2
`
const multiCommitContextDiff = `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
Date:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2

commit 84e9c75e388ae3e866e121087ea2dd45a71068f2
Author: Dylan Ayrey <dxa4481@rit.edu>
Date:   Wed Dec 12 18:19:21 2018 -0800

    Update aws again

diff --git a/aws b/aws
index 239b415..2ee133b 100644
--- a/aws
+++ b/aws
@@ -1,5 +1,7 @@
 blah blaj
 
-this is the secret: AKIA2E0A8F3B244C9986
+this is the secret: [Default]
+Access key Id: AKIAILE3JG6KMS3HZGCA
+Secret Access Key: 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
 
-okay thank you bye
\ No newline at end of file
+okay thank you bye
`

const singleCommitMultiDiff = `commit 70001020fab32b1fcf2f1f0e5c66424eae649826 (HEAD -> master, origin/master, origin/HEAD)
Author: Dustin Decker <humanatcomputer@gmail.com>
Date:   Mon Mar 15 23:27:16 2021 -0700

    Update aws

diff --git a/aws b/aws
index 2ee133b..12b4843 100644
--- a/aws
+++ b/aws
@@ -1,7 +1,5 @@
-blah blaj
-
-this is the secret: [Default]
-Access key Id: AKIAILE3JG6KMS3HZGCA
-Secret Access Key: 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
-
-okay thank you bye
+[default]
+aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
+aws_secret_access_key = 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
+output = json
+region = us-east-2

diff --git a/aws b/aws
index 239b415..2ee133b 100644
--- a/aws
+++ b/aws
@@ -1,5 +1,7 @@
 blah blaj
 
-this is the secret: AKIA2E0A8F3B244C9986
+this is the secret: [Default]
+Access key Id: AKIAILE3JG6KMS3HZGCA
+Secret Access Key: 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
 
-okay thank you bye
\ No newline at end of file
+okay thank you bye
`

const singleCommitContextDiffMessageOne = `Update aws
`

const singleCommitContextDiffMessageTwo = `Update aws again
`

const singleCommitContextDiffDiffOneA = `[default]
aws_access_key_id = AKIAXYZDQCEN4B6JSJQI
aws_secret_access_key = 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
output = json
region = us-east-2
`

const singleCommitContextDiffDiffTwoA = `

this is the secret: [Default]
Access key Id: AKIAILE3JG6KMS3HZGCA
Secret Access Key: 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

okay thank you bye
`
