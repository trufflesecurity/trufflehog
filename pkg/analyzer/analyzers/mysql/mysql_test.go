package mysql

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	mysqlPass = "23201da=b56ca236f3dc6736c0f9afad"
	mysqlHost = "localhost"
	mysqlPort = "3308" // Do not use 3307, as local dev environments can use it for other things

	inactivePass = "inactive"
	inactiveHost = "192.0.2.0"

	defaultPort = "3306"
)

//go:embed expected_output.json
var expectedOutput []byte

func TestAnalyzer_Analyze(t *testing.T) {
	if err := startMysql(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("could not start local mysql: %v w/stderr:\n%s", err, string(exitErr.Stderr))
		} else {
			t.Fatalf("could not start local mysql: %v", err)
		}
	}
	defer stopMysql()

	tests := []struct {
		name             string
		connectionString string
		want             []byte // JSON string
		wantErr          bool
	}{
		{
			name:             "valid Mysql connection",
			connectionString: fmt.Sprintf(`root:%s@%s:%s/mysql`, mysqlPass, mysqlHost, mysqlPort),
			want:             expectedOutput,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyzer{Cfg: &config.Config{}}
			got, err := a.Analyze(context.Background(), map[string]string{"connection_string": tt.connectionString})
			if (err != nil) != tt.wantErr {
				t.Errorf("Analyzer.Analyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// bindings need to be in the same order to be comparable
			sortBindings(got.Bindings)

			// Marshal the actual result to JSON
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("could not marshal got to JSON: %s", err)
			}

			// Parse the expected JSON string
			var wantObj analyzers.AnalyzerResult
			if err := json.Unmarshal(tt.want, &wantObj); err != nil {
				t.Fatalf("could not unmarshal want JSON string: %s", err)
			}

			// bindings need to be in the same order to be comparable
			sortBindings(wantObj.Bindings)

			// Marshal the expected result to JSON (to normalize)
			wantJSON, err := json.Marshal(wantObj)
			if err != nil {
				t.Fatalf("could not marshal want to JSON: %s", err)
			}

			// Compare the JSON strings
			if string(gotJSON) != string(wantJSON) {
				// Pretty-print both JSON strings for easier comparison
				var gotIndented, wantIndented []byte
				gotIndented, err = json.MarshalIndent(got, "", " ")
				if err != nil {
					t.Fatalf("could not marshal got to indented JSON: %s", err)
				}
				wantIndented, err = json.MarshalIndent(wantObj, "", " ")
				if err != nil {
					t.Fatalf("could not marshal want to indented JSON: %s", err)
				}

				t.Errorf("Analyzer.Analyze() = %s, want %s", gotIndented, wantIndented)
			}
		})
	}
}

// Helper function to sort bindings
func sortBindings(bindings []analyzers.Binding) {
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].Resource.Name == bindings[j].Resource.Name {
			return bindings[i].Permission.Value < bindings[j].Permission.Value
		}
		return bindings[i].Resource.Name < bindings[j].Resource.Name
	})
}

var mysqlDockerHash string

func dockerLogLine(hash string, needle string) chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for {
			out, err := exec.Command("docker", "logs", hash).CombinedOutput()
			if err != nil {
				panic(err)
			}
			if strings.Contains(string(out), needle) {
				ch <- struct{}{}
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return ch
}

func startMysql() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", mysqlPort+":"+defaultPort,
		"-e", "MYSQL_ROOT_PASSWORD="+mysqlPass,
		"-d", "mysql",
	)
	fmt.Println(cmd.String())
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	mysqlDockerHash = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(mysqlDockerHash, "MySQL init process done. Ready for start up."):
		return nil
	case <-time.After(30 * time.Second):
		stopMysql()
		return errors.New("timeout waiting for mysql database to be ready")
	}
}

func stopMysql() {
	exec.Command("docker", "kill", mysqlDockerHash).Run()
}
