package pymysql

import (
	"context"
	"regexp"
	"strings"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(pymysql\.connect\([^)]*)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pymysql"}
}

func findPyMySQLCreds(creds string) (bool) {
    
    DB := ""
    HOST := ""
    PORT := "3306"      // The default port of mysql.
    USERNAME := ""      
    PASSWORD := ""

    // Loop over the parameters and try to find host, port, password and user.
    for _, param := range strings.Split(strings.TrimLeft(creds, "pymysql.connect("), ",") {
        param = strings.TrimSpace(param)
        
        if strings.Contains(param, "host=") {
            HOST = strings.Trim(strings.Trim(param, "host="), "\"")
 
        } else if strings.Contains(param, "port=") {
            PORT = strings.Trim(strings.Trim(param, "port="), "\"")
        
        } else if strings.Contains(param, "db=") {
            DB = strings.Trim(strings.Trim(param, "db="), "\"")
 
        } else if strings.Contains(param, "user=") {
            USERNAME = strings.Trim(strings.Trim(param, "user="), "\"")
 
        } else if strings.Contains(param, "passwd=") {
            PASSWORD = strings.Trim(strings.Trim(param, "passwd="), "\"")
        }
    }
    // At this point, we should have everything we need to make the sql request.
    // Try to connect with database.
    conn := USERNAME + ":" + PASSWORD + "@tcp(" + HOST + ":" + PORT + ")/" + DB
    db, err := sql.Open("mysql", conn)
    if err != nil {
		return false
	}
    // Close the database. 
    defer db.Close()

    // Check if we can ping the database or not
	if err := db.Ping(); err != nil {
		return false
	}

    return true
}

// FromData will find and optionally verify PyMySQL secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

    // Loop over all the matches.
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_PyMySQL,
			Raw:          []byte(resMatch),
            Redacted:     resMatch + `")`,
		}
        
        // Verify if the secrets are valid or not.
		if verify {
            s.Verified = findPyMySQLCreds(resMatch)
		}

		results = append(results, s)
	}

	return results, nil
}
