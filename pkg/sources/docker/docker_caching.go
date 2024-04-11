package docker

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// ConnectToLayersDB opens the SQLite database and returns a connection.
func ConnectToLayersDB(dbName string) (*sql.DB, error) {
	conn, err := sql.Open("sqlite3", dbName)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}
	return conn, nil
}

// InitializeLayersDB initializes the SQLite database with the digest table
// Schema: digest (digest TEXT UNIQUE, verified BOOLEAN, unverified_with_error BOOLEAN, completed BOOLEAN)
// It returns an error if encountered
func InitializeLayersDB(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS digest (digest TEXT UNIQUE, verified BOOLEAN, unverified_with_error BOOLEAN, completed BOOLEAN)")
	if err != nil {
		return err
	}
	return nil
}

// InsertReplaceDigest inserts a digest into the database with the fields verified, unverified_with_error, and completed set to false.
// It replaces an existing entry b/c this code will only execute if the existing has "completed=false", in which case we want to restart processing.
// It returns an error if encountered
func InsertReplaceDigest(db *sql.DB, digest string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO digest (digest, verified, unverified_with_error, completed) VALUES (?, ?, ?, ?)", digest, false, false, false)
	if err != nil {
		return err
	}
	return nil
}

// UpdateCompleted updates the completed field of a digest in the database.
// It returns an error if encountered
func UpdateCompleted(db *sql.DB, digest string, completed bool) error {
	// Prepare the SQL statement for update
	_, err := db.Exec("UPDATE digest SET completed = ? WHERE digest = ?", completed, digest)
	if err != nil {
		return err
	}
	return nil
}

// UpdateVerified updates the verified field of a digest in the database.
// It returns an error if encountered
func UpdateVerified(db *sql.DB, digest string, verified bool) error {
	_, err := db.Exec("UPDATE digest SET verified = ? WHERE digest = ?", verified, digest)
	if err != nil {
		return err
	}
	return nil
}

// UpdateUnverified updates the unverified_with_error field of a digest in the database.
// It returns an error if encountered
func UpdateUnverified(db *sql.DB, digest string, unverified bool) error {
	_, err := db.Exec("UPDATE digest SET unverified_with_error = ? WHERE digest = ?", unverified, digest)
	if err != nil {
		return err
	}
	return nil
}

// SkipDockerLayer will return True iff the layer has been scanned before and no secrets were found.
// This function factors in previously unverified secrets that had errors, since they could still be valid.
// It returns an error if encountered
func SkipDockerLayer(db *sql.DB, digest string) (bool, error) {
	rows, err := db.Query("SELECT verified, unverified_with_error FROM digest WHERE digest = ? and completed = true", digest)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if rows.Next() {
		var verified, unverified_with_error bool
		err = rows.Scan(&verified, &unverified_with_error)
		if err != nil {
			return false, err
		}
		if !verified && !unverified_with_error {
			return true, nil
		}
	}
	return false, nil
}
