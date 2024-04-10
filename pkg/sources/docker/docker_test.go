package docker

import (
	"database/sql"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestDockerImageScan(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"trufflesecurity/secrets"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	chunksChan := make(chan *sources.Chunk, 1)
	chunkCounter := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.Equal(t, 1, chunkCounter)
}

func TestDockerImageScanWithDigest(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"trufflesecurity/secrets@sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	chunksChan := make(chan *sources.Chunk, 1)
	chunkCounter := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.Equal(t, 1, chunkCounter)
}

func TestBaseAndTagFromImage(t *testing.T) {
	tests := []struct {
		image      string
		wantBase   string
		wantTag    string
		wantDigest bool
	}{
		{"golang:1.16", "golang", "1.16", false},
		{"golang@sha256:abcdef", "golang", "sha256:abcdef", true},
		{"ghcr.io/golang:1.16", "ghcr.io/golang", "1.16", false},
		{"ghcr.io/golang:nightly", "ghcr.io/golang", "nightly", false},
		{"ghcr.io/golang", "ghcr.io/golang", "latest", false},
		{"ghcr.io/trufflesecurity/secrets", "ghcr.io/trufflesecurity/secrets", "latest", false},
	}

	for _, tt := range tests {
		gotBase, gotTag, gotDigest := baseAndTagFromImage(tt.image)
		if gotBase != tt.wantBase || gotTag != tt.wantTag || gotDigest != tt.wantDigest {
			t.Errorf("baseAndTagFromImage(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.image, gotBase, gotTag, gotDigest, tt.wantBase, tt.wantTag, tt.wantDigest)
		}
	}
}

func TestConnectToLayersDB(t *testing.T) {
	dbName := ":memory:"
	db, err := ConnectToLayersDB(dbName)
	assert.NoError(t, err)
	assert.NotNil(t, db)
	db.Close()
}

func TestInitializeLayersDB(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	_, err = db.Query("SELECT digest, verified, unverified_with_error, completed FROM digest")
	assert.NoError(t, err)
}

func TestAddDigestToLayersDB(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = AddDigestToLayersDB(db, "test-digest")
	assert.NoError(t, err)

	rows, err := db.Query("SELECT verified, unverified_with_error, completed FROM digest WHERE digest = ?", "test-digest")
	assert.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var verified, unverifiedWithError, completed bool
		err = rows.Scan(&verified, &unverifiedWithError, &completed)
		assert.NoError(t, err)
		assert.False(t, verified)
		assert.False(t, unverifiedWithError)
		assert.False(t, completed)
	}
}

func TestReplaceDigestInLayersDB(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")

	_, err = db.Exec("UPDATE digest SET verified = true, unverified_with_error = true, completed = true WHERE digest = ?", "test-digest")
	assert.NoError(t, err)

	err = AddDigestToLayersDB(db, "test-digest")
	assert.NoError(t, err)

	rows, err := db.Query("SELECT verified, unverified_with_error, completed FROM digest WHERE digest = ?", "test-digest")
	assert.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var verified, unverifiedWithError, completed bool
		err = rows.Scan(&verified, &unverifiedWithError, &completed)
		assert.NoError(t, err)
		assert.False(t, verified)
		assert.False(t, unverifiedWithError)
		assert.False(t, completed)
	}
}

func TestUpdateStatusInLayersDB(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	err = UpdateStatusInLayersDB(db, "test-digest", true)
	assert.NoError(t, err)

	rows, err := db.Query("SELECT completed FROM digest WHERE digest = ?", "test-digest")
	assert.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var completed bool
		err = rows.Scan(&completed)
		assert.NoError(t, err)
		assert.True(t, completed)
	}
}

func TestSkipDockerLayerVerified(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	SetVerified(db, "test-digest")
	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerUnverified(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	SetUnverifiedWithError(db, "test-digest")
	UpdateStatusInLayersDB(db, "test-digest", true)
	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerVerifiedAndUnverifiedTrue(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	SetVerified(db, "test-digest")
	SetUnverifiedWithError(db, "test-digest")
	UpdateStatusInLayersDB(db, "test-digest", true)
	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerVerifiedAndUnverifiedFalse(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	UpdateStatusInLayersDB(db, "test-digest", true)
	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.True(t, skipLayer)
}

func TestSkipDockerLayerNoRows(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSetVerified(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	err = SetVerified(db, "test-digest")
	assert.NoError(t, err)

	rows, err := db.Query("SELECT verified FROM digest WHERE digest = ?", "test-digest")
	assert.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var verified bool
		err = rows.Scan(&verified)
		assert.NoError(t, err)
		assert.True(t, verified)
	}
}

func TestSetUnverifiedWithError(t *testing.T) {
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	AddDigestToLayersDB(db, "test-digest")
	err = SetUnverifiedWithError(db, "test-digest")
	assert.NoError(t, err)

	rows, err := db.Query("SELECT unverified_with_error FROM digest WHERE digest = ?", "test-digest")
	assert.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var unverifiedWithError bool
		err = rows.Scan(&unverifiedWithError)
		assert.NoError(t, err)
		assert.True(t, unverifiedWithError)
	}
}
