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
	// Testing ConnectToLayersDB properly connects to an in-memory database.
	dbName := ":memory:"
	db, err := ConnectToLayersDB(dbName)
	assert.NoError(t, err)
	assert.NotNil(t, db)
	db.Close()
}

func TestInitializeLayersDB(t *testing.T) {
	// Testing InitializeLayersDB properly initializes the database with the digest table.
	// Schema: digest (digest TEXT UNIQUE, verified BOOLEAN, unverified_with_error BOOLEAN, completed BOOLEAN)
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	_, err = db.Query("SELECT digest, verified, unverified_with_error, completed FROM digest")
	assert.NoError(t, err)
}

func TestInsertDigest(t *testing.T) {
	// Testing InsertDigest properly inserts a new digest into the database.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
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

func TestReplaceDigest(t *testing.T) {
	// Testing ReplaceDigest properly replaces the digest in the database with existing entry.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	_, err = db.Exec("UPDATE digest SET verified = true, unverified_with_error = true, completed = true WHERE digest = ?", "test-digest")
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
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

func TestUpdateCompleted(t *testing.T) {
	// Testing UpdateCompleted properly updates the completed field of a digest in the database.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateCompleted(db, "test-digest", true)
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

func TestUpdateVerified(t *testing.T) {
	// Testing UpdateVerified properly updates the verified field in the database.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateVerified(db, "test-digest", true)
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

func TestUpdateUnverified(t *testing.T) {
	// Testing UpdateUnverified properly updates unverified_with_error field in the database.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateUnverified(db, "test-digest", true)
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

func TestSkipDockerLayerOnlyVerifiedTrue(t *testing.T) {
	// Testing the case where TruffleHog found a secret in the layer before.
	// (digest = 'test-digest', verified = True, unverified_with_error = false, completed = True)
	// Should return False, since we want the user to see the secret (thus re-scanning required)
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateVerified(db, "test-digest", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "test-digest", true)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerOnlyUnverifiedTrue(t *testing.T) {
	// Testing the case where TruffleHog found a secret in the layer before, but it was unverified with errors.
	// (digest = 'test-digest', verified = False, unverified_with_error = True, completed = True)
	// Should return False, since we want to re-scan the secret.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateUnverified(db, "test-digest", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "test-digest", true)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerVerifiedAndUnverifiedTrue(t *testing.T) {
	// Testing the case where TruffleHog found a verified and unverified_with_error secret in the layer before.
	// (digest = 'test-digest', verified = True, unverified_with_error = True, completed = True)
	// Should return False, since we want the user to see the secret (thus re-scanning required)
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateVerified(db, "test-digest", true)
	assert.NoError(t, err)

	err = UpdateUnverified(db, "test-digest", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "test-digest", true)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerVerifiedAndUnverifiedFalse(t *testing.T) {
	// Testing the case where TruffleHog found no secrets in the layer before. Should be most common case.
	// (digest = 'test-digest', verified = False, unverified_with_error = False, completed = True)
	// Should return True, since we don't want to re-scan the layer.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "test-digest")
	assert.NoError(t, err)

	err = UpdateCompleted(db, "test-digest", true)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.True(t, skipLayer)
}

func TestSkipDockerLayerNoRows(t *testing.T) {
	// Testing the case where the layer has not been scanned before.
	// Should return False, since we want to scan the layer.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.NoError(t, err)
	assert.False(t, skipLayer)
}

func TestSkipDockerLayerError(t *testing.T) {
	// Testing the case where an error occurs while querying the database.
	dbName := ":memory:"
	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	// Close the database to simulate an error when querying.
	db.Close()

	skipLayer, err := SkipDockerLayer(db, "test-digest")
	assert.Error(t, err)
	assert.False(t, skipLayer)
}

func TestDockerScanWithCacheVerifiedSecret(t *testing.T) {
	// Testing the case where TruffleHog found a secret in a layer and we're scanning the same layer with cache enabled.
	// (digest = 'test-digest', verified = True, unverified_with_error = false, completed = True)
	// This should return one secret, since we want to re-scan the layer (and the test image has one secret in that layer).

	dir := t.TempDir()
	dbName := dir + "/test.db"

	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59")
	assert.NoError(t, err)

	err = UpdateVerified(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:  []string{"trufflesecurity/secrets"},
		Cache:   true,
		CacheDb: dbName,
	}

	conn := &anypb.Any{}
	err = conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)

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

func TestDockerScanWithCacheUnverifiedSecret(t *testing.T) {
	// Testing the case where TruffleHog found an unverified (with error) secret in a layer and we're scanning the same layer with cache enabled.
	// (digest = 'test-digest', verified = False, unverified_with_error = True, completed = True)
	// This should return one secret, since we want to re-scan the layer (and the test image has one secret in that layer).

	dir := t.TempDir()
	dbName := dir + "/test.db"

	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59")
	assert.NoError(t, err)

	err = UpdateUnverified(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:  []string{"trufflesecurity/secrets"},
		Cache:   true,
		CacheDb: dbName,
	}

	conn := &anypb.Any{}
	err = conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)

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

func TestDockerScanWithCacheVerifiedAndUnverifiedSecret(t *testing.T) {
	// Testing the case where TruffleHog found an unverified (with error) and verified secret in a layer and we're scanning the same layer with cache enabled.
	// (digest = 'test-digest', verified = True, unverified_with_error = True, completed = True)
	// This should return one secret, since we want to re-scan the layer (and the test image has one secret in that layer).

	dir := t.TempDir()
	dbName := dir + "/test.db"

	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59")
	assert.NoError(t, err)

	err = UpdateUnverified(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	err = UpdateVerified(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	err = UpdateCompleted(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:  []string{"trufflesecurity/secrets"},
		Cache:   true,
		CacheDb: dbName,
	}

	conn := &anypb.Any{}
	err = conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)

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

func TestDockerScanWithCacheVerifiedSecretNotCompleted(t *testing.T) {
	// Testing the case where TruffleHog found a secret in a layer, but completed = false (simulating a layer currently in processing).
	// (digest = 'test-digest', verified = True, unverified_with_error = false, completed = False)
	// We're scanning the same layer with cache enabled. The InsertReplaceDigest function should run, making verified = false.
	// This will restart the layer scan/cache process.
	// This should return one secret, since we want to re-scan the layer (and the test image has one secret in that layer).

	dir := t.TempDir()
	dbName := dir + "/test.db"

	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59")
	assert.NoError(t, err)

	err = UpdateVerified(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:  []string{"trufflesecurity/secrets"},
		Cache:   true,
		CacheDb: dbName,
	}

	conn := &anypb.Any{}
	err = conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)

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

func TestDockerScanWithCacheNoSecrets(t *testing.T) {
	// Testing the case where TruffleHog didn't find a secret and we're scanning the same layer with cache enabled.
	// This will be the most common case.
	// (digest = 'test-digest', verified = False, unverified_with_error = False, completed = True)
	// This should return zero secrets, since we don't want to re-scan the layer.

	dir := t.TempDir()
	dbName := dir + "/test.db"

	db, _ := sql.Open("sqlite3", dbName)
	defer db.Close()

	err := InitializeLayersDB(db)
	assert.NoError(t, err)

	err = InsertReplaceDigest(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59")
	assert.NoError(t, err)

	err = UpdateCompleted(db, "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59", true)
	assert.NoError(t, err)

	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:  []string{"trufflesecurity/secrets"},
		Cache:   true,
		CacheDb: dbName,
	}

	conn := &anypb.Any{}
	err = conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)

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

	assert.Equal(t, 0, chunkCounter)
}
