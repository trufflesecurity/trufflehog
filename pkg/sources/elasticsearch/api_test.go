package elasticsearch

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterParams_Query(t *testing.T) {
	t.Run("no query JSON and no timestamp produces an empty query", func(t *testing.T) {
		fp := FilterParams{}

		query, err := fp.Query(time.Time{})
		assert.NoError(t, err)
		assert.Equal(t, map[string]any{}, query["query"])
	})

	t.Run("invalid query JSON returns an error", func(t *testing.T) {
		fp := FilterParams{queryJSON: "not json"}

		_, err := fp.Query(time.Time{})
		assert.Error(t, err)
	})

	t.Run("latest timestamp adds a range clause on @timestamp", func(t *testing.T) {
		fp := FilterParams{}
		latest := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

		query, err := fp.Query(latest)
		assert.NoError(t, err)

		clause, ok := query["query"].(map[string]any)
		assert.True(t, ok)

		rangeClause, ok := clause["range"].(map[string]map[string]string)
		assert.True(t, ok)
		assert.Equal(t, latest.Format(time.RFC3339), rangeClause["@timestamp"]["gte"])
	})

	t.Run("since timestamp is used when latest timestamp is zero", func(t *testing.T) {
		fp := FilterParams{sinceTimestamp: "2024-01-01T00:00:00Z"}

		query, err := fp.Query(time.Time{})
		assert.NoError(t, err)

		clause, ok := query["query"].(map[string]any)
		assert.True(t, ok)

		rangeClause, ok := clause["range"].(map[string]map[string]string)
		assert.True(t, ok)
		assert.Equal(t, "2024-01-01T00:00:00Z", rangeClause["@timestamp"]["gte"])
	})

	t.Run("latest timestamp takes priority over since timestamp", func(t *testing.T) {
		fp := FilterParams{sinceTimestamp: "2024-01-01T00:00:00Z"}
		latest := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

		query, err := fp.Query(latest)
		assert.NoError(t, err)

		clause := query["query"].(map[string]any)
		rangeClause := clause["range"].(map[string]map[string]string)
		assert.Equal(t, latest.Format(time.RFC3339), rangeClause["@timestamp"]["gte"])
	})
}

func TestIndex_DocumentAlreadySeen(t *testing.T) {
	index := NewIndex()

	firstTimestamp := "2024-01-01T00:00:00Z"

	// A document with a newer timestamp than the zero value is treated as new,
	// and becomes the index's latest timestamp. It is not recorded in the
	// seen list, since the list was just reset.
	seen := index.DocumentAlreadySeen(&Document{id: "doc-1", timestamp: firstTimestamp})
	assert.False(t, seen)

	// A second document at the same (not newer) timestamp is treated as new,
	// since the run has not been marked complete yet, and it is recorded in
	// the seen list.
	seen = index.DocumentAlreadySeen(&Document{id: "doc-2", timestamp: firstTimestamp})
	assert.False(t, seen)

	// Once the run completes, the latest timestamp is recorded as the
	// timestamp of the last run.
	index.UpdateLatestTimestampLastRun()

	// A document already recorded in the seen list at that timestamp is now
	// reported as a duplicate.
	seen = index.DocumentAlreadySeen(&Document{id: "doc-2", timestamp: firstTimestamp})
	assert.True(t, seen)

	// A new document ID at that same timestamp is still treated as new.
	seen = index.DocumentAlreadySeen(&Document{id: "doc-3", timestamp: firstTimestamp})
	assert.False(t, seen)

	// A document with an unparsable timestamp is treated as new and does not
	// change index state.
	seen = index.DocumentAlreadySeen(&Document{id: "doc-4", timestamp: "not-a-timestamp"})
	assert.False(t, seen)
}
