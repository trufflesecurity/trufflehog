package logstash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSource_DistributeDocumentScans(t *testing.T) {
	indices := []Index{
		Index{Name: "index", PrimaryShards: []int{}, DocumentCount: 20},
		Index{Name: "index2", PrimaryShards: []int{}, DocumentCount: 9},
		Index{Name: "index3", PrimaryShards: []int{}, DocumentCount: 0},
	}

	// Scanning 30 documents with 2 workers should yield 2 UOWs 15 docs each:
	// Range{"index", 0, 15}
	// Range{"index", 5, 20}
	// Range{"index2", 0, 9}
	uows := DistributeDocumentScans(2, indices)

	assert.Equal(t, 2, len(uows))

	assert.Equal(t, 14, uows[0].MaxDocumentCount)
	assert.Equal(t, 14, uows[0].DocumentCount)
	assert.Equal(t, 1, len(uows[0].IndexDocumentRanges))

	assert.Equal(t, "index", uows[0].IndexDocumentRanges[0].Name)
	assert.Equal(t, 0, uows[0].IndexDocumentRanges[0].Offset)
	assert.Equal(t, 14, uows[0].IndexDocumentRanges[0].DocumentCount)

	assert.Equal(t, 15, uows[1].MaxDocumentCount)
	assert.Equal(t, 15, uows[1].DocumentCount)
	assert.Equal(t, 2, len(uows[1].IndexDocumentRanges))

	assert.Equal(t, "index", uows[1].IndexDocumentRanges[0].Name)
	assert.Equal(t, 14, uows[1].IndexDocumentRanges[0].Offset)
	assert.Equal(t, 6, uows[1].IndexDocumentRanges[0].DocumentCount)

	assert.Equal(t, "index2", uows[1].IndexDocumentRanges[1].Name)
	assert.Equal(t, 0, uows[1].IndexDocumentRanges[1].Offset)
	assert.Equal(t, 9, uows[1].IndexDocumentRanges[1].DocumentCount)
}

func TestSource_AddRange(t *testing.T) {
	index := Index{Name: "index1", PrimaryShards: []int{1, 4, 3}, DocumentCount: 20}
	index2 := Index{Name: "index2", PrimaryShards: []int{1, 2, 8}, DocumentCount: 10}
	index3 := Index{Name: "index3", PrimaryShards: []int{9, 7, 5}, DocumentCount: 0}

	uow := NewUnitOfWork(10)

	// Does filling up a UOW with a larger index work?
	offset := uow.AddRange(index, 0)
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.IndexDocumentRanges[0].DocumentCount)

	// Does trying to add another range into a full UOW leave it unchanged?
	offset2 := uow.AddRange(index2, 0)
	assert.Equal(t, 0, offset2)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.IndexDocumentRanges[0].DocumentCount)

	// Does trying to add an index with no documents leave it unchanged?
	offset += uow.AddRange(index3, 0)
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.IndexDocumentRanges[0].DocumentCount)

	// Does filling up another UOW with a larger index work?
	uow2 := NewUnitOfWork(9)

	offset += uow2.AddRange(index, offset)
	assert.Equal(t, 19, offset)
	assert.Equal(t, 9, uow2.MaxDocumentCount)
	assert.Equal(t, uow2.MaxDocumentCount, uow2.DocumentCount)
	assert.Equal(t, 1, len(uow2.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow2.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow2.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 10, uow2.IndexDocumentRanges[0].Offset)
	assert.Equal(t, uow2.MaxDocumentCount, uow2.IndexDocumentRanges[0].DocumentCount)

	// Does finishing off an index into a UOW with room to spare work?
	uow3 := NewUnitOfWork(9)

	offset += uow3.AddRange(index, offset)
	assert.Equal(t, 20, offset)
	assert.Equal(t, 9, uow3.MaxDocumentCount)
	assert.Equal(t, 1, uow3.DocumentCount)
	assert.Equal(t, 1, len(uow3.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow3.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow3.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 19, uow3.IndexDocumentRanges[0].Offset)
	assert.Equal(t, 1, uow3.IndexDocumentRanges[0].DocumentCount)

	uow = NewUnitOfWork(21)

	// Does adding an empty range into a new UOW leave it unchanged?
	offset = uow.AddRange(index3, 0)
	assert.Equal(t, 0, offset)
	assert.Equal(t, 21, uow.MaxDocumentCount)
	assert.Equal(t, 0, uow.DocumentCount)
	assert.Equal(t, 0, len(uow.IndexDocumentRanges))

	// Does adding a range into a larger UOW work?
	offset = uow.AddRange(index, 0)
	assert.Equal(t, 20, offset)
	assert.Equal(t, 1, len(uow.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[0].Offset)
	assert.Equal(t, 20, uow.IndexDocumentRanges[0].DocumentCount)

	// Does filling up a UOW that already has a range in it work?
	offset = uow.AddRange(index2, 0)
	assert.Equal(t, 1, offset)
	assert.Equal(t, 2, len(uow.IndexDocumentRanges))
	assert.Equal(t, index.Name, uow.IndexDocumentRanges[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.IndexDocumentRanges[0].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[0].Offset)
	assert.Equal(t, 20, uow.IndexDocumentRanges[0].DocumentCount)
	assert.Equal(t, index2.Name, uow.IndexDocumentRanges[1].Name)
	assert.Equal(t, index2.PrimaryShards, uow.IndexDocumentRanges[1].PrimaryShards)
	assert.Equal(t, 0, uow.IndexDocumentRanges[1].Offset)
	assert.Equal(t, 1, uow.IndexDocumentRanges[1].DocumentCount)
}
