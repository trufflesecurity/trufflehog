package elasticsearch

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
	// Search{"index", 0, 15, ""}
	// Search{"index", 5, 20, ""}
	// Search{"index2", 0, 9, ""}
	uows := DistributeDocumentScans(2, indices, "")

	assert.Equal(t, 2, len(uows))

	assert.Equal(t, 14, uows[0].MaxDocumentCount)
	assert.Equal(t, 14, uows[0].DocumentCount)
	assert.Equal(t, 1, len(uows[0].DocumentSearches))

	assert.Equal(t, "index", uows[0].DocumentSearches[0].Name)
	assert.Equal(t, 0, uows[0].DocumentSearches[0].Offset)
	assert.Equal(t, 14, uows[0].DocumentSearches[0].DocumentCount)

	assert.Equal(t, 15, uows[1].MaxDocumentCount)
	assert.Equal(t, 15, uows[1].DocumentCount)
	assert.Equal(t, 2, len(uows[1].DocumentSearches))

	assert.Equal(t, "index", uows[1].DocumentSearches[0].Name)
	assert.Equal(t, 14, uows[1].DocumentSearches[0].Offset)
	assert.Equal(t, 6, uows[1].DocumentSearches[0].DocumentCount)

	assert.Equal(t, "index2", uows[1].DocumentSearches[1].Name)
	assert.Equal(t, 0, uows[1].DocumentSearches[1].Offset)
	assert.Equal(t, 9, uows[1].DocumentSearches[1].DocumentCount)
}

func TestSource_AddSearch(t *testing.T) {
	index := Index{Name: "index1", PrimaryShards: []int{1, 4, 3}, DocumentCount: 20}
	index2 := Index{Name: "index2", PrimaryShards: []int{1, 2, 8}, DocumentCount: 10}
	index3 := Index{Name: "index3", PrimaryShards: []int{9, 7, 5}, DocumentCount: 0}

	uow := NewUnitOfWork(10)

	// Does filling up a UOW with a larger index work?
	offset := uow.AddSearch(index, 0, "")
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.DocumentSearches))
	assert.Equal(t, index.Name, uow.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentSearches[0].DocumentCount)

	// Does trying to add another range into a full UOW leave it unchanged?
	offset2 := uow.AddSearch(index2, 0, "")
	assert.Equal(t, 0, offset2)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.DocumentSearches))
	assert.Equal(t, index.Name, uow.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentSearches[0].DocumentCount)

	// Does trying to add an index with no documents leave it unchanged?
	offset += uow.AddSearch(index3, 0, "")
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.MaxDocumentCount)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentCount)
	assert.Equal(t, 1, len(uow.DocumentSearches))
	assert.Equal(t, index.Name, uow.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[0].Offset)
	assert.Equal(t, uow.MaxDocumentCount, uow.DocumentSearches[0].DocumentCount)

	// Does filling up another UOW with a larger index work?
	uow2 := NewUnitOfWork(9)

	offset += uow2.AddSearch(index, offset, "")
	assert.Equal(t, 19, offset)
	assert.Equal(t, 9, uow2.MaxDocumentCount)
	assert.Equal(t, uow2.MaxDocumentCount, uow2.DocumentCount)
	assert.Equal(t, 1, len(uow2.DocumentSearches))
	assert.Equal(t, index.Name, uow2.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow2.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 10, uow2.DocumentSearches[0].Offset)
	assert.Equal(t, uow2.MaxDocumentCount, uow2.DocumentSearches[0].DocumentCount)

	// Does finishing off an index into a UOW with room to spare work?
	uow3 := NewUnitOfWork(9)

	offset += uow3.AddSearch(index, offset, "")
	assert.Equal(t, 20, offset)
	assert.Equal(t, 9, uow3.MaxDocumentCount)
	assert.Equal(t, 1, uow3.DocumentCount)
	assert.Equal(t, 1, len(uow3.DocumentSearches))
	assert.Equal(t, index.Name, uow3.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow3.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 19, uow3.DocumentSearches[0].Offset)
	assert.Equal(t, 1, uow3.DocumentSearches[0].DocumentCount)

	uow = NewUnitOfWork(21)

	// Does adding an empty range into a new UOW leave it unchanged?
	offset = uow.AddSearch(index3, 0, "")
	assert.Equal(t, 0, offset)
	assert.Equal(t, 21, uow.MaxDocumentCount)
	assert.Equal(t, 0, uow.DocumentCount)
	assert.Equal(t, 0, len(uow.DocumentSearches))

	// Does adding a range into a larger UOW work?
	offset = uow.AddSearch(index, 0, "")
	assert.Equal(t, 20, offset)
	assert.Equal(t, 1, len(uow.DocumentSearches))
	assert.Equal(t, index.Name, uow.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[0].Offset)
	assert.Equal(t, 20, uow.DocumentSearches[0].DocumentCount)

	// Does filling up a UOW that already has a range in it work?
	offset = uow.AddSearch(index2, 0, "")
	assert.Equal(t, 1, offset)
	assert.Equal(t, 2, len(uow.DocumentSearches))
	assert.Equal(t, index.Name, uow.DocumentSearches[0].Name)
	assert.Equal(t, index.PrimaryShards, uow.DocumentSearches[0].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[0].Offset)
	assert.Equal(t, 20, uow.DocumentSearches[0].DocumentCount)
	assert.Equal(t, index2.Name, uow.DocumentSearches[1].Name)
	assert.Equal(t, index2.PrimaryShards, uow.DocumentSearches[1].PrimaryShards)
	assert.Equal(t, 0, uow.DocumentSearches[1].Offset)
	assert.Equal(t, 1, uow.DocumentSearches[1].DocumentCount)
}
