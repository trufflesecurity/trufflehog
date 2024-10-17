package elasticsearch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSource_distributeDocumentScans(t *testing.T) {
	indices := Indices{
		indices: []*Index{
			&Index{name: "index", documentCount: 20},
			&Index{name: "index2", documentCount: 9},
			&Index{name: "index3", documentCount: 0},
		},
		filterParams: &FilterParams{},
	}

	t.Run(
		"Distributing 30 documents from 3 indices (1 empty) with 2 workers works",
		func(t *testing.T) {
			uows := distributeDocumentScans(&indices, 2, .9)

			assert.Equal(t, 2, len(uows))

			assert.Equal(t, 14, uows[0].maxDocumentCount)
			assert.Equal(t, 14, uows[0].documentCount)
			assert.Equal(t, 1, len(uows[0].documentSearches))

			assert.Equal(t, "index", uows[0].documentSearches[0].index.name)
			assert.Equal(t, 0, uows[0].documentSearches[0].offset)
			assert.Equal(t, 14, uows[0].documentSearches[0].documentCount)
			assert.Equal(t, 1, uows[0].documentSearches[0].skipCount)

			assert.Equal(t, 15, uows[1].maxDocumentCount)
			assert.Equal(t, 15, uows[1].documentCount)
			assert.Equal(t, 2, len(uows[1].documentSearches))

			assert.Equal(t, "index", uows[1].documentSearches[0].index.name)
			assert.Equal(t, 14, uows[1].documentSearches[0].offset)
			assert.Equal(t, 6, uows[1].documentSearches[0].documentCount)
			assert.Equal(t, 0, uows[1].documentSearches[0].skipCount)

			assert.Equal(t, "index2", uows[1].documentSearches[1].index.name)
			assert.Equal(t, 0, uows[1].documentSearches[1].offset)
			assert.Equal(t, 9, uows[1].documentSearches[1].documentCount)
			assert.Equal(t, 0, uows[1].documentSearches[1].skipCount)
		},
	)
}

func TestSource_addSearch(t *testing.T) {
	index := Index{name: "index1", documentCount: 20}
	index2 := Index{name: "index2", documentCount: 10}
	index3 := Index{name: "index3", documentCount: 0}

	uow := NewUnitOfWork(10)

	// Does filling up a UOW with a larger index work?
	offset := uow.addSearch(&index, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.maxDocumentCount)
	assert.Equal(t, uow.maxDocumentCount, uow.documentCount)
	assert.Equal(t, 1, len(uow.documentSearches))
	assert.Equal(t, index.name, uow.documentSearches[0].index.name)
	assert.Equal(t, 0, uow.documentSearches[0].offset)
	assert.Equal(t, uow.maxDocumentCount, uow.documentSearches[0].documentCount)

	// Does trying to add another range into a full UOW leave it unchanged?
	offset2 := uow.addSearch(&index2, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 0, offset2)
	assert.Equal(t, 10, uow.maxDocumentCount)
	assert.Equal(t, uow.maxDocumentCount, uow.documentCount)
	assert.Equal(t, 1, len(uow.documentSearches))
	assert.Equal(t, index.name, uow.documentSearches[0].index.name)
	assert.Equal(t, 0, uow.documentSearches[0].offset)
	assert.Equal(t, uow.maxDocumentCount, uow.documentSearches[0].documentCount)

	// Does trying to add an index with no documents leave it unchanged?
	offset += uow.addSearch(&index3, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 10, offset)
	assert.Equal(t, 10, uow.maxDocumentCount)
	assert.Equal(t, uow.maxDocumentCount, uow.documentCount)
	assert.Equal(t, 1, len(uow.documentSearches))
	assert.Equal(t, index.name, uow.documentSearches[0].index.name)
	assert.Equal(t, 0, uow.documentSearches[0].offset)
	assert.Equal(t, uow.maxDocumentCount, uow.documentSearches[0].documentCount)

	// Does filling up another UOW with a larger index work?
	uow2 := NewUnitOfWork(9)

	offset += uow2.addSearch(&index, &FilterParams{}, offset, 1.0)
	assert.Equal(t, 19, offset)
	assert.Equal(t, 9, uow2.maxDocumentCount)
	assert.Equal(t, uow2.maxDocumentCount, uow2.documentCount)
	assert.Equal(t, 1, len(uow2.documentSearches))
	assert.Equal(t, index.name, uow2.documentSearches[0].index.name)
	assert.Equal(t, 10, uow2.documentSearches[0].offset)
	assert.Equal(t, uow2.maxDocumentCount, uow2.documentSearches[0].documentCount)

	// Does finishing off an index into a UOW with room to spare work?
	uow3 := NewUnitOfWork(9)

	offset += uow3.addSearch(&index, &FilterParams{}, offset, 1.0)
	assert.Equal(t, 20, offset)
	assert.Equal(t, 9, uow3.maxDocumentCount)
	assert.Equal(t, 1, uow3.documentCount)
	assert.Equal(t, 1, len(uow3.documentSearches))
	assert.Equal(t, index.name, uow3.documentSearches[0].index.name)
	assert.Equal(t, 19, uow3.documentSearches[0].offset)
	assert.Equal(t, 1, uow3.documentSearches[0].documentCount)

	uow = NewUnitOfWork(21)

	// Does adding an empty range into a new UOW leave it unchanged?
	offset = uow.addSearch(&index3, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 0, offset)
	assert.Equal(t, 21, uow.maxDocumentCount)
	assert.Equal(t, 0, uow.documentCount)
	assert.Equal(t, 0, len(uow.documentSearches))

	// Does adding a range into a larger UOW work?
	offset = uow.addSearch(&index, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 20, offset)
	assert.Equal(t, 1, len(uow.documentSearches))
	assert.Equal(t, index.name, uow.documentSearches[0].index.name)
	assert.Equal(t, 0, uow.documentSearches[0].offset)
	assert.Equal(t, 20, uow.documentSearches[0].documentCount)

	// Does filling up a UOW that already has a range in it work?
	offset = uow.addSearch(&index2, &FilterParams{}, 0, 1.0)
	assert.Equal(t, 1, offset)
	assert.Equal(t, 2, len(uow.documentSearches))
	assert.Equal(t, index.name, uow.documentSearches[0].index.name)
	assert.Equal(t, 0, uow.documentSearches[0].offset)
	assert.Equal(t, 20, uow.documentSearches[0].documentCount)
	assert.Equal(t, index2.name, uow.documentSearches[1].index.name)
	assert.Equal(t, 0, uow.documentSearches[1].offset)
	assert.Equal(t, 1, uow.documentSearches[1].documentCount)
}
