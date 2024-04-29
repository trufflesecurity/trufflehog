package elasticsearch

import "fmt"

type DocumentSearch struct {
	Index
	offset       int
	filterParams FilterParams
}

type UnitOfWork struct {
	maxDocumentCount int
	documentCount    int
	documentSearches []DocumentSearch
}

func NewUnitOfWork(maxDocumentCount int) UnitOfWork {
	uow := UnitOfWork{maxDocumentCount: maxDocumentCount}
	uow.documentSearches = []DocumentSearch{}

	return uow
}

func (ds *DocumentSearch) String() string {
	if ds.offset > 0 {
		return fmt.Sprintf("%s [%d:]", ds.name, ds.offset)
	} else {
		return ds.name
	}
}

func (uow *UnitOfWork) AddSearch(
	index Index,
	offset int,
	filterParams FilterParams,
) int {
	indexDocCount := index.documentCount - offset
	addedDocumentCount := min(uow.maxDocumentCount-uow.documentCount, indexDocCount)

	if addedDocumentCount > 0 {
		uow.documentSearches = append(uow.documentSearches, DocumentSearch{
			Index: Index{
				name:          index.name,
				primaryShards: index.primaryShards,
				documentCount: addedDocumentCount,
			},
			offset:       offset,
			filterParams: filterParams,
		})

		uow.documentCount += addedDocumentCount
	}

	return addedDocumentCount
}

func DistributeDocumentScans(
	maxUnits int,
	indices []Index,
	filterParams FilterParams,
) []UnitOfWork {
	totalDocumentCount := 0

	for _, i := range indices {
		totalDocumentCount += i.documentCount
	}

	unitsOfWork := make([]UnitOfWork, maxUnits)
	documentsAssigned := 0
	for i := 0; i < maxUnits; i++ {
		documentCount := totalDocumentCount / maxUnits

		// The total number of documents to process might not be perfectly
		// divisible by the number of workers, so make sure any remaining documents
		// get processed by assigning them to the last worker
		if i == maxUnits-1 {
			documentCount = totalDocumentCount - documentsAssigned
		}

		unitsOfWork[i] = NewUnitOfWork(documentCount)

		documentsAssigned += documentCount
	}

	unitOfWorkIndex := 0
	for _, i := range indices {
		uow := &unitsOfWork[unitOfWorkIndex]
		offset := uow.AddSearch(i, 0, filterParams)

		// If we've yet to distribute all the documents in the index, go into the
		// next unit of work, and the next, and the next....
		for offset < i.documentCount {
			unitOfWorkIndex++
			uow := &unitsOfWork[unitOfWorkIndex]
			offset += uow.AddSearch(i, offset, filterParams)
		}
	}

	return unitsOfWork
}
