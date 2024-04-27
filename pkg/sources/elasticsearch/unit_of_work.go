package elasticsearch

type IndexDocumentRange struct {
	Index
	Offset int
}

type UnitOfWork struct {
	MaxDocumentCount    int
	DocumentCount       int
	IndexDocumentRanges []IndexDocumentRange
}

func NewUnitOfWork(maxDocumentCount int) UnitOfWork {
	uow := UnitOfWork{MaxDocumentCount: maxDocumentCount}
	uow.IndexDocumentRanges = []IndexDocumentRange{}

	return uow
}

func (uow *UnitOfWork) AddRange(index Index, offset int) int {
	indexDocCount := index.DocumentCount - offset
	addedDocumentCount := min(uow.MaxDocumentCount-uow.DocumentCount, indexDocCount)

	if addedDocumentCount > 0 {
		uow.IndexDocumentRanges = append(uow.IndexDocumentRanges, IndexDocumentRange{
			Index: Index{
				Name:          index.Name,
				PrimaryShards: index.PrimaryShards,
				DocumentCount: addedDocumentCount,
			},
			Offset: offset,
		})

		uow.DocumentCount += addedDocumentCount
	}

	return addedDocumentCount
}

func DistributeDocumentScans(maxUnits int, indices []Index) []UnitOfWork {
	totalDocumentCount := 0

	for _, i := range indices {
		totalDocumentCount += i.DocumentCount
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
		offset := uow.AddRange(i, 0)

		// If we've yet to distribute all the documents in the index, go into the
		// next unit of work, and the next, and the next....
		for offset < i.DocumentCount {
			unitOfWorkIndex++
			uow := &unitsOfWork[unitOfWorkIndex]
			offset += uow.AddRange(i, offset)
		}
	}

	return unitsOfWork
}
