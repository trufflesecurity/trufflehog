package logstash

import (
	"fmt"
	"strings"
)

type IndexDocumentCount struct {
	IndexName     string
	DocumentCount int
}

type IndexDocumentRange struct {
	Offset int
	Limit  int
}

type UnitOfWork struct {
	MaxDocumentCount    int
	DocumentCount       int
	IndexDocumentRanges map[string]IndexDocumentRange
}

func NewUnitOfWork(maxDocumentCount int) UnitOfWork {
	uow := UnitOfWork{MaxDocumentCount: maxDocumentCount}
	uow.IndexDocumentRanges = make(map[string]IndexDocumentRange)

	return uow
}

func (uow *UnitOfWork) String() string {
	b := strings.Builder{}
	b.WriteString("UnitOfWork{")
	rangesWritten := 0
	for indexName, indexDocumentRange := range uow.IndexDocumentRanges {
		if rangesWritten > 0 {
			b.WriteString(", ")
		}
		b.WriteString(fmt.Sprintf(
			"%s: %d-%d",
			indexName,
			indexDocumentRange.Offset,
			indexDocumentRange.Offset+indexDocumentRange.Limit,
		))
		rangesWritten++
	}
	b.WriteString("}")
	return b.String()
}

func (uow *UnitOfWork) AddRange(indexName string, offset, limit int) (int, int) {
	addedDocumentCount := min(uow.MaxDocumentCount-uow.DocumentCount, limit)
	uow.IndexDocumentRanges[indexName] = IndexDocumentRange{
		Offset: offset,
		Limit:  addedDocumentCount,
	}
	uow.DocumentCount += addedDocumentCount

	return offset + addedDocumentCount, limit - addedDocumentCount
}

func DistributeDocumentScans(
	maxUnits int,
	indexDocumentCounts []IndexDocumentCount,
) []UnitOfWork {
	totalDocumentCount := 0

	for _, idc := range indexDocumentCounts {
		totalDocumentCount += idc.DocumentCount
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
	for _, indexDocumentCount := range indexDocumentCounts {
		// Skip empty indices
		if indexDocumentCount.DocumentCount == 0 {
			continue
		}

		uow := &unitsOfWork[unitOfWorkIndex]

		// Add the indexes documents to the unit of work, returning any spillover
		offset, documentCount := uow.AddRange(
			indexDocumentCount.IndexName,
			0,
			indexDocumentCount.DocumentCount,
		)

		// If there was spillover, it needs to go into the next unit of work, and
		// the next, and the next....
		for documentCount > 0 {
			unitOfWorkIndex++
			uow := &unitsOfWork[unitOfWorkIndex]
			offset, documentCount = uow.AddRange(
				indexDocumentCount.IndexName,
				offset,
				documentCount,
			)
		}
	}

	return unitsOfWork
}
