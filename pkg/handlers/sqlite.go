package handlers

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type sqliteHandler struct{ *defaultHandler }

func newSqliteHandler() *sqliteHandler {
	return &sqliteHandler{defaultHandler: newDefaultHandler(sqliteHandlerType)}
}

// HandleFile processes SQLITE databases.
// It returns a channel of DataorErr that will receive either file data
// or errors encountered during processing.
//
// Fatal errors that will terminate processing include:
// - Context cancellation or deadline exceeded
// - Errors reading or uncompressing the RPM file
// - Panics during processing (wrapped as ErrProcessingFatal)
//
// Non-fatal errors that will be reported but allow processing to continue include:
// - Errors processing individual files within the RPM archive (wrapped as ErrProcessingWarning)
//
// This implementation was heavily inspired by the RPM Handler and github.com/joho/sqltocsv (MIT)
func (s *sqliteHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)
	defer close(dataOrErrChan)

	defer func() {
		if r := recover(); r != nil {
			var panicErr error
			if e, ok := r.(error); ok {
				panicErr = e
			} else {
				panicErr = fmt.Errorf("panic occurred: %v", r)
			}
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: panic error: %v", ErrProcessingFatal, panicErr),
			}
		}
	}()

	start := time.Now() // start the clock

	// Reads the file into a temp DB since we dont have access to the original filename or file handler
	tempDb, err := os.CreateTemp("", "truffle-temp.sqlite")
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error creating temporary sqlite db: %v", ErrProcessingFatal, err),
		}
	}
	defer func() {
		// clean up temp file when we're done with it
		_ = tempDb.Close()
		_ = os.Remove(tempDb.Name())
	}()
	buf := bytes.NewBuffer(nil)
	_, err = buf.ReadFrom(input)
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error writing temporary sqlite db: %v", ErrProcessingFatal, err),
		}
	}
	_, err = tempDb.Write(buf.Bytes())
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error writing temporary sqlite db: %v", ErrProcessingFatal, err),
		}
	}

	// open our temp file as a SQLITE3 db with some nice options to keep us moving along
	conn, err := sql.Open("sqlite3", "file:"+tempDb.Name()+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error opening temporary sqlite database file: %v", ErrProcessingFatal, err),
		}
	}
	defer conn.Close() //nolint:errcheck

	// run our processor function
	err = s.processSQLiteDB(ctx, conn, dataOrErrChan)
	if err == nil {
		s.metrics.incFilesProcessed()
	}
	s.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
	return dataOrErrChan

}

func (s *sqliteHandler) processSQLiteDB(ctx logContext.Context, conn *sql.DB, dataOrErrChan chan DataOrErr) error {
	// gets a list of all tables in the database
	tableNameRows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	defer tableNameRows.Close() //nolint:errcheck
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error scanning for table names in database: %v", ErrProcessingFatal, err),
		}
	}
	tableNames := []string{}
	for tableNameRows.Next() {
		name := ""
		err = tableNameRows.Scan(&name)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error scanning table names into slice: %v", ErrProcessingFatal, err),
			}
		}
		tableNames = append(tableNames, name)
	}
	// for each table, get column names and all rows
	for _, table := range tableNames {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			outFile := buffer.NewBuffer()
			// create a new CSV -- we're essentially exporting the db as CSV so the rest of the scanner can easily scan it
			w := csv.NewWriter(outFile)
			colNames := []string{}
			cols, err := conn.Query("PRAGMA table_info(" + table + ")") // for some reason calling Columns() raises an error, so we do an actual PRAGMA query
			for cols.Next() {
				var id, colName, c3, c4, c5, c6 any
				if err := cols.Scan(&id, &colName, &c3, &c4, &c5, &c6); err != nil {

					dataOrErrChan <- DataOrErr{
						Err: fmt.Errorf("%w: error getting column names: %v", ErrProcessingWarning, err),
					}
				}
				colNames = append(colNames, colName.(string))
			}
			if err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error getting column names: %v", ErrProcessingWarning, err),
				}
			}
			colNamesWithTable := append(colNames, "table") // add an extra column for table name for reference later if necessary
			err = w.Write(colNamesWithTable)
			if err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error writing column names: %v", ErrProcessingWarning, err),
				}
			}
			rows, err := conn.Query(`SELECT * from ` + table)
			if err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error querying table contents: %v", ErrProcessingWarning, err),
				}
			}
			for rows.Next() {
				row := make([]any, len(colNames))
				rowPtrs := make([]any, len(colNames))
				for i := range colNames {
					rowPtrs[i] = &row[i]
				}
				if err := rows.Scan(rowPtrs...); err != nil {
					dataOrErrChan <- DataOrErr{
						Err: fmt.Errorf("%w: error scanning row contents: %v", ErrProcessingWarning, err),
					}
				}
				row = append(row, table)
				strRow := []string{}
				for i := range rowPtrs {
					strRow = append(strRow, fmt.Sprintf("%v", row[i]))
				}
				strRow = append(strRow, table)
				err = w.Write(strRow)
				if err != nil {
					dataOrErrChan <- DataOrErr{
						Err: fmt.Errorf("%w: error wrting to temp csv: %v", ErrProcessingWarning, err),
					}
				}
			}
			w.Flush()
			fileCtx := logContext.WithValues(ctx, "table", table)
			rdr, err := newMimeTypeReader(outFile)
			if err != nil {
				return fmt.Errorf("error creating mime-type reader: %w", err)
			}

			// now handle each table in CSV format as you would any other file
			if err := s.handleNonArchiveContent(fileCtx, rdr, dataOrErrChan); err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error processing sqlite database: %v", ErrProcessingWarning, err),
				}
				s.metrics.incErrors()
			}
			s.metrics.incFilesProcessed()
		}
	}
	ctx.Logger().V(3).Info("SQLite database fully chunked and ready for scanning")
	return nil
}
