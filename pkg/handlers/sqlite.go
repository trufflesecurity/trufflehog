package handlers

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
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

	go func() {
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
			return
		}
		defer func() {
			// clean up temp file when we're done with it
			_ = tempDb.Close()
			_ = os.Remove(tempDb.Name())
		}()
		_, err = io.Copy(tempDb, input)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error writing temporary sqlite db: %v", ErrProcessingFatal, err),
			}
			return
		}

		// open our temp file as a SQLITE3 db with some nice options to keep us moving along
		conn, err := sql.Open("sqlite", "file:"+tempDb.Name()+"?_busy_timeout=5000&_journal_mode=WAL")
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error opening temporary sqlite database file: %v", ErrProcessingFatal, err),
			}
			return
		}
		defer conn.Close() //nolint:errcheck

		// gets a list of all tables in the database
		tableNameRows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error scanning for table names in database: %v", ErrProcessingFatal, err),
			}
			return
		}
		defer tableNameRows.Close() //nolint:errcheck
		re := regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
		tableNames := []string{}
		for tableNameRows.Next() {
			name := ""
			err = tableNameRows.Scan(&name)
			if err != nil {
				dataOrErrChan <- DataOrErr{
					Err: fmt.Errorf("%w: error scanning table names into slice: %v", ErrProcessingFatal, err),
				}
				return
			}
			tableNames = append(tableNames, re.ReplaceAllString(name, ""))
		}

		for _, table := range tableNames {
			// run our processor function
			err = s.processSqliteTable(ctx, table, conn, dataOrErrChan)
			if err == nil {
				s.metrics.incFilesProcessed()
			}
		}
		s.measureLatencyAndHandleErrors(ctx, start, err, dataOrErrChan)
		ctx.Logger().V(3).Info("SQLite database fully chunked and ready for scanning")
	}()
	return dataOrErrChan
}

func (s *sqliteHandler) processSqliteTable(ctx logContext.Context, table string, conn *sql.DB, dataOrErrChan chan DataOrErr) error {
	colNames := []string{}
	cols, err := conn.Query(`PRAGMA table_info("` + table + `")`) // for some reason calling Columns() raises an error, so we do an actual PRAGMA query
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error getting column names: %v", ErrProcessingWarning, err),
		}
	}
	defer cols.Close() //nolint:errcheck
	for cols.Next() {
		var id, colName, c3, c4, c5, c6 any
		if err := cols.Scan(&id, &colName, &c3, &c4, &c5, &c6); err != nil {

			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error getting column names: %v", ErrProcessingFatal, err),
			}
			return err
		}
		colNames = append(colNames, colName.(string))
	}
	rows, err := conn.Query(`SELECT * from ` + table + `;`)
	if err != nil {
		dataOrErrChan <- DataOrErr{
			Err: fmt.Errorf("%w: error querying table contents: %v", ErrProcessingWarning, err),
		}
	}
	defer rows.Close() //nolint:errcheck
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
		strRow := []string{}
		for i := range rowPtrs {
			strRow = append(strRow, fmt.Sprintf("%v", row[i]))
		}
		strRow = append(strRow, table)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error wrting to temp csv: %v", ErrProcessingWarning, err),
			}
		}
		jsonMap := map[string]any{
			"__table__": table,
		}
		for i, col := range colNames {
			jsonMap[col] = strRow[i]
		}
		buf := bytes.NewBuffer(nil)
		b, err := yaml.Marshal(jsonMap)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error marshlaing row to json: %v", ErrProcessingWarning, err),
			}
		}
		_, err = buf.Write(b)
		if err != nil {
			dataOrErrChan <- DataOrErr{
				Err: fmt.Errorf("%w: error writing bytes to buffer: %v", ErrProcessingWarning, err),
			}
		}
		fileCtx := logContext.WithValues(ctx, "table", table)
		rdr, err := newMimeTypeReader(buf)
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
	return nil
}
