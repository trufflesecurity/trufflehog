package mysql

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jedib0t/go-pretty/text"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/xo/dburl"

	"github.com/fatih/color"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

const (
	// MySQL SSL Modes
	mysql_sslmode                 = "ssl-mode"
	mysql_sslmode_disabled        = "DISABLED"
	mysql_sslmode_preferred       = "PREFERRED"
	mysql_sslmode_required        = "REQUIRED"
	mysql_sslmode_verify_ca       = "VERIFY_CA"
	mysql_sslmode_verify_identity = "VERIFY_IDENTITY"
	//https://github.com/go-sql-driver/mysql/issues/899#issuecomment-443493840

	// MySQL Built-in Databases
	mysql_db_sys      = "sys"
	mysql_db_perf_sch = "performance_schema"
	mysql_db_info_sch = "information_schema"
	mysql_db_mysql    = "mysql"

	mysql_all = "*"
)

type GlobalPrivs struct {
	Privs []string
}

type Database struct {
	Name        string
	Default     bool
	Tables      *[]Table
	Privs       []string
	Routines    *[]Routine
	Nonexistent bool
}

type Table struct {
	Name        string
	Columns     []Column
	Privs       []string
	Nonexistent bool
	Bytes       uint64
}

type Column struct {
	Name  string
	Privs []string
}

type Routine struct {
	Name        string
	Privs       []string
	Nonexistent bool
}

// so CURRENT_USER returns `doadmin@%` and not `doadmin@localhost
// USER() returns `doadmin@localhost`

func AnalyzePermissions(cfg *config.Config, connectionStr string) {

	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	db, err := createConnection(connectionStr)
	if err != nil {
		color.Red("[!] Error connecting to the MySQL database: %s", err)
		return
	}

	defer db.Close()

	// Get the current user
	user, err := getUser(db)
	if err != nil {
		color.Red("[!] Error getting the current user: %s", err)
		return
	}
	color.Green("[+] Successfully connected as user: %s", user)

	// Get all accessible databases
	var databases = make(map[string]*Database, 0)
	err = getDatabases(db, databases)
	if err != nil {
		color.Red("[!] Error getting databases: %s", err)
		return
	}

	//Get all accessible tables
	err = getTables(db, databases)
	if err != nil {
		color.Red("[!] Error getting tables: %s", err)
		return
	}

	// Get all accessible routines
	err = getRoutines(db, databases)
	if err != nil {
		color.Red("[!] Error getting routines: %s", err)
		return
	}

	// Get user grants
	grants, err := getGrants(db)
	if err != nil {
		color.Red("[!] Error getting user grants: %s", err)
		return
	}

	var globalPrivs GlobalPrivs
	// Process user grants
	processGrants(grants, databases, &globalPrivs)

	// Print the results
	printResults(databases, globalPrivs, cfg.ShowAll)

	// Build print function, check data, and then review all of the logic.
	// Then make sure we have an instance of lal of that logic to actually test.

}

func createConnection(connection string) (*sql.DB, error) {
	// Check if the connection string starts with 'mysql://'
	if !strings.HasPrefix(connection, "mysql://") {
		color.Yellow("[i] The connection string should start with 'mysql://'. Adding it for you.")
		connection = "mysql://" + connection
	}

	// Adapt ssl-mode params to Go MySQL driver
	connection, err := fixTLSQueryParam(connection)
	if err != nil {
		return nil, err
	}

	// Parse the connection string
	u, err := dburl.Parse(connection)
	if err != nil {
		return nil, err
	}

	// Connect to the MySQL database
	db, err := sql.Open("mysql", u.DSN)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxLifetime(time.Minute * 5)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	// Check the connection
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			return nil, fmt.Errorf("%s. try adding 'ssl-mode=PREFERRED' to your connection string", err.Error())
		}
		return nil, err
	}

	return db, nil
}

func fixTLSQueryParam(connection string) (string, error) {
	// Parse connection string on "?"
	parsed := strings.Split(connection, "?")

	// Check if has query parms
	if len(parsed) < 2 {
		// Add 10s timeout
		connection += "?timeout=10s"
		return connection, nil
	}

	var error error

	// Split parms
	querySlice := strings.Split(parsed[1], "&")

	// Check if ssl-mode is present
	for i, part := range querySlice {
		if strings.HasPrefix(part, "ssl-mode") {
			mode := strings.Split(part, "=")[1]
			switch mode {
			case mysql_sslmode_disabled:
				querySlice[i] = "tls=false"
			case mysql_sslmode_preferred:
				querySlice[i] = "tls=preferred"
			case mysql_sslmode_required:
				querySlice[i] = "tls=true"
			case mysql_sslmode_verify_ca:
				error = fmt.Errorf("this implementation does not support VERIFY_CA. try removing it or using ssl-mode=REQUIRED")
				// Need to implement --ssl-ca or --ssl-capath
			case mysql_sslmode_verify_identity:
				error = fmt.Errorf("this implementation does not support VERIFY_IDENTITY. try removing it or using ssl-mode=REQUIRED")
				// Need to implement --ssl-ca or --ssl-capath
			}
		}
	}

	// Join the parts back together
	newQuerySlice := strings.Join(querySlice, "&")
	return (parsed[0] + "?" + newQuerySlice + "&timeout=10s"), error
}

func getUser(db *sql.DB) (string, error) {
	var user string
	err := db.QueryRow("SELECT CURRENT_USER()").Scan(&user)
	if err != nil {
		return "", err
	}
	return user, nil
}

func getDatabases(db *sql.DB, databases map[string]*Database) error {
	rows, err := db.Query("SHOW DATABASES")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var dbName string
		err = rows.Scan(&dbName)
		if err != nil {
			return err
		}
		// check if the database is a built-in database
		built_in_db := false
		switch dbName {
		case mysql_db_sys, mysql_db_perf_sch, mysql_db_info_sch, mysql_db_mysql:
			built_in_db = true
		}
		// add the database to the databases map
		newTables := make([]Table, 0)
		newRoutines := make([]Routine, 0)
		databases[dbName] = &Database{Name: dbName, Default: built_in_db, Tables: &newTables, Routines: &newRoutines}
	}

	return nil
}

func getTables(db *sql.DB, databases map[string]*Database) error {
	rows, err := db.Query("SELECT table_schema, table_name, IFNULL(DATA_LENGTH,0) FROM information_schema.tables")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var dbName string
		var tableName string
		var tableSize uint64
		err = rows.Scan(&dbName, &tableName, &tableSize)
		if err != nil {
			return err
		}

		// find the database in the databases slice
		d := databases[dbName]
		*d.Tables = append(*d.Tables, Table{Name: tableName, Bytes: tableSize})
	}

	return nil
}

func getRoutines(db *sql.DB, databases map[string]*Database) error {
	rows, err := db.Query("SELECT routine_schema, routine_name FROM information_schema.routines")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var dbName string
		var routineName string
		err = rows.Scan(&dbName, &routineName)
		if err != nil {
			return err
		}
		// find the database in the databases slice
		d, ok := databases[dbName]
		if !ok {
			databases[dbName] = &Database{Name: dbName, Default: false, Tables: &[]Table{}, Routines: &[]Routine{}, Nonexistent: true}
			d = databases[dbName]
		}

		*d.Routines = append(*d.Routines, Routine{Name: routineName})
	}

	return nil
}

func getGrants(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SHOW GRANTS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []string
	for rows.Next() {
		var grant string
		err = rows.Scan(&grant)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}

	return grants, nil
}

// ToDo: Deal with these GRANT/REVOKE statements
// GRANT SELECT (col1), INSERT (col1, col2) ON mydb.mytbl TO 'someuser'@'somehost';
// GRANT PROXY ON 'localuser'@'localhost' TO 'externaluser'@'somehost';
// GRANT 'role1', 'role2' TO 'user1'@'localhost', 'user2'@'localhost';

// What are the default privs on information_schema and performance_Schema?
// Seems table by table...maybe just put "Not Implemented" and leave this to be a show_all option.

// Note: Can't GRANT on a table that doesn't exist, but DB is fine.

// processGrants processes the grants and adds them to the databases structs and globalPrivs
func processGrants(grants []string, databases map[string]*Database, globalPrivs *GlobalPrivs) {
	for _, grant := range grants {
		// GRANTs on non-existent databases are valid, but we need that object to exist in "databases" for processGrant().
		db := parseDBFromGrant(grant)
		if db == mysql_all {
			continue
		}
		_, ok := databases[db]
		if !ok {
			databases[db] = &Database{Name: db, Default: false, Tables: &[]Table{}, Routines: &[]Routine{}, Nonexistent: true}
		}
	}
	for _, grant := range grants {
		processGrant(grant, databases, globalPrivs)
	}
}

func processGrant(grant string, databases map[string]*Database, globalPrivs *GlobalPrivs) {
	isGrant := strings.HasPrefix(grant, "GRANT")
	//hasGrantOption := strings.HasSuffix(grant, "WITH GRANT OPTION")

	// remove GRANT or REVOKE
	grant = strings.TrimPrefix(grant, "GRANT")
	grant = strings.TrimPrefix(grant, "REVOKE")

	// Split on " ON "
	parts := strings.Split(grant, " ON ")
	if len(parts) < 2 {
		color.Red("[!] Error processing grant: %s", grant)
		return
	}

	// Put privs in a slice
	privs := strings.Split(parts[0], ",")
	for i, priv := range privs {
		privs[i] = strings.Trim(priv, " ")
	}

	// Get DB and Table
	dbName := strings.Trim(strings.Split(parts[1], " TO ")[0], " ")
	if dbName == parts[1] {
		dbName = strings.Trim(strings.Split(parts[1], " FROM ")[0], " ")
	}

	// Find the database in the databases slice
	// Note: table may not exist yet OR may be a routine
	dbTableParts := strings.Split(dbName, ".")
	db := strings.Trim(dbTableParts[0], "\"`")
	table := strings.Trim(dbTableParts[1], "\"`")

	// dont' forget to deal with revoking db-level privs

	if db == mysql_all {
		// Deal with "ALL" and "ALL PRIVILEGES"
		switch privs[0] {
		case "ALL", "ALL PRIVILEGES":
			addRemoveAllPrivs(databases, globalPrivs, isGrant)
		default:
			for _, priv := range privs {
				addRemoveOnePrivOnAll(databases, globalPrivs, priv, isGrant)
			}
		}
	} else {

		// Check if the privs are for a routine
		isRoutine := checkIsRoutine(privs)
		if isRoutine {
			db = strings.TrimPrefix(db, "PROCEDURE `")
			db = strings.TrimSuffix(db, "`")
		}
		d := databases[db]

		switch {
		case table == mysql_all:
			filteredDBPrivs := filterDBPrivs(privs)
			filteredTablePrivs := filterTablePrivs(privs)
			d.Privs = addRemovePrivs(d.Privs, filteredDBPrivs, isGrant)
			for i, t := range *d.Tables {
				(*d.Tables)[i].Privs = addRemovePrivs(t.Privs, filteredTablePrivs, isGrant)
			}
		case isRoutine:
			var idx = getRoutineIndex(d, table)
			if idx == -1 {
				*d.Routines = append(*d.Routines, Routine{Name: table, Nonexistent: true})
				idx = len(*d.Routines) - 1
			}
			(*d.Routines)[idx].Privs = addRemovePrivs((*d.Routines)[idx].Privs, privs, isGrant)
		default:
			var idx = getTableIndex(d, table)
			if idx == -1 {
				*d.Tables = append(*d.Tables, Table{Name: table, Nonexistent: true, Bytes: 0})
				idx = len(*d.Tables) - 1
			}
			(*d.Tables)[idx].Privs = addRemovePrivs((*d.Tables)[idx].Privs, privs, isGrant)
		}
	}
}

func parseDBFromGrant(grant string) string {
	// Split on " ON "
	parts := strings.Split(grant, " ON ")
	if len(parts) < 2 {
		color.Red("[!] Error processing grant: %s", grant)
		return ""
	}

	// Get DB and Table
	dbName := strings.Trim(strings.Split(parts[1], " TO ")[0], " ")
	if dbName == parts[1] {
		dbName = strings.Trim(strings.Split(parts[1], " FROM ")[0], " ")
	}
	dbTableParts := strings.Split(dbName, ".")
	db := strings.Trim(dbTableParts[0], "\"`")
	db = strings.TrimPrefix(db, "PROCEDURE `")
	db = strings.TrimSuffix(db, "`")
	return db
}

func filterDBPrivs(privs []string) []string {
	filtered := make([]string, 0)
	for _, priv := range privs {
		if SCOPES[priv].Database {
			filtered = append(filtered, priv)
		}
	}
	return filtered
}

func filterTablePrivs(privs []string) []string {
	filtered := make([]string, 0)
	for _, priv := range privs {
		if SCOPES[priv].Table {
			filtered = append(filtered, priv)
		}
	}
	return filtered
}

func addRemoveOnePrivOnAll(databases map[string]*Database, globalPrivs *GlobalPrivs, priv string, isGrant bool) {
	scope, ok := SCOPES[priv]
	if !ok {
		color.Red("[!] Error processing grant: privilege doesn't exist in our MySQL (%s)", priv)
		return
	}

	slicedPriv := []string{priv}

	// Add priv to globalPrivs
	if scope.Global {
		globalPrivs.Privs = addRemovePrivs(globalPrivs.Privs, slicedPriv, isGrant)
	}

	// Add/Remove priv to all databases
	if scope.Database {
		for _, d := range databases {
			if d.Name == "information_schema" || d.Name == "performance_schema" {
				continue
			}
			d.Privs = addRemovePrivs(d.Privs, slicedPriv, isGrant)
		}
	}

	// Add/Remove priv to all tables
	if scope.Table {
		for _, d := range databases {
			for i, t := range *d.Tables {
				(*d.Tables)[i].Privs = addRemovePrivs(t.Privs, slicedPriv, isGrant)
			}
		}
	}

	// Add/Remove priv to all routines
	if scope.Routine {
		for _, d := range databases {
			for i, r := range *d.Routines {
				(*d.Routines)[i].Privs = addRemovePrivs(r.Privs, slicedPriv, isGrant)
			}
		}
	}
}

func addRemoveAllPrivs(databases map[string]*Database, globalPrivs *GlobalPrivs, isGrant bool) {
	// Add all privs to globalPrivs
	globalAllPrivs := getGlobalAllPrivileges()
	globalPrivs.Privs = addRemovePrivs(globalPrivs.Privs, globalAllPrivs, isGrant)

	// Get DB, Table and Routine Privs
	dbAllPrivs := getDBAllPrivs()
	tableAllPrivs := getTableAllPrivs()
	routineAllPrivs := getRoutineAllPrivs()

	// Add all privs to all databases and tables and routines
	for _, d := range databases {
		if d.Name == "information_schema" || d.Name == "performance_schema" {
			continue
		}
		// Add DB-level privs
		d.Privs = addRemovePrivs(d.Privs, dbAllPrivs, isGrant)

		// Add Table-level privs
		for i, t := range *d.Tables {
			(*d.Tables)[i].Privs = addRemovePrivs(t.Privs, tableAllPrivs, isGrant)
		}

		// Add Routine-level privs
		for i, r := range *d.Routines {
			(*d.Routines)[i].Privs = addRemovePrivs(r.Privs, routineAllPrivs, isGrant)
		}
	}
}

func getGlobalAllPrivileges() []string {
	privs := make([]string, 0)
	for priv, scope := range SCOPES {
		if scope.Global && !scope.Dynamic && priv != "USAGE" && priv != "GRANT OPTION" {
			privs = append(privs, priv)
		}
	}
	return privs
}

func getDBAllPrivs() []string {
	privs := make([]string, 0)
	for priv, scope := range SCOPES {
		if scope.Database && !scope.Dynamic && priv != "USAGE" && priv != "GRANT OPTION" {
			privs = append(privs, priv)
		}
	}
	return privs
}

func getTableAllPrivs() []string {
	privs := make([]string, 0)
	for priv, scope := range SCOPES {
		if scope.Table && !scope.Dynamic && priv != "USAGE" && priv != "GRANT OPTION" {
			privs = append(privs, priv)
		}
	}
	return privs
}

func getRoutineAllPrivs() []string {
	privs := make([]string, 0)
	for priv, scope := range SCOPES {
		if scope.Routine && !scope.Dynamic && priv != "USAGE" && priv != "GRANT OPTION" {
			privs = append(privs, priv)
		}
	}
	return privs
}

func checkIsRoutine(privs []string) bool {
	if len(privs) > 0 {
		return SCOPES[privs[0]].Routine
	}
	return false
}

func getTableIndex(d *Database, tableName string) int {
	for i, t := range *d.Tables {
		if t.Name == tableName {
			return i
		}
	}
	return -1
}

func getRoutineIndex(d *Database, routineName string) int {
	for i, r := range *d.Routines {
		if r.Name == routineName {
			return i
		}
	}
	return -1
}

func addRemovePrivs(currentPrivs []string, privsToAddRemove []string, add bool) []string {
	newPrivs := make([]string, 0)
	if add {
		newPrivs = append(currentPrivs, privsToAddRemove...)
		return newPrivs
	}
	for _, p := range currentPrivs {
		found := false
		for _, p2 := range privsToAddRemove {
			if p == p2 {
				found = true
				break
			}
		}
		if !found {
			newPrivs = append(newPrivs, p)
		}
	}
	return newPrivs
}

func printResults(databases map[string]*Database, globalPrivs GlobalPrivs, showAll bool) {
	// Print Global Privileges
	printGlobalPrivs(globalPrivs)
	// Print Database and Table Privileges
	printDBTablePrivs(databases, showAll)
	// Print Routine Privileges
	printRoutinePrivs(databases, showAll)
}

func printGlobalPrivs(globalPrivs GlobalPrivs) {
	// Prep table writer
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Global Privileges"})

	// Print global privs
	globalPrivsStr := ""
	for _, priv := range globalPrivs.Privs {
		globalPrivsStr += priv + ", "
	}
	// Clean up privs string
	globalPrivsStr = cleanPrivStr(globalPrivsStr)

	// Add rows of priv string data
	t.AppendRow([]interface{}{analyzers.GreenWriter(text.WrapSoft(globalPrivsStr, 100))})
	t.Render()
}

func printDBTablePrivs(databases map[string]*Database, showAll bool) {
	// Prep table writer
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Database", "Table", "Privileges", "Est. Size"})

	// Print database privs
	for _, d := range databases {
		if isBuiltIn(d.Name) && !showAll {
			continue
		}

		// Add privileges to db or table privs strings
		dbPrivsStr := ""
		dbTablesStr := ""
		for _, priv := range d.Privs {
			scope := SCOPES[priv]
			if scope.Database && scope.Table {
				dbTablesStr += priv + ", "
			} else {
				dbPrivsStr += priv + ", "
			}
		}

		// Clean up privs strings
		dbPrivsStr = cleanPrivStr(dbPrivsStr)
		dbTablesStr = cleanPrivStr(dbTablesStr)

		// Prep String colors
		var dbName string
		var writer func(a ...interface{}) string
		if d.Default {
			dbName = d.Name + " (built-in)"
			writer = analyzers.YellowWriter
		} else if d.Nonexistent {
			dbName = d.Name + " (nonexistent)"
			writer = analyzers.RedWriter
		} else {
			dbName = d.Name
			writer = analyzers.GreenWriter
		}

		// Prep Priv Strings

		// Add rows of priv string data
		t.AppendRow([]interface{}{writer(dbName), writer("<DB-Level Privs>"), writer(text.WrapSoft(dbPrivsStr, 80)), writer("-")})
		t.AppendRow([]interface{}{"", writer("<All tables>"), writer(text.WrapSoft(dbTablesStr, 80)), writer("-")})

		// Print table privs
		for _, t2 := range *d.Tables {
			tablePrivsStr := ""
			for _, priv := range t2.Privs {
				tablePrivsStr += priv + ", "
			}
			tablePrivsStr = cleanPrivStr(tablePrivsStr)
			t.AppendRow([]interface{}{"", writer(t2.Name), writer(text.WrapSoft(tablePrivsStr, 80)), writer(humanize.Bytes(t2.Bytes))})
		}
		// Add a separator between databases
		t.AppendSeparator()
	}
	t.Render()
}

func printRoutinePrivs(databases map[string]*Database, showAll bool) {
	// Print routine privs
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Database", "Routine", "Privileges"})

	// Add rows of priv string data
	for _, d := range databases {
		if isBuiltIn(d.Name) && !showAll {
			continue
		}
		for _, r := range *d.Routines {
			routinePrivsStr := ""
			for _, priv := range r.Privs {
				routinePrivsStr += priv + ", "
			}
			routinePrivsStr = cleanPrivStr(routinePrivsStr)
			var writer func(a ...interface{}) string
			switch d.Name {
			case mysql_db_info_sch, mysql_db_perf_sch, mysql_db_sys, mysql_db_mysql:
				writer = analyzers.YellowWriter
			default:
				writer = analyzers.GreenWriter
			}
			t.AppendRow([]interface{}{writer(d.Name), writer(r.Name), writer(text.WrapSoft(routinePrivsStr, 80))})
		}
	}
	t.Render()
}

func cleanPrivStr(priv string) string {
	priv = strings.TrimSuffix(priv, ", ")
	if priv == "" {
		priv = "-"
	}
	return priv
}

func isBuiltIn(dbName string) bool {
	switch dbName {
	case mysql_db_sys, mysql_db_perf_sch, mysql_db_info_sch, mysql_db_mysql:
		return true
	}
	return false
}
