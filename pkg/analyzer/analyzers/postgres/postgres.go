package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/lib/pq"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

type DBPrivs struct {
	Connect    bool
	Create     bool
	CreateTemp bool
}

type DB struct {
	DatabaseName string
	Owner        string
	DBPrivs
}

type TablePrivs struct {
	Select     bool
	Insert     bool
	Update     bool
	Delete     bool
	Truncate   bool
	References bool
	Trigger    bool
}

type TableData struct {
	Size  string
	Rows  string
	Privs TablePrivs
}

const (
	defaultPort = "5432"

	pg_connect_timeout = "connect_timeout"
	pg_dbname          = "dbname"
	pg_host            = "host"
	pg_password        = "password"
	pg_port            = "port"
	pg_requiressl      = "requiressl"
	pg_sslmode         = "sslmode"
	pg_sslmode_allow   = "allow"
	pg_sslmode_disable = "disable"
	pg_sslmode_prefer  = "prefer"
	pg_sslmode_require = "require"
	pg_user            = "user"
)

var connStrPartPattern = regexp.MustCompile(`([[:alpha:]]+)='(.+?)' ?`)

func AnalyzePermissions(connectionStr string, showAll bool) {
	connStr, err := pq.ParseURL(string(connectionStr))
	if err != nil {
		color.Red("[x] Failed to parse Postgres connection string.\n    Error: " + err.Error())
		return
	}
	parts := connStrPartPattern.FindAllStringSubmatch(connStr, -1)
	params := make(map[string]string, len(parts))
	for _, part := range parts {
		params[part[1]] = part[2]
	}
	db, err := createConnection(params, "")
	if err != nil {
		color.Red("[x] Failed to connect to Postgres database.\n    Error: " + err.Error())
		return
	}
	defer db.Close()
	color.Yellow("[!] Successfully connected to Postgres database.")
	err = getUserPrivs(db)
	if err != nil {
		color.Red("[x] Failed to retrieve user privileges.\n    Error: " + err.Error())
		return
	}
	dbs, err := getDBPrivs(db)
	if err != nil {
		color.Red("[x] Failed to retrieve database privileges.\n    Error: " + err.Error())
		return
	}
	err = getTablePrivs(params, dbs)
	if err != nil {
		color.Red("[x] Failed to retrieve table privileges.\n    Error: " + err.Error())
		return
	}
}

func isErrorDatabaseNotFound(err error, dbName string, user string) bool {
	options := []string{dbName, user, "postgres"}
	for _, option := range options {
		if strings.Contains(err.Error(), fmt.Sprintf("database \"%s\" does not exist", option)) {
			return true
		}
	}
	return false
}

func createConnection(params map[string]string, database string) (*sql.DB, error) {
	if sslmode := params[pg_sslmode]; sslmode == pg_sslmode_allow || sslmode == pg_sslmode_prefer {
		// pq doesn't support 'allow' or 'prefer'. If we find either of them, we'll just ignore it. This will trigger
		// the same logic that is run if no sslmode is set at all (which mimics 'prefer', which is the default).
		delete(params, pg_sslmode)
	}

	var connStr string
	for key, value := range params {
		if database != "" && key == "dbname" {
			connStr += fmt.Sprintf("%s='%s'", key, database)
		} else {
			connStr += fmt.Sprintf("%s='%s'", key, value)
		}
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	switch {
	case err == nil:
		return db, nil
	case strings.Contains(err.Error(), "password authentication failed"):
		return nil, errors.New("password authentication failed")
	case errors.Is(err, pq.ErrSSLNotSupported) && params[pg_sslmode] == "":
		// If the sslmode is unset, then either it was unset in the candidate secret, or we've intentionally unset it
		// because it was specified as 'allow' or 'prefer', neither of which pq supports. In all of these cases, non-SSL
		// connections are acceptable, so now we try a connection without SSL.
		params[pg_sslmode] = pg_sslmode_disable
		defer delete(params, pg_sslmode) // We want to return with the original params map intact (for ExtraData)
		return createConnection(params, database)
	case isErrorDatabaseNotFound(err, params[pg_dbname], params[pg_user]):
		color.Green("[!] Successfully connected to Postgres database.")
		return nil, err
	default:
		return nil, err
	}
}

func getUserPrivs(db *sql.DB) error {
	// Prepare the SQL statement
	query := `SELECT rolname AS role_name,
				rolsuper AS is_superuser,
				rolinherit AS can_inherit,
				rolcreaterole AS can_create_role,
				rolcreatedb AS can_create_db,
				rolcanlogin AS can_login,
				rolreplication AS is_replication_role,
				rolbypassrls AS bypasses_rls
			FROM pg_roles WHERE rolname = current_user;`

	// Execute the SQL query
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var roleName string
	var isSuperuser, canInherit, canCreateRole, canCreateDB, canLogin, isReplicationRole, bypassesRLS bool
	// Iterate over the rows
	for rows.Next() {
		if err := rows.Scan(&roleName, &isSuperuser, &canInherit, &canCreateRole, &canCreateDB, &canLogin, &isReplicationRole, &bypassesRLS); err != nil {
			return err
		}
	}

	// Check for errors during iteration
	if err := rows.Err(); err != nil {
		return err
	}

	// Map roles to privileges
	var mapRoles map[string]bool = map[string]bool{
		"Superuser":            isSuperuser,
		"Inheritance of Privs": canInherit,
		"Create Role":          canCreateRole,
		"Create DB":            canCreateDB,
		"Login":                canLogin,
		"Replication":          isReplicationRole,
		"Bypass RLS":           bypassesRLS,
	}

	// Print User roles + privs
	color.Yellow("[i] User: %s", roleName)
	color.Yellow("[i] Privileges: ")
	for role, priv := range mapRoles {
		if role == "Superuser" && priv {
			color.Green("  - %s", role)
		} else if priv {
			color.Yellow("  - %s", role)
		}
	}
	return nil
}

func getDBPrivs(db *sql.DB) ([]string, error) {
	query := `
        SELECT 
            d.datname AS database_name,
            u.usename AS owner,
            current_user AS current_user,
            has_database_privilege(current_user, d.datname, 'CONNECT') AS can_connect,
            has_database_privilege(current_user, d.datname, 'CREATE') AS can_create,
            has_database_privilege(current_user, d.datname, 'TEMP') AS can_create_temporary_tables
        FROM 
            pg_database d
        JOIN 
            pg_user u ON d.datdba = u.usesysid
        WHERE 
            NOT d.datistemplate
        ORDER BY 
            d.datname;
    `
	// Originally had WHERE NOT d.datistemplate  AND d.datallowconn

	// Execute the query
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dbs := make([]DB, 0)

	var currentUser string
	// Iterate through the result set
	for rows.Next() {
		var dbName, owner string
		var canConnect, canCreate, canCreateTemp bool
		err := rows.Scan(&dbName, &owner, &currentUser, &canConnect, &canCreate, &canCreateTemp)
		if err != nil {
			return nil, err
		}

		db := DB{
			DatabaseName: dbName,
			Owner:        owner,
			DBPrivs: DBPrivs{
				Connect:    canConnect,
				Create:     canCreate,
				CreateTemp: canCreateTemp,
			},
		}
		dbs = append(dbs, db)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Print db privs
	if len(dbs) > 0 {
		fmt.Println("\n")
		color.Green("[i] User has the following database privileges:")
		printDBPrivs(dbs, currentUser)
		return buildSliceDBNames(dbs), nil
	}
	return nil, nil
}

func printDBPrivs(dbs []DB, current_user string) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Database", "Owner", "Access Privileges"})
	for _, db := range dbs {
		privs := buildDBPrivsStr(db)
		writer := getDBWriter(db, current_user)
		t.AppendRow([]interface{}{writer(db.DatabaseName), writer(db.Owner), writer(privs)})
	}
	t.Render()
}

func buildDBPrivsStr(db DB) string {
	privs := ""
	if db.Connect {
		privs += "CONNECT"
	}
	if db.Create {
		privs += ", CREATE"
	}
	if db.CreateTemp {
		privs += ", TEMP"
	}
	privs = strings.TrimPrefix(privs, ", ")
	return privs
}

func getDBWriter(db DB, current_user string) func(a ...interface{}) string {
	if db.Owner == current_user {
		return analyzers.GreenWriter
	} else if db.Connect && db.Create && db.CreateTemp {
		return analyzers.GreenWriter
	} else if db.Connect || db.Create || db.CreateTemp {
		return analyzers.YellowWriter
	} else {
		return analyzers.DefaultWriter
	}
}

func buildSliceDBNames(dbs []DB) []string {
	var dbNames []string
	for _, db := range dbs {
		if db.DBPrivs.Connect {
			dbNames = append(dbNames, db.DatabaseName)
		}
	}
	return dbNames
}

func getTablePrivs(params map[string]string, databases []string) error {

	tablePrivileges := make(map[string]map[string]*TableData, 0)

	for _, dbase := range databases {

		// Connect to db
		db, err := createConnection(params, dbase)
		if err != nil {
			color.Red("[x] Failed to connect to Postgres database: %s", dbase)
			continue
		}
		defer db.Close()

		// Get table privs
		query := `
		SELECT
			rtg.table_catalog,
			rtg.table_name,
			rtg.privilege_type,
			pg_size_pretty(pg_total_relation_size(pc.oid)) AS table_size,
			pc.reltuples AS estimate
		FROM
			information_schema.role_table_grants rtg
		JOIN
			pg_catalog.pg_class pc ON rtg.table_name = pc.relname
		WHERE
			rtg.grantee = current_user;

		`

		// Execute the query
		rows, err := db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Iterate through the result set
		for rows.Next() {
			var database, table, priv, size, row_count string
			err := rows.Scan(&database, &table, &priv, &size, &row_count)
			if err != nil {
				return err
			}

			if _, ok := tablePrivileges[database]; !ok {
				tablePrivileges[database] = map[string]*TableData{
					table: {},
				}
			}

			switch priv {
			case "SELECT":
				tablePrivileges[database][table].Privs.Select = true
			case "INSERT":
				tablePrivileges[database][table].Privs.Insert = true
			case "UPDATE":
				tablePrivileges[database][table].Privs.Update = true
			case "DELETE":
				tablePrivileges[database][table].Privs.Delete = true
			case "TRUNCATE":
				tablePrivileges[database][table].Privs.Truncate = true
			case "REFERENCES":
				tablePrivileges[database][table].Privs.References = true
			case "TRIGGER":
				tablePrivileges[database][table].Privs.Trigger = true
			}
			tablePrivileges[database][table].Size = size
			if row_count != "-1" {
				tablePrivileges[database][table].Rows = row_count
			} else {
				tablePrivileges[database][table].Rows = "Unknown"
			}
		}
		if err = rows.Err(); err != nil {
			return err
		}
		db.Close()
	}

	// Print table privs
	if len(tablePrivileges) > 0 {
		fmt.Println("\n")
		color.Green("[i] User has the following table privileges:")
		printTablePrivs(tablePrivileges)
	}
	return nil
}

func printTablePrivs(tables map[string]map[string]*TableData) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Database", "Table", "Access Privileges", "Est. Size", "Est. Rows"})
	var writer func(a ...interface{}) string
	for db, table := range tables {
		for table_name, tableData := range table {
			privs := tableData.Privs
			privsStr := buildTablePrivsStr(privs)
			if privsStr == "" {
				writer = color.New().SprintFunc()
			} else {
				writer = color.New(color.FgGreen).SprintFunc()
			}
			t.AppendRow([]interface{}{writer(db), writer(table_name), writer(privsStr), writer("< " + tableData.Size), writer(tableData.Rows)})
		}
	}
	t.Render()
}

func buildTablePrivsStr(privs TablePrivs) string {
	var privsStr string
	if privs.Select {
		privsStr += "SELECT"
	}
	if privs.Insert {
		privsStr += ", INSERT"
	}
	if privs.Update {
		privsStr += ", UPDATE"
	}
	if privs.Delete {
		privsStr += ", DELETE"
	}
	if privs.Truncate {
		privsStr += ", TRUNCATE"
	}
	if privs.References {
		privsStr += ", REFERENCES"
	}
	if privs.Trigger {
		privsStr += ", TRIGGER"
	}
	privsStr = strings.TrimPrefix(privsStr, ", ")
	return privsStr
}
