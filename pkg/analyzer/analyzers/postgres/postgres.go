//go:generate generate_permissions permissions.yaml permissions.go postgres

package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/lib/pq"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypePostgres }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	uri, ok := credInfo["connection_string"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Postgres", "validate_credentials", "config", "", errors.New("connection string not found in credInfo"))
	}

	info, err := AnalyzePermissions(a.Cfg, uri)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Postgres", "analyze_permissions", "Database", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypePostgres,
		Metadata:     nil,
		Bindings:     []analyzers.Binding{},
	}

	// set user related bindings in result
	userResource, userBindings := bakeUserBindings(info)
	result.Bindings = append(result.Bindings, userBindings...)

	// add user's database privileges to bindings
	dbNameToResourceMap, dbBindings := bakeDatabaseBindings(userResource, info)
	result.Bindings = append(result.Bindings, dbBindings...)

	// add user's table privileges to bindings
	tableBindings := bakeTableBindings(dbNameToResourceMap, info)
	result.Bindings = append(result.Bindings, tableBindings...)

	return &result
}

func bakeUserBindings(info *SecretInfo) (analyzers.Resource, []analyzers.Binding) {
	userResource := analyzers.Resource{
		Name:               info.User,
		FullyQualifiedName: info.Host + "/" + info.User,
		Type:               "user",
		Metadata: map[string]any{
			"role": info.Role,
		},
	}

	var bindings []analyzers.Binding

	for rolePriv, exists := range info.RolePrivs {
		if exists {
			bindings = append(bindings, analyzers.Binding{
				Resource: userResource,
				Permission: analyzers.Permission{
					Value: rolePriv,
				},
			})
		}
	}

	return userResource, bindings
}

func bakeDatabaseBindings(userResource analyzers.Resource, info *SecretInfo) (map[string]*analyzers.Resource, []analyzers.Binding) {
	dbNameToResourceMap := map[string]*analyzers.Resource{}
	dbBindings := []analyzers.Binding{}

	for _, db := range info.DBs {
		dbResource := analyzers.Resource{
			Name:               db.DatabaseName,
			FullyQualifiedName: info.Host + "/" + db.DatabaseName,
			Type:               "database",
			Metadata: map[string]any{
				"owner": db.Owner,
			},
			Parent: &userResource,
		}

		// populate map to reference later for tables
		dbNameToResourceMap[db.DatabaseName] = &dbResource

		dbPriviliges := map[string]bool{
			"connect": db.Connect,
			"create":  db.Create,
			"temp":    db.CreateTemp,
		}

		for priv, exists := range dbPriviliges {
			if exists {
				dbBindings = append(dbBindings, analyzers.Binding{
					Resource: dbResource,
					Permission: analyzers.Permission{
						Value: priv,
					},
				})
			}
		}
	}

	return dbNameToResourceMap, dbBindings
}

func bakeTableBindings(dbNameToResourceMap map[string]*analyzers.Resource, info *SecretInfo) []analyzers.Binding {
	var tableBindings []analyzers.Binding

	for dbName, tableMap := range info.TablePrivs {
		dbResource, ok := dbNameToResourceMap[dbName]
		if !ok {
			continue
		}

		for tableName, tableData := range tableMap {
			tableResource := analyzers.Resource{
				Name:               tableName,
				FullyQualifiedName: info.Host + "/" + dbResource.Name + "/" + tableName,
				Type:               "table",
				Metadata: map[string]any{
					"size": tableData.Size,
					"rows": tableData.Rows,
				},
				Parent: dbResource,
			}

			tablePrivsMap := map[string]bool{
				"select":     tableData.Privs.Select,
				"insert":     tableData.Privs.Insert,
				"update":     tableData.Privs.Update,
				"delete":     tableData.Privs.Delete,
				"truncate":   tableData.Privs.Truncate,
				"references": tableData.Privs.References,
				"trigger":    tableData.Privs.Trigger,
			}

			for priv, exists := range tablePrivsMap {
				if exists {
					tableBindings = append(tableBindings, analyzers.Binding{
						Resource: tableResource,
						Permission: analyzers.Permission{
							Value: priv,
						},
					})
				}
			}
		}
	}

	return tableBindings
}

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

type SecretInfo struct {
	Host       string
	User       string
	Role       string
	RolePrivs  map[string]bool
	DBs        []DB
	TablePrivs map[string]map[string]*TableData
}

func AnalyzeAndPrintPermissions(cfg *config.Config, connectionStr string) {

	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	info, err := AnalyzePermissions(cfg, connectionStr)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	color.Yellow("[!] Successfully connected to Postgres database.")
	printUserRoleAndPriv(info.Role, info.RolePrivs)

	// Print db privs
	if len(info.DBs) > 0 {
		fmt.Print("\n\n")
		color.Green("[i] User has the following database privileges:")
		printDBPrivs(info.DBs, info.User)
	}

	// Print table privs
	if len(info.TablePrivs) > 0 {
		fmt.Print("\n\n")
		color.Green("[i] User has the following table privileges:")
		printTablePrivs(info.TablePrivs)
	}
}

func AnalyzePermissions(cfg *config.Config, connectionStr string) (*SecretInfo, error) {

	connStr, err := pq.ParseURL(string(connectionStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Postgres connection string: %w", err)
	}
	parts := connStrPartPattern.FindAllStringSubmatch(connStr, -1)
	params := make(map[string]string, len(parts))
	for _, part := range parts {
		params[part[1]] = part[2]
	}
	db, err := createConnection(params, "")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Postgres database: %w", err)
	}
	defer db.Close()

	role, privs, err := getUserPrivs(db)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user privileges: %w", err)
	}
	currentUser, dbs, err := getDBPrivs(db)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve database privileges: %w", err)
	}
	tablePrivs, err := getTablePrivs(params, buildSliceDBNames(dbs))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve table privileges: %w", err)
	}

	return &SecretInfo{
		Host:       params[pg_host],
		User:       currentUser,
		Role:       role,
		RolePrivs:  privs,
		DBs:        dbs,
		TablePrivs: tablePrivs,
	}, nil
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

func getUserPrivs(db *sql.DB) (string, map[string]bool, error) {
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
		return "", nil, err
	}
	defer rows.Close()

	var roleName string
	var isSuperuser, canInherit, canCreateRole, canCreateDB, canLogin, isReplicationRole, bypassesRLS bool
	// Iterate over the rows
	for rows.Next() {
		if err := rows.Scan(&roleName, &isSuperuser, &canInherit, &canCreateRole, &canCreateDB, &canLogin, &isReplicationRole, &bypassesRLS); err != nil {
			return "", nil, err
		}
	}

	// Check for errors during iteration
	if err := rows.Err(); err != nil {
		return "", nil, err
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

	return roleName, mapRoles, nil
}

func getDBPrivs(db *sql.DB) (string, []DB, error) {
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
		return "", nil, err
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
			return "", nil, err
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
		return "", nil, err
	}

	return currentUser, dbs, nil
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

func getTablePrivs(params map[string]string, databases []string) (map[string]map[string]*TableData, error) {

	tablePrivileges := make(map[string]map[string]*TableData, 0)

	for _, dbase := range databases {
		// Connect to db
		db, err := createConnection(params, dbase)
		if err != nil {
			// color.Red("[x] Failed to connect to Postgres database: %s", dbase)
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
			return nil, err
		}
		defer rows.Close()

		// Iterate through the result set
		for rows.Next() {
			var database, table, priv, size, row_count string
			err := rows.Scan(&database, &table, &priv, &size, &row_count)
			if err != nil {
				return nil, err
			}

			if _, ok := tablePrivileges[database]; !ok {
				tablePrivileges[database] = map[string]*TableData{
					table: {},
				}
			}

			if _, ok := tablePrivileges[database][table]; !ok {
				tablePrivileges[database][table] = &TableData{}
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
			return nil, err
		}
		db.Close()
	}

	return tablePrivileges, nil
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

func printUserRoleAndPriv(role string, privs map[string]bool) {
	color.Yellow("[i] User: %s", role)
	color.Yellow("[i] Privileges: ")
	for role, priv := range privs {
		if role == "Superuser" && priv {
			color.Green("  - %s", role)
		} else if priv {
			color.Yellow("  - %s", role)
		}
	}
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
