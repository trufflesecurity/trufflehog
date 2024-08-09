package mysql

type PrivTypes struct {
	Global   bool
	Database bool
	Table    bool
	Column   bool
	Routine  bool
	Proxy    bool
	Dynamic  bool
}

// https://dev.mysql.com/doc/refman/8.0/en/grant.html#grant-global-privileges:~:text=%27localhost%27%3B-,Privileges%20Supported%20by%20MySQL,-The%20following%20tables
var SCOPES = map[string]PrivTypes{
	// Static privs
	"ALTER":                   {Global: true, Database: true, Table: true},
	"ALTER ROUTINE":           {Global: true, Database: true, Routine: true},
	"CREATE":                  {Global: true, Database: true, Table: true},
	"CREATE ROLE":             {Global: true},
	"CREATE ROUTINE":          {Global: true, Database: true},
	"CREATE TABLESPACE":       {Global: true},
	"CREATE TEMPORARY TABLES": {Global: true, Database: true},
	"CREATE USER":             {Global: true},
	"CREATE VIEW":             {Global: true, Database: true, Table: true},
	"DELETE":                  {Global: true, Database: true, Table: true},
	"DROP":                    {Global: true, Database: true, Table: true},
	"DROP ROLE":               {Global: true},
	"EVENT":                   {Global: true, Database: true},
	"EXECUTE":                 {Global: true, Database: true, Routine: true},
	"FILE":                    {Global: true},
	"GRANT OPTION":            {Global: true, Database: true, Table: true, Routine: true, Proxy: true}, // Not granted on ALL PRIVILEGES
	"INDEX":                   {Global: true, Database: true, Table: true},
	"INSERT":                  {Global: true, Database: true, Table: true, Column: true},
	"LOCK TABLES":             {Global: true, Database: true},
	"PROCESS":                 {Global: true},
	"PROXY":                   {Proxy: true}, // Not granted on ALL PRIVILEGES
	"REFERENCES":              {Global: true, Database: true, Table: true, Column: true},
	"RELOAD":                  {Global: true},
	"REPLICATION CLIENT":      {Global: true},
	"REPLICATION SLAVE":       {Global: true},
	"SELECT":                  {Global: true, Database: true, Table: true, Column: true},
	"SHOW DATABASES":          {Global: true},
	"SHOW VIEW":               {Global: true, Database: true, Table: true},
	"SHUTDOWN":                {Global: true},
	"SUPER":                   {Global: true},
	"TRIGGER":                 {Global: true, Database: true, Table: true},
	"UPDATE":                  {Global: true, Database: true, Table: true, Column: true},

	// This is a special case, it's not a real privilege
	"USAGE": {Global: true, Database: true, Table: true, Column: true, Routine: true},

	// Dynamic privs
	"ALLOW_NONEXISTENT_DEFINER":    {Global: true, Dynamic: true},
	"APPLICATION_PASSWORD_ADMIN":   {Global: true, Dynamic: true},
	"AUDIT_ABORT_EXEMPT":           {Global: true, Dynamic: true},
	"AUDIT_ADMIN":                  {Global: true, Dynamic: true},
	"AUTHENTICATION_POLICY_ADMIN":  {Global: true, Dynamic: true},
	"BACKUP_ADMIN":                 {Global: true, Dynamic: true},
	"BINLOG_ADMIN":                 {Global: true, Dynamic: true},
	"BINLOG_ENCRYPTION_ADMIN":      {Global: true, Dynamic: true},
	"CLONE_ADMIN":                  {Global: true, Dynamic: true},
	"CONNECTION_ADMIN":             {Global: true, Dynamic: true},
	"ENCRYPTION_KEY_ADMIN":         {Global: true, Dynamic: true},
	"FIREWALL_ADMIN":               {Global: true, Dynamic: true},
	"FIREWALL_EXEMPT":              {Global: true, Dynamic: true},
	"FIREWALL_USER":                {Global: true, Dynamic: true},
	"FLUSH_OPTIMIZER_COSTS":        {Global: true, Dynamic: true},
	"FLUSH_STATUS":                 {Global: true, Dynamic: true},
	"FLUSH_TABLES":                 {Global: true, Dynamic: true},
	"FLUSH_USER_RESOURCES":         {Global: true, Dynamic: true},
	"GROUP_REPLICATION_ADMIN":      {Global: true, Dynamic: true},
	"GROUP_REPLICATION_STREAM":     {Global: true, Dynamic: true},
	"INNODB_REDO_LOG_ARCHIVE":      {Global: true, Dynamic: true},
	"INNODB_REDO_LOG_ENABLE":       {Global: true, Dynamic: true},
	"MASKING_DICTIONARIES_ADMIN":   {Global: true, Dynamic: true},
	"NDB_STORED_USER":              {Global: true, Dynamic: true},
	"PASSWORDLESS_USER_ADMIN":      {Global: true, Dynamic: true},
	"PERSIST_RO_VARIABLES_ADMIN":   {Global: true, Dynamic: true},
	"REPLICATION_APPLIER":          {Global: true, Dynamic: true},
	"REPLICATION_SLAVE_ADMIN":      {Global: true, Dynamic: true},
	"RESOURCE_GROUP_ADMIN":         {Global: true, Dynamic: true},
	"RESOURCE_GROUP_USER":          {Global: true, Dynamic: true},
	"ROLE_ADMIN":                   {Global: true, Dynamic: true},
	"SENSITIVE_VARIABLES_OBSERVER": {Global: true, Dynamic: true},
	"SERVICE_CONNECTION_ADMIN":     {Global: true, Dynamic: true},
	"SESSION_VARIABLES_ADMIN":      {Global: true, Dynamic: true},
	"SET_ANY_DEFINER":              {Global: true, Dynamic: true},
	"SET_USER_ID":                  {Global: true, Dynamic: true},
	"SHOW_ROUTINE":                 {Global: true, Dynamic: true},
	"SKIP_QUERY_REWRITE":           {Global: true, Dynamic: true},
	"SYSTEM_USER":                  {Global: true, Dynamic: true},
	"SYSTEM_VARIABLES_ADMIN":       {Global: true, Dynamic: true},
	"TABLE_ENCRYPTION_ADMIN":       {Global: true, Dynamic: true},
	"TELEMETRY_LOG_ADMIN":          {Global: true, Dynamic: true},
	"TP_CONNECTION_ADMIN":          {Global: true, Dynamic: true},
	"TRANSACTION_GTID_TAG":         {Global: true, Dynamic: true},
	"VERSION_TOKEN_ADMIN":          {Global: true, Dynamic: true},
	"XA_RECOVER_ADMIN":             {Global: true, Dynamic: true},
}
