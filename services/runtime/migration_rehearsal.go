package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

type migrationImportRequest struct {
	Version        int                      `json:"schemaVersion"`
	Snapshot       migrationSnapshotRequest `json:"snapshot"`
	StreamHash     string                   `json:"streamHash"`
	CandidateImage string                   `json:"candidateImage"`
}
type migrationImportReceipt struct {
	Version              int                    `json:"schemaVersion"`
	Binding              migrationImportRequest `json:"binding"`
	RequestHash          string                 `json:"requestHash"`
	Status               string                 `json:"status"`
	CheckedAt            string                 `json:"checkedAt"`
	OldColumnPrimaryHash string                 `json:"oldColumnPrimaryHash"`
	LedgerHash           string                 `json:"migrationLedgerHash"`
	RowDigest            string                 `json:"rowDigest"`
	Rows                 int                    `json:"rowCount"`
	Tables               int                    `json:"tableCount"`
	Preservation         string                 `json:"dataPreservation"`
	MigrationDDL         string                 `json:"migrationDDL"`
	Compatibility        string                 `json:"previousReleaseCompatibility"`
	WriteQuiescence      string                 `json:"currentWriteQuiescence"`
	EpochAdvancement     string                 `json:"schemaEpochAdvancement"`
	PublicationEligible  bool                   `json:"publicationEligible"`
	Reason               string                 `json:"reason"`
}
type migrationImportRecord struct {
	Receipt              migrationImportReceipt `json:"receipt"`
	CloneDatabase        string                 `json:"cloneDatabase"`
	SnapshotResourceHash string                 `json:"snapshotResourceHash"`
}

func validImportRequest(q migrationImportRequest) bool {
	return q.Version == 1 && validateSnapshotRequest(q.Snapshot) == nil && q.Snapshot.BaseReleaseID != nil && accessHex.MatchString(q.StreamHash) && q.StreamHash != strings.Repeat("0", 64) && digestImage.MatchString(q.CandidateImage)
}
func importCloneDatabase(q migrationImportRequest) string {
	return "app_" + hashBytes([]byte("autosoft:migration-import:v1:" + accessHash(q)))[:24]
}
func emptyImportReceipt(q migrationImportRequest) migrationImportReceipt {
	zero := strings.Repeat("0", 64)
	return migrationImportReceipt{Version: 1, Binding: q, RequestHash: accessHash(q), Status: "pending", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), OldColumnPrimaryHash: zero, LedgerHash: zero, RowDigest: zero, Preservation: "not_proven", MigrationDDL: "not_run", Compatibility: "not_run", WriteQuiescence: "not_run", EpochAdvancement: "not_run", Reason: "import_unavailable"}
}
func validateImportRecord(v migrationImportRecord) error {
	r := v.Receipt
	if !validImportRequest(r.Binding) || r.Version != 1 || r.RequestHash != accessHash(r.Binding) || v.CloneDatabase != importCloneDatabase(r.Binding) || !accessHex.MatchString(v.SnapshotResourceHash) || v.SnapshotResourceHash == strings.Repeat("0", 64) || r.PublicationEligible || r.MigrationDDL != "not_run" || r.Compatibility != "not_run" || r.WriteQuiescence != "not_run" || r.EpochAdvancement != "not_run" || r.Rows < 0 || r.Rows > snapshotMaximumRows || r.Tables < 0 || r.Tables > 64 {
		return snapshotUnavailable
	}
	if _, e := time.Parse(time.RFC3339Nano, r.CheckedAt); e != nil {
		return snapshotUnavailable
	}
	for _, h := range []string{r.OldColumnPrimaryHash, r.LedgerHash, r.RowDigest} {
		if !accessHex.MatchString(h) {
			return snapshotUnavailable
		}
	}
	if r.Status == "imported" {
		if r.Preservation != "snapshot_import_only" || r.Reason != "remaining_contract_required" {
			return snapshotUnavailable
		}
		for _, h := range []string{r.OldColumnPrimaryHash, r.LedgerHash, r.RowDigest} {
			if h == strings.Repeat("0", 64) {
				return snapshotUnavailable
			}
		}
	} else if r.Status == "pending" || r.Status == "quarantined" {
		if r.Preservation != "not_proven" || r.Reason != "import_unavailable" || r.Rows != 0 || r.Tables != 0 || r.OldColumnPrimaryHash != strings.Repeat("0", 64) || r.LedgerHash != strings.Repeat("0", 64) || r.RowDigest != strings.Repeat("0", 64) {
			return snapshotUnavailable
		}
	} else {
		return snapshotUnavailable
	}
	return nil
}

func (s *server) importDirectory(q migrationImportRequest) string {
	return filepath.Join(s.data, "migration-imports", q.Snapshot.AppID, q.Snapshot.AttemptID)
}
func (s *server) readMigrationImport(q migrationImportRequest) (migrationImportRecord, error) {
	var v migrationImportRecord
	if !validImportRequest(q) {
		return v, snapshotUnavailable
	}
	sealed, e := snapshotFile(s, filepath.Join(s.importDirectory(q), "state.enc"), 1<<20)
	if e != nil {
		return v, e
	}
	key, e := vaultKey()
	if e != nil {
		return v, snapshotUnavailable
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return v, snapshotUnavailable
	}
	a, e := cipher.NewGCM(block)
	if e != nil || len(sealed) < a.NonceSize() {
		return v, snapshotUnavailable
	}
	plain, e := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], []byte("autosoft:migration-import:v1:state"))
	if e != nil || importerJSON(plain, &v) != nil || validateImportRecord(v) != nil || !reflect.DeepEqual(v.Receipt.Binding, q) {
		return v, snapshotUnavailable
	}
	return v, nil
}

// The initial exclusive intent is also the cross-process claim. Even a visible
// intent whose directory sync failed blocks another dispatch. No pending or
// quarantined import is resumed automatically.
func (s *server) retainMigrationImport(v migrationImportRecord, initial bool) error {
	if runtime.GOOS != "linux" || validateImportRecord(v) != nil {
		return snapshotUnavailable
	}
	dir := s.importDirectory(v.Receipt.Binding)
	if withdrawalAncestors(s.data, dir, true) != nil {
		return snapshotUnavailable
	}
	file := filepath.Join(dir, "state.enc")
	if !initial {
		info, e := os.Lstat(file)
		if e != nil || !snapshotOrdinary(info, 1<<20) {
			return snapshotUnavailable
		}
	}
	key, e := vaultKey()
	if e != nil {
		return snapshotUnavailable
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return snapshotUnavailable
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return snapshotUnavailable
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return snapshotUnavailable
	}
	plain, e := json.Marshal(v)
	if e != nil || len(plain) > 1<<20 {
		return snapshotUnavailable
	}
	sealed := a.Seal(nonce, nonce, plain, []byte("autosoft:migration-import:v1:state"))
	var f *os.File
	var name string
	if initial {
		f, e = os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		name = file
	} else {
		f, e = os.CreateTemp(dir, ".import-")
		if e == nil {
			name = f.Name()
		}
		defer os.Remove(name)
	}
	if e != nil {
		return snapshotUnavailable
	}
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(sealed)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return snapshotUnavailable
	}
	if !initial && os.Rename(name, file) != nil {
		return snapshotUnavailable
	}
	for d := dir; ; d = filepath.Dir(d) {
		h, e := os.Open(d)
		if e != nil {
			return snapshotUnavailable
		}
		e = h.Sync()
		_ = h.Close()
		if e != nil {
			return snapshotUnavailable
		}
		if d == filepath.Clean(s.data) {
			break
		}
	}
	actual, e := s.readMigrationImport(v.Receipt.Binding)
	if e != nil || !reflect.DeepEqual(actual, v) {
		return snapshotUnavailable
	}
	return nil
}

func (s *server) openImportStream(v migrationSnapshotRecord) (*os.File, error) {
	if validateSnapshotReceipt(v.Receipt) != nil || v.Receipt.Status != "captured" {
		return nil, snapshotUnavailable
	}
	file := filepath.Join(s.snapshotDirectory(v.Receipt.Binding), "rows.enc")
	if withdrawalAncestors(s.data, filepath.Dir(file), false) != nil {
		return nil, snapshotUnavailable
	}
	info, e := os.Lstat(file)
	if e != nil || !snapshotOrdinary(info, snapshotMaximumBytes) || info.Size() != v.Receipt.Bytes {
		return nil, snapshotUnavailable
	}
	f, e := os.Open(file)
	if e != nil {
		return nil, snapshotUnavailable
	}
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		_ = f.Close()
		return nil, snapshotUnavailable
	}
	return f, nil
}

func importerSchemaHash(meta snapshotMetadata) string {
	type table struct {
		Name             string
		Columns, Primary []string
		Definitions      []snapshotColumn
	}
	tables := []table{}
	for _, t := range meta.Tables {
		tables = append(tables, table{t.Name, t.Columns, t.Primary, t.Definitions})
	}
	return accessHash(tables)
}

type migrationImportDatabase interface {
	Prepare(context.Context, string, snapshotMetadata) error
	Insert(context.Context, string, snapshotTable, []any) error
	Proof(context.Context, string, migrationSnapshotRecord, snapshotMetadata) (int, string, error)
	Current(context.Context, migrationSnapshotRecord, snapshotMetadata) error
	Close() error
}
type migrationImportStore interface {
	Read(migrationImportRequest) (migrationImportRecord, error)
	Retain(migrationImportRecord, bool) error
	Stream(migrationSnapshotRecord) (io.ReadCloser, error)
}
type protectedImportStore struct{ s *server }

func (p protectedImportStore) Read(q migrationImportRequest) (migrationImportRecord, error) {
	return p.s.readMigrationImport(q)
}
func (p protectedImportStore) Retain(v migrationImportRecord, initial bool) error {
	return p.s.retainMigrationImport(v, initial)
}
func (p protectedImportStore) Stream(v migrationSnapshotRecord) (io.ReadCloser, error) {
	return p.s.openImportStream(v)
}

func importerRead(ctx context.Context, store migrationImportStore, v migrationSnapshotRecord, row func(snapshotTable, []any) error) (importedSnapshot, error) {
	f, e := store.Stream(v)
	if e != nil {
		return importedSnapshot{}, snapshotUnavailable
	}
	defer f.Close()
	return decodeImportSnapshot(ctx, f, v, row)
}

// All uncertain writes remain one-shot. A subsequent status request performs
// readback only; it cannot create, import, resume DDL or remove a partial clone.
func runMigrationImport(ctx context.Context, q migrationImportRequest, snapshot migrationSnapshotRecord, store migrationImportStore, db migrationImportDatabase) (migrationImportReceipt, error) {
	out := emptyImportReceipt(q)
	if !validImportRequest(q) || !reflect.DeepEqual(q.Snapshot, snapshot.Receipt.Binding) || q.StreamHash != snapshot.Receipt.StreamHash || !accessHex.MatchString(snapshot.ResourceHash) || snapshot.ResourceHash == strings.Repeat("0", 64) {
		return out, snapshotUnavailable
	}
	decoded, e := importerRead(ctx, store, snapshot, nil)
	if e != nil {
		return out, snapshotUnavailable
	}
	if db.Current(ctx, snapshot, decoded.Metadata) != nil {
		return out, snapshotUnavailable
	}
	if retained, e := store.Read(q); e == nil {
		if validateImportRecord(retained) != nil || retained.SnapshotResourceHash != snapshot.ResourceHash {
			return out, snapshotUnavailable
		}
		if retained.Receipt.Status != "imported" {
			return retained.Receipt, snapshotUnavailable
		}
		rows, digest, e := db.Proof(ctx, retained.CloneDatabase, snapshot, decoded.Metadata)
		if e != nil || rows != snapshot.Receipt.Rows || digest != snapshot.Receipt.RowDigest || retained.Receipt.Rows != rows || retained.Receipt.Tables != len(decoded.Metadata.Tables) || retained.Receipt.OldColumnPrimaryHash != importerSchemaHash(decoded.Metadata) || retained.Receipt.LedgerHash != snapshot.Receipt.LedgerHash || retained.Receipt.RowDigest != digest || db.Current(ctx, snapshot, decoded.Metadata) != nil {
			return out, snapshotUnavailable
		}
		if store.Retain(retained, false) != nil {
			return out, snapshotUnavailable
		}
		return retained.Receipt, nil
	} else if !os.IsNotExist(e) {
		return out, snapshotUnavailable
	}
	clone := importCloneDatabase(q)
	if clone == "app_"+hashBytes([]byte(q.Snapshot.AppID))[:24] {
		return out, snapshotUnavailable
	}
	v := migrationImportRecord{Receipt: out, CloneDatabase: clone, SnapshotResourceHash: snapshot.ResourceHash}
	if store.Retain(v, true) != nil {
		return out, snapshotUnavailable
	}
	failImport := func() (migrationImportReceipt, error) {
		v.Receipt = emptyImportReceipt(q)
		v.Receipt.Status = "quarantined"
		_ = store.Retain(v, false)
		return v.Receipt, snapshotUnavailable
	}
	if ctx.Err() != nil || db.Current(ctx, snapshot, decoded.Metadata) != nil || db.Prepare(ctx, clone, decoded.Metadata) != nil {
		return failImport()
	}
	second, e := importerRead(ctx, store, snapshot, func(t snapshotTable, values []any) error { return db.Insert(ctx, clone, t, values) })
	if e != nil || !importerEqual(second, decoded) {
		return failImport()
	}
	rows, digest, e := db.Proof(ctx, clone, snapshot, decoded.Metadata)
	if e != nil || rows != snapshot.Receipt.Rows || digest != snapshot.Receipt.RowDigest || db.Current(ctx, snapshot, decoded.Metadata) != nil || ctx.Err() != nil {
		return failImport()
	}
	v.Receipt.Status = "imported"
	v.Receipt.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	v.Receipt.Preservation = "snapshot_import_only"
	v.Receipt.Reason = "remaining_contract_required"
	v.Receipt.Rows = rows
	v.Receipt.Tables = len(decoded.Metadata.Tables)
	v.Receipt.RowDigest = digest
	v.Receipt.LedgerHash = snapshot.Receipt.LedgerHash
	v.Receipt.OldColumnPrimaryHash = importerSchemaHash(decoded.Metadata)
	if store.Retain(v, false) != nil {
		return failImport()
	}
	return v.Receipt, nil
}

type sqlMigrationImport struct {
	s        *server
	db       *sql.DB
	c        *sql.Conn
	clone    string
	prepared bool
	tables   map[string]snapshotTable
}

func (p *sqlMigrationImport) Close() error {
	if p.c != nil {
		_ = p.c.Close()
	}
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}
func (p *sqlMigrationImport) connection(ctx context.Context) error {
	if p.c != nil {
		return nil
	}
	db, e := importerAdmin(p.s)
	if e != nil {
		return snapshotUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	c, e := db.Conn(ctx)
	if e != nil {
		_ = db.Close()
		return snapshotUnavailable
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = c.Close()
			_ = db.Close()
		}
	}()
	if importerSession(ctx, c) != nil {
		return snapshotUnavailable
	}
	for _, q := range []string{"SET SESSION time_zone='+00:00'", "SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_BACKSLASH_ESCAPES'"} {
		if _, e = c.ExecContext(ctx, q); e != nil {
			return snapshotUnavailable
		}
	}
	p.db, p.c = db, c
	accepted = true
	return nil
}
func importerAdmin(s *server) (*sql.DB, error) {
	if s.snapshotAdminOpen != nil {
		return s.snapshotAdminOpen()
	}
	password, e := secret("MYSQL_PROVISIONER_PASSWORD")
	if e != nil {
		password, e = secret("MYSQL_PASSWORD")
	}
	if e != nil {
		return nil, snapshotUnavailable
	}
	user := env("MYSQL_USER", "provisioner")
	registered, e := mysqlConnectionAs(user, password)
	if e != nil {
		return nil, snapshotUnavailable
	}
	_ = registered.Close()
	cfg := importerAdminConfig(user, password)
	return sql.Open("mysql", cfg.FormatDSN())
}
func importerAdminConfig(user, password string) *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(env("MYSQL_HOST", "mysql"), env("MYSQL_PORT", "3306"))
	cfg.TLSConfig = "autosoft-verified"
	cfg.Timeout = 15 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.ParseTime = false
	cfg.MultiStatements = false
	return cfg
}
func importerSession(ctx context.Context, c *sql.Conn) error {
	var partial, secure bool
	var mandatory string
	if c.QueryRowContext(ctx, "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport").Scan(&partial, &mandatory, &secure) != nil || partial || mandatory != "" || !secure {
		return snapshotUnavailable
	}
	user := env("MYSQL_USER", "provisioner")
	if !identity.MatchString(user) {
		return snapshotUnavailable
	}
	// Authenticate the existing fixed company account and TLS endpoint. This
	// does not introduce an app account, reset a password or change privileges.
	var current, role, status, cipher string
	if c.QueryRowContext(ctx, "SELECT CURRENT_USER(), CURRENT_ROLE()").Scan(&current, &role) != nil || current != user+"@%" || role != "NONE" || c.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&status, &cipher) != nil || status != "Ssl_cipher" || cipher == "" || len(cipher) > 256 {
		return snapshotUnavailable
	}
	var autocommit bool
	if c.QueryRowContext(ctx, "SELECT @@SESSION.autocommit").Scan(&autocommit) != nil || !autocommit {
		return snapshotUnavailable
	}
	return nil
}
func importerCloneAudit(ctx context.Context, c *sql.Conn, database string, encrypted bool) error {
	if !applicationSQLDatabase.MatchString(database) || importerSession(ctx, c) != nil {
		return snapshotUnavailable
	}
	rows, e := c.QueryContext(ctx, "SHOW GRANTS")
	if e != nil {
		return snapshotUnavailable
	}
	grants := []string{}
	for rows.Next() {
		var g string
		if rows.Scan(&g) != nil || len(grants) >= 16 || len(g) > 16384 {
			_ = rows.Close()
			return snapshotUnavailable
		}
		grants = append(grants, g)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil || !importerProvisionerGrants(env("MYSQL_USER", "provisioner"), database, grants) {
		return snapshotUnavailable
	}
	if encrypted {
		var name, encryption string
		if c.QueryRowContext(ctx, "SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&name, &encryption) != nil || name != database || encryption != "Y" && encryption != "YES" {
			return snapshotUnavailable
		}
	}
	return nil
}
func importerProvisionerGrants(user, database string, grants []string) bool {
	if !identity.MatchString(user) || !applicationSQLDatabase.MatchString(database) || len(grants) == 0 {
		return false
	}
	needed := map[string]bool{"CREATE": false, "INSERT": false, "SELECT": false}
	allowed := map[string]bool{"CREATE": true, "ALTER": true, "INDEX": true, "SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "REFERENCES": true}
	for _, g := range grants {
		if strings.ContainsAny(g, "\x00\r\n\t") || len(g) > 16384 {
			return false
		}
		g = strings.TrimSuffix(g, " WITH GRANT OPTION")
		body := ""
		for _, account := range []string{"`" + user + "`@`%`", "'" + user + "'@'%'"} {
			if strings.HasSuffix(g, " TO "+account) {
				body = strings.TrimSuffix(g, " TO "+account)
			}
		}
		if !strings.HasPrefix(body, "GRANT ") {
			return false
		}
		privileges, scope, ok := strings.Cut(strings.TrimPrefix(body, "GRANT "), " ON ")
		if !ok {
			return false
		}
		if scope == "*.*" {
			if privileges != "USAGE" && privileges != "CREATE USER" {
				return false
			}
			continue
		}
		if scope != "`app\\_%`.*" && scope != "`app\\_"+database[4:]+"`.*" {
			return false
		}
		seen := map[string]bool{}
		for _, p := range strings.Split(privileges, ",") {
			p = strings.TrimSpace(p)
			if !allowed[p] || seen[p] {
				return false
			}
			seen[p] = true
			if _, ok := needed[p]; ok {
				needed[p] = true
			}
		}
	}
	return needed["CREATE"] && needed["SELECT"] && needed["INSERT"]
}
func (p *sqlMigrationImport) Prepare(ctx context.Context, database string, meta snapshotMetadata) error {
	if database != p.clone || p.prepared || !applicationSQLDatabase.MatchString(database) || importerTables(meta) != nil || p.connection(ctx) != nil {
		return snapshotUnavailable
	}
	if importerCloneAudit(ctx, p.c, database, false) != nil {
		return snapshotUnavailable
	}
	var n int
	if p.c.QueryRowContext(ctx, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&n) != nil || n != 0 {
		return snapshotUnavailable
	}
	// No IF NOT EXISTS: an independently created collision is unavailable.
	if _, e := p.c.ExecContext(ctx, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4 ENCRYPTION='Y'"); e != nil {
		return snapshotUnavailable
	}
	var encryption string
	if p.c.QueryRowContext(ctx, "SELECT DEFAULT_ENCRYPTION FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&encryption) != nil || encryption != "Y" && encryption != "YES" {
		return snapshotUnavailable
	}
	for _, t := range meta.Tables {
		ddl, e := importerCreateTable(database, t)
		if e != nil {
			return e
		}
		if _, e = p.c.ExecContext(ctx, ddl); e != nil {
			return snapshotUnavailable
		}
	}
	p.tables = map[string]snapshotTable{}
	for _, t := range meta.Tables {
		p.tables[t.Name] = t
	}
	p.prepared = true
	return nil
}
func (p *sqlMigrationImport) Insert(ctx context.Context, database string, t snapshotTable, values []any) error {
	if p.c == nil || !p.prepared || database != p.clone || !importerEqual(p.tables[t.Name], t) {
		return snapshotUnavailable
	}
	return importerInsert(ctx, p.c, database, t, values)
}
func (p *sqlMigrationImport) Current(ctx context.Context, v migrationSnapshotRecord, meta snapshotMetadata) error {
	if ctx.Err() != nil || p.s.snapshotContext(v.Receipt.Binding) != nil {
		return snapshotUnavailable
	}
	resource, e := snapshotFile(p.s, filepath.Join(p.s.data, "resources", v.Receipt.Binding.AppID+".enc"), 1<<20)
	if e != nil || hashBytes(resource) != v.ResourceHash {
		return snapshotUnavailable
	}
	account, exists, e := p.s.snapshotAccount(v.Receipt.Binding.AppID)
	if e != nil || !exists || account.Schema != v.Receipt.SchemaEpoch {
		return snapshotUnavailable
	}
	db, e := p.s.snapshotDatabase(account)
	if e != nil {
		return snapshotUnavailable
	}
	defer db.Close()
	if p.s.auditSnapshotAccount(ctx, account, db) != nil || p.s.auditSnapshotObjects(ctx, account) != nil {
		return snapshotUnavailable
	}
	c, e := db.Conn(ctx)
	if e != nil {
		return snapshotUnavailable
	}
	defer c.Close()
	actual, e := snapshotMetadataRead(ctx, c, account.Database)
	if e != nil || !importerEqual(actual, meta) || p.s.snapshotContext(v.Receipt.Binding) != nil || ctx.Err() != nil {
		return snapshotUnavailable
	}
	return nil
}
func (p *sqlMigrationImport) Proof(ctx context.Context, database string, v migrationSnapshotRecord, meta snapshotMetadata) (int, string, error) {
	if database != p.clone || !applicationSQLDatabase.MatchString(database) || importerTables(meta) != nil || p.connection(ctx) != nil || importerCloneAudit(ctx, p.c, database, true) != nil {
		return 0, "", snapshotUnavailable
	}
	before, e := snapshotMetadataRead(ctx, p.c, database)
	if e != nil || importerTables(before) != nil || importerSchemaHash(before) != importerSchemaHash(meta) || !reflect.DeepEqual(before.Ledger, meta.Ledger) {
		return 0, "", snapshotUnavailable
	}
	for _, q := range []string{"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"} {
		if _, e = p.c.ExecContext(ctx, q); e != nil {
			return 0, "", snapshotUnavailable
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = p.c.ExecContext(cleanup, "ROLLBACK")
	}()
	actual, e := snapshotMetadataRead(ctx, p.c, database)
	if e != nil || !importerEqual(actual, before) || importerTables(actual) != nil {
		return 0, "", snapshotUnavailable
	}
	digest := importerDigest(v.Key, v.Receipt.RequestHash)
	total := 0
	for _, t := range meta.Tables {
		cols, pk, lengths := []string{}, []string{}, []string{}
		for _, name := range t.Columns {
			cols = append(cols, "`"+name+"`")
			lengths = append(lengths, "COALESCE(OCTET_LENGTH(`"+name+"`),0)")
		}
		for _, name := range t.Primary {
			pk = append(pk, "`"+name+"`")
		}
		var maximum, count int64
		if p.c.QueryRowContext(ctx, "SELECT COALESCE(MAX("+strings.Join(lengths, "+")+"),0), COUNT(*) FROM `"+database+"`.`"+t.Name+"`").Scan(&maximum, &count) != nil || maximum < 0 || maximum > 512<<10 || count < 0 || count > int64(snapshotMaximumRows-total) {
			return 0, "", snapshotUnavailable
		}
		rows, e := p.c.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM `"+database+"`.`"+t.Name+"` ORDER BY "+strings.Join(pk, ","))
		if e != nil {
			return 0, "", snapshotUnavailable
		}
		seen := int64(0)
		for rows.Next() {
			if ctx.Err() != nil || total >= snapshotMaximumRows {
				_ = rows.Close()
				return 0, "", snapshotUnavailable
			}
			raw := make([]sql.RawBytes, len(t.Columns))
			dest := make([]any, len(raw))
			for i := range raw {
				dest[i] = &raw[i]
			}
			if rows.Scan(dest...) != nil {
				_ = rows.Close()
				return 0, "", snapshotUnavailable
			}
			values := make([]any, len(raw))
			size := 0
			for i, b := range raw {
				size += len(b)
				if size > 512<<10 {
					_ = rows.Close()
					return 0, "", snapshotUnavailable
				}
				if b != nil {
					values[i] = append([]byte{}, b...)
				}
			}
			if importerDigestRow(digest, t.Name, values) != nil {
				_ = rows.Close()
				return 0, "", snapshotUnavailable
			}
			total++
			seen++
		}
		e = rows.Err()
		_ = rows.Close()
		if e != nil || seen != count {
			return 0, "", snapshotUnavailable
		}
	}
	if _, e = p.c.ExecContext(ctx, "ROLLBACK"); e != nil {
		return 0, "", snapshotUnavailable
	}
	after, e := snapshotMetadataRead(ctx, p.c, database)
	if e != nil || !importerEqual(after, actual) || importerCloneAudit(ctx, p.c, database, true) != nil || ctx.Err() != nil {
		return 0, "", snapshotUnavailable
	}
	return total, hex.EncodeToString(digest.Sum(nil)), nil
}

// This internal entry point consumes only the exact retained verification and
// capture. Registration in the authenticated broker API is a separate change.
func (s *server) importMigrationSnapshot(ctx context.Context, q migrationImportRequest) (migrationImportReceipt, error) {
	out := emptyImportReceipt(q)
	if !validImportRequest(q) || ctx.Err() != nil {
		return out, snapshotUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	// This internal entry point acquires the same app lock without an unbounded
	// wait. A caller already holding that lock must use a future reviewed hook.
	value, _ := s.locks.LoadOrStore("app-"+q.Snapshot.AppID, new(sync.Mutex))
	lock, ok := value.(*sync.Mutex)
	if !ok || !lock.TryLock() {
		return out, snapshotUnavailable
	}
	defer lock.Unlock()
	if ctx.Err() != nil || s.snapshotContext(q.Snapshot) != nil {
		return out, snapshotUnavailable
	}
	b, e := snapshotFile(s, filepath.Join(s.data, "receipts", q.Snapshot.AttemptID+".json"), 1<<20)
	var verification Verification
	if e != nil || importerJSON(b, &verification) != nil || verification.AppID != q.Snapshot.AppID || verification.AttemptID != q.Snapshot.AttemptID || verification.SourceHash != q.Snapshot.SourceHash || len(verification.Images) != 1 || verification.Images[0] != q.CandidateImage || migrationSetHash(verification.Migrations) != q.Snapshot.MigrationHash || verification.MigrationSnapshot == nil || !reflect.DeepEqual(verification.MigrationSnapshot.Binding, q.Snapshot) {
		return out, snapshotUnavailable
	}
	v, e := s.readSnapshot(q.Snapshot)
	if e != nil || !reflect.DeepEqual(v.Receipt, *verification.MigrationSnapshot) || v.Receipt.StreamHash != q.StreamHash || v.Receipt.Status != "captured" {
		return out, snapshotUnavailable
	}
	db := &sqlMigrationImport{s: s, clone: importCloneDatabase(q)}
	defer db.Close()
	return runMigrationImport(ctx, q, v, protectedImportStore{s}, db)
}
