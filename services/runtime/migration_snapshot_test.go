package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type snapshotSQLFixture struct {
	value                                resources
	ledger                               map[string]string
	events                               []string
	connections, metadataReads, writes   int
	engine, extra, rawType, createSuffix string
	noPrimary, missingDatabase           bool
	triggers, foreignKeys                int
	maximumRaw, tableRows                int64
	adminNoVisibility, partialRevokes    bool
	hook                                 func(string)
}
type snapshotConnector struct {
	f    *snapshotSQLFixture
	kind string
}

func (c snapshotConnector) Connect(context.Context) (driver.Conn, error) {
	c.f.connections++
	return &snapshotConnection{c.f, c.kind, c.f.connections}, nil
}
func (snapshotConnector) Driver() driver.Driver { return grantSQLDriver{} }

type snapshotConnection struct {
	f    *snapshotSQLFixture
	kind string
	id   int
}

func (*snapshotConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("no preparation")
}
func (*snapshotConnection) Close() error { return nil }
func (*snapshotConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("must use exact read-only snapshot")
}
func (c *snapshotConnection) ExecContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.f.events = append(c.f.events, q)
	if c.f.hook != nil {
		c.f.hook(q)
	}
	switch q {
	case "SET SESSION time_zone='+00:00'", "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY", "ROLLBACK":
		return driver.RowsAffected(0), nil
	}
	c.f.writes++
	return nil, errors.New("fixture forbids all data/DDL/privilege writes")
}
func (c *snapshotConnection) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f := c.f
	f.events = append(f.events, q)
	if f.hook != nil {
		f.hook(q)
	}
	result := func(columns []string, values ...[]driver.Value) (driver.Rows, error) {
		return &grantSQLRows{columns: columns, values: values}, nil
	}
	user := f.value.User
	if c.kind == "auditor" {
		user = "snapshot_auditor"
	} else if c.kind == "admin" {
		user = "provisioner"
	}
	if strings.Contains(q, "INFORMATION_SCHEMA.") && len(args) > 0 && args[0].Value != f.value.Database {
		return nil, errors.New("foreign schema query")
	}
	switch {
	case q == "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport":
		return result([]string{"partial", "mandatory", "secure"}, []driver.Value{f.partialRevokes, "", true})
	case q == "SHOW SESSION STATUS LIKE 'Ssl_cipher'":
		return result([]string{"name", "value"}, []driver.Value{"Ssl_cipher", "TLS_AES_256_GCM_SHA384"})
	case q == "SELECT CURRENT_USER(), CURRENT_ROLE()":
		return result([]string{"user", "roles"}, []driver.Value{user + "@%", "NONE"})
	case q == "SHOW GRANTS":
		scope, _ := applicationSQLScope(f.value.AppID, f.value.Database, f.value.User)
		rights := "SELECT, INSERT, UPDATE"
		if c.kind == "auditor" {
			rights = "SELECT, TRIGGER"
		} else if c.kind == "admin" {
			if f.adminNoVisibility {
				return result([]string{"grant"}, []driver.Value{"GRANT CREATE USER ON *.* TO 'provisioner'@'%'"})
			}
			return result([]string{"grant"}, []driver.Value{"GRANT CREATE USER ON *.* TO 'provisioner'@'%'"}, []driver.Value{"GRANT CREATE, ALTER, INDEX, SELECT, INSERT, UPDATE, DELETE, REFERENCES ON `app\\_%`.* TO 'provisioner'@'%' WITH GRANT OPTION"})
		}
		return result([]string{"grant"}, []driver.Value{"GRANT USAGE ON *.* TO '" + user + "'@'%'"}, []driver.Value{"GRANT " + rights + " ON " + scope + " TO '" + user + "'@'%'"})
	case strings.HasPrefix(q, "SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION"):
		if f.missingDatabase {
			return result([]string{"name", "encryption"})
		}
		return result([]string{"name", "encryption"}, []driver.Value{f.value.Database, "Y"})
	case strings.HasPrefix(q, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA"):
		n := int64(1)
		if f.missingDatabase {
			n = 0
		}
		return result([]string{"count"}, []driver.Value{n})
	case strings.Contains(q, "INFORMATION_SCHEMA.TRIGGERS"):
		return result([]string{"count"}, []driver.Value{int64(f.triggers)})
	case strings.Contains(q, "INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS"):
		return result([]string{"count"}, []driver.Value{int64(f.foreignKeys)})
	case strings.Contains(q, "INFORMATION_SCHEMA.TABLES"):
		f.metadataReads++
		engine := f.engine
		if engine == "" {
			engine = "InnoDB"
		}
		values := [][]driver.Value{}
		if f.ledger != nil {
			values = append(values, []driver.Value{"_autosoft_migrations", engine, "BASE TABLE"})
		}
		values = append(values, []driver.Value{"records", engine, "BASE TABLE"})
		return result([]string{"name", "engine", "type"}, values...)
	case strings.HasPrefix(q, "SHOW CREATE TABLE"):
		name := "records"
		if strings.Contains(q, "_autosoft_migrations") {
			name = "_autosoft_migrations"
		}
		return result([]string{"table", "create"}, []driver.Value{name, "CREATE TABLE `" + name + "` (id VARCHAR(80) PRIMARY KEY) ENCRYPTION='Y'" + f.createSuffix})
	case strings.Contains(q, "INFORMATION_SCHEMA.COLUMNS"):
		name := args[1].Value.(string)
		values := [][]driver.Value{}
		columns := []string{"id", "amount", "payload", "optional"}
		types := []string{"varchar", "decimal", "varbinary", "varchar"}
		if name == "_autosoft_migrations" {
			columns = []string{"id", "checksum"}
			types = []string{"varchar", "char"}
		}
		for i, col := range columns {
			extra, kind := "", types[i]
			if name == "records" && i == 0 {
				extra = f.extra
				if f.rawType != "" {
					kind = f.rawType
				}
			}
			values = append(values, []driver.Value{col, kind, kind, "YES", nil, nil, nil, extra, "", int64(i + 1)})
		}
		return result([]string{"name", "type", "fulltype", "nullable", "default", "charset", "collation", "extra", "generation", "ordinal"}, values...)
	case strings.Contains(q, "INFORMATION_SCHEMA.STATISTICS"):
		if f.noPrimary {
			return result([]string{"column", "seq", "part"})
		}
		return result([]string{"column", "seq", "part"}, []driver.Value{"id", int64(1), nil})
	case strings.HasPrefix(q, "SELECT id, checksum FROM"):
		values := [][]driver.Value{}
		for _, id := range []string{"m1", "m2"} {
			if sum, ok := f.ledger[id]; ok {
				values = append(values, []driver.Value{id, sum})
			}
		}
		return result([]string{"id", "checksum"}, values...)
	case strings.HasPrefix(q, "SELECT COALESCE(MAX("):
		count := int64(2)
		maximum := int64(100)
		if f.maximumRaw != 0 {
			maximum = f.maximumRaw
		}
		if f.tableRows != 0 {
			count = f.tableRows
		}
		if strings.Contains(q, "_autosoft_migrations") {
			count = int64(len(f.ledger))
		}
		return result([]string{"maximum", "count"}, []driver.Value{maximum, count})
	case strings.Contains(q, "FROM `"+f.value.Database+"`.`records` ORDER BY `id`"):
		return result([]string{"id", "amount", "payload", "optional"}, []driver.Value{[]byte("private-business-canary"), []byte("999999999999999999.123400"), []byte{0, 255, 1}, nil}, []driver.Value{[]byte("second"), []byte("0.000000"), []byte{}, []byte{}})
	case strings.Contains(q, "FROM `"+f.value.Database+"`.`_autosoft_migrations` ORDER BY `id`"):
		values := [][]driver.Value{}
		for _, id := range []string{"m1", "m2"} {
			if sum, ok := f.ledger[id]; ok {
				values = append(values, []driver.Value{[]byte(id), []byte(sum)})
			}
		}
		return result([]string{"id", "checksum"}, values...)
	}
	return nil, errors.New("unknown fixed query")
}
func snapshotFixture(t *testing.T) (*server, *snapshotSQLFixture, migrationSnapshotRequest) {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	t.Setenv("MYSQL_SNAPSHOT_AUDITOR_USER", "snapshot_auditor")
	t.Setenv("MYSQL_USER", "provisioner")
	app := "app1"
	hash := sha256.Sum256([]byte(app))
	name := "app_" + hex.EncodeToString(hash[:])[:24]
	v := resources{AppID: app, Database: name, User: name, Password: strings.Repeat("a", 64), MySQLGrantVersion: 1, MySQLGrantVerified: true, Schema: 1, Applied: map[string]string{}}
	f := &snapshotSQLFixture{value: v, ledger: map[string]string{}}
	s := &server{data: root, token: "trusted-token", approvalKey: bytes.Repeat([]byte{4}, 32)}
	s.snapshotOpen = func(resources) (*sql.DB, error) { return sql.OpenDB(snapshotConnector{f, "own"}), nil }
	s.snapshotAdminOpen = func() (*sql.DB, error) { return sql.OpenDB(snapshotConnector{f, "admin"}), nil }
	s.snapshotAuditorOpen = func() (*sql.DB, error) { return sql.OpenDB(snapshotConnector{f, "auditor"}), nil }
	source := filepath.Join(root, "sources", "attempt1")
	_ = os.MkdirAll(source, 0700)
	_ = os.WriteFile(filepath.Join(source, "app.manifest.json"), []byte("{}"), 0600)
	h, e := sourceDigest(source)
	if e != nil {
		t.Fatal(e)
	}
	q := migrationSnapshotRequest{Version: 1, AppID: app, JobID: "job1", AttemptID: "attempt1", Fence: 2, SourceHash: h, MigrationHash: migrationSetHash([]Migration{})}
	if e = s.acceptFence(app, q.JobID, q.AttemptID, q.Fence); e != nil {
		t.Fatal(e)
	}
	return s, f, q
}
func retainSnapshotResource(t *testing.T, s *server, f *snapshotSQLFixture) {
	t.Helper()
	if e := writeEncrypted(filepath.Join(s.data, "resources", f.value.AppID+".enc"), f.value); e != nil {
		t.Fatal(e)
	}
}
func TestMigrationSnapshotGoldenAndNoFalseCertificates(t *testing.T) {
	q := migrationSnapshotRequest{Version: 1, AppID: "app1", JobID: "job1", AttemptID: "attempt1", Fence: 2, SourceHash: strings.Repeat("c", 64), MigrationHash: migrationSetHash([]Migration{})}
	if accessHash(q) != "dada73995c93f5d3c9ee42340a5f56b0af2b5b40b1c7f1583fd1ec7853d2143a" {
		t.Fatal("cross-language hash drift")
	}
	m := []Migration{{ID: "add_a", Checksum: strings.Repeat("a", 64)}, {ID: "add_b", Checksum: strings.Repeat("b", 64)}}
	if migrationSetHash(m) != "3b51ff005b9cd381eeba647dcfc5a39975601f94f2b58fd27e105a8ccfcfc400" {
		t.Fatal("nonempty ordered cross-language migration hash drift")
	}
	base := "release1"
	nonempty := q
	nonempty.BaseReleaseID = &base
	nonempty.BaseHash = strings.Repeat("d", 64)
	nonempty.BaseImage = "registry.test/app@sha256:" + strings.Repeat("e", 64)
	nonempty.MigrationHash = migrationSetHash(m)
	if accessHash(nonempty) != "f177aa42aed8096812b190c02b163f5ae2bd5ba66f0978e49bbf3c076eeb4e55" {
		t.Fatal("exact base/request cross-language hash drift")
	}
	r := emptySnapshot(q)
	if validateSnapshotReceipt(r) != nil {
		t.Fatal("valid pending refused")
	}
	badPending := r
	badPending.Unapplied = []string{"m1"}
	if validateSnapshotReceipt(badPending) == nil {
		t.Fatal("pending receipt carried unapplied evidence")
	}
	r.Status = "captured"
	r.Preservation = "captured_only"
	r.Reason = "none"
	r.Bytes = 20
	for _, h := range []*string{&r.SchemaHash, &r.LedgerHash, &r.StreamHash, &r.RowDigest} {
		*h = strings.Repeat("a", 64)
	}
	if validateSnapshotReceipt(r) != nil {
		t.Fatal("valid capture refused")
	}
	for _, change := range []func(*migrationSnapshotReceipt){func(v *migrationSnapshotReceipt) { v.PublicationEligible = true }, func(v *migrationSnapshotReceipt) { v.Preservation = "preserved" }, func(v *migrationSnapshotReceipt) { v.Compatibility = "passed" }, func(v *migrationSnapshotReceipt) { v.SchemaHash = strings.Repeat("0", 64) }, func(v *migrationSnapshotReceipt) { v.Unapplied = []string{"m1"} }, func(v *migrationSnapshotReceipt) { v.Rows = 100001 }} {
		copy := r
		change(&copy)
		if validateSnapshotReceipt(copy) == nil {
			t.Fatal("fake capture accepted")
		}
	}
}
func TestMigrationSnapshotTypedMetadataLimits(t *testing.T) {
	for _, variant := range []string{"valid", "non_innodb", "auto_increment", "generated", "unsupported_type", "foreign_key", "no_primary"} {
		t.Run(variant, func(t *testing.T) {
			s, f, _ := snapshotFixture(t)
			switch variant {
			case "non_innodb":
				f.engine = "MyISAM"
			case "auto_increment":
				f.extra = "auto_increment"
			case "generated":
				f.extra = "STORED GENERATED"
			case "unsupported_type":
				f.rawType = "geometry"
			case "foreign_key":
				f.createSuffix = " FOREIGN KEY (id) REFERENCES other(id)"
			case "no_primary":
				f.noPrimary = true
			}
			db, _ := s.snapshotDatabase(f.value)
			defer db.Close()
			c, e := db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			meta, e := snapshotMetadataRead(context.Background(), c, f.value.Database)
			if (e == nil) != (variant == "valid") {
				t.Fatalf("unexpected metadata result: %v", e)
			}
			if variant == "valid" && (len(meta.Tables) != 2 || meta.Tables[1].Definitions[1].DataType != "decimal") {
				t.Fatal("typed precision metadata missing")
			}
			if f.writes != 0 {
				t.Fatal("metadata changed DB")
			}
		})
	}
}
func TestMigrationSnapshotAuditorVisibilityIsNotAssumed(t *testing.T) {
	s, f, _ := snapshotFixture(t)
	if s.auditSnapshotObjects(context.Background(), f.value) != nil {
		t.Fatal("exact auditor refused")
	}
	for _, bad := range []string{"missing", "triggers", "foreign_keys", "global", "legacy_scope", "extra_right"} {
		t.Run(bad, func(t *testing.T) {
			s, f, _ := snapshotFixture(t)
			switch bad {
			case "missing":
				t.Setenv("MYSQL_SNAPSHOT_AUDITOR_USER", "")
			case "triggers":
				f.triggers = 1
			case "foreign_keys":
				f.foreignKeys = 1
			default:
				scope, _ := applicationSQLScope(f.value.AppID, f.value.Database, f.value.User)
				g := "GRANT SELECT, TRIGGER ON " + scope + " TO 'snapshot_auditor'@'%'"
				if bad == "global" {
					g = "GRANT SELECT, TRIGGER ON *.* TO 'snapshot_auditor'@'%'"
				}
				if bad == "legacy_scope" {
					g = strings.Replace(g, "app\\_", "app_", 1)
				}
				if bad == "extra_right" {
					g = strings.Replace(g, "SELECT, TRIGGER", "SELECT, TRIGGER, UPDATE", 1)
				}
				if snapshotAuditorGrants("snapshot_auditor", scope, []string{g}) {
					t.Fatal("broadened auditor accepted")
				}
				return
			}
			if s.auditSnapshotObjects(context.Background(), f.value) == nil {
				t.Fatal("absence inferred without complete visibility")
			}
		})
	}
}
func TestMigrationSnapshotEncryptedRowsPreserveRawPrecisionAndNull(t *testing.T) {
	s, f, q := snapshotFixture(t)
	db, _ := s.snapshotDatabase(f.value)
	defer db.Close()
	c, _ := db.Conn(context.Background())
	defer c.Close()
	meta, e := snapshotMetadataRead(context.Background(), c, f.value.Database)
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(filepath.Join(t.TempDir(), "stream"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	key := bytes.Repeat([]byte{8}, 32)
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	w := snapshotStream{file: file, a: a, prefix: bytes.Repeat([]byte{9}, 8), digest: sha256.New(), binding: accessHash(q)}
	count, digest, e := captureSnapshotRows(context.Background(), c, f.value.Database, meta, &w, key)
	if e != nil || count != 2 || !accessHex.MatchString(digest) {
		t.Fatalf("capture failed %v", e)
	}
	_, _ = file.Seek(0, 0)
	encrypted, _ := io.ReadAll(file)
	if bytes.Contains(encrypted, []byte("private-business-canary")) || bytes.Contains(encrypted, []byte("999999999999999999.123400")) {
		t.Fatal("plaintext written")
	}
	plaintext := []map[string]any{}
	seq := uint32(0)
	for len(encrypted) > 0 {
		n := int(binary.BigEndian.Uint32(encrypted[:4]))
		nonce := append(append([]byte{}, w.prefix...), make([]byte, 4)...)
		binary.BigEndian.PutUint32(nonce[8:], seq)
		p, e := a.Open(nil, nonce, encrypted[4:4+n], []byte(qHashSequence(w.binding, seq)))
		if e != nil {
			t.Fatal(e)
		}
		var value map[string]any
		_ = json.Unmarshal(p, &value)
		if value["type"] == "row" {
			plaintext = append(plaintext, value)
		}
		encrypted = encrypted[4+n:]
		seq++
	}
	values := plaintext[0]["values"].([]any)
	if values[1] != base64.StdEncoding.EncodeToString([]byte("999999999999999999.123400")) || values[2] != base64.StdEncoding.EncodeToString([]byte{0, 255, 1}) || values[3] != nil {
		t.Fatal("raw decimal/binary/NULL changed")
	}
	if plaintext[1]["values"].([]any)[3] != "" {
		t.Fatal("empty value conflated with NULL")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e = captureSnapshotRows(ctx, c, f.value.Database, meta, &w, key); e == nil {
		t.Fatal("cancelled capture accepted")
	}
}
func qHashSequence(binding string, sequence uint32) string {
	return fmt.Sprintf("%s:%d", binding, sequence)
}
func TestMigrationAdmissionBlocksUnappliedAndChangedHistoryBeforeAnyWrites(t *testing.T) {
	for _, variant := range []string{"already_applied", "unapplied", "changed_checksum", "deleted_old_definition", "ledger_drift", "malformed_resource", "orphan_database", "fresh", "active_without_resource"} {
		t.Run(variant, func(t *testing.T) {
			s, f, _ := snapshotFixture(t)
			m := Migration{ID: "m1", Checksum: strings.Repeat("d", 64)}
			f.ledger["m1"] = m.Checksum
			f.value.Applied["m1"] = m.Checksum
			migrations := []Migration{m}
			switch variant {
			case "unapplied":
				migrations = append(migrations, Migration{ID: "m2", Checksum: strings.Repeat("e", 64)})
			case "changed_checksum":
				migrations[0].Checksum = strings.Repeat("e", 64)
			case "deleted_old_definition":
				migrations = []Migration{}
			case "ledger_drift":
				f.value.Applied = map[string]string{}
			case "fresh":
				f.missingDatabase = true
			case "active_without_resource":
				f.missingDatabase = true
				_ = atomicJSON(filepath.Join(s.data, "active", "app1.json"), activeDeployment{ReleaseID: "release1"})
			}
			if variant != "fresh" && variant != "orphan_database" && variant != "active_without_resource" {
				retainSnapshotResource(t, s, f)
			}
			if variant == "malformed_resource" {
				_ = os.WriteFile(filepath.Join(s.data, "resources", "app1.enc"), []byte("broken"), 0600)
			}
			fresh, e := s.migrationAdmission(context.Background(), "app1", migrations, nil, true)
			if (e == nil) != (variant == "fresh" || variant == "already_applied") {
				t.Fatalf("unexpected admission %v", e)
			}
			if e == nil && fresh != (variant == "fresh") {
				t.Fatal("bad genesis classification")
			}
			if f.writes != 0 {
				t.Fatal("live DDL/permission/record mutation")
			}
		})
	}
}
func TestMigrationSnapshotContextAndRouteRefusalNeverQueriesForeignDB(t *testing.T) {
	s, f, q := snapshotFixture(t)
	if s.snapshotContext(q) != nil {
		t.Fatal("valid context refused")
	}
	q.Fence++
	if s.snapshotContext(q) == nil {
		t.Fatal("stale fence accepted")
	}
	q.Fence--
	q.SourceHash = strings.Repeat("a", 64)
	if s.snapshotContext(q) == nil {
		t.Fatal("source drift accepted")
	}
	mux := http.NewServeMux()
	s.registerMigrationSnapshotRoutes(mux)
	for _, route := range []string{"/v1/migrations/snapshot", "/v1/migrations/snapshot-status"} {
		request := httptest.NewRequest("GET", route, nil)
		request.Header.Set("Authorization", "Bearer "+s.token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, request)
		if w.Code != 405 || f.connections != 0 {
			t.Fatal("non-POST snapshot authority accepted")
		}
	}
	q.AppID = "app2"
	body, _ := json.Marshal(q)
	h := hmac.New(sha256.New, s.approvalKey)
	_, _ = h.Write(body)
	request := httptest.NewRequest("POST", "/v1/migrations/snapshot", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("X-Autosoft-Proof", hex.EncodeToString(h.Sum(nil)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, request)
	if w.Code != 409 || f.connections != 0 || strings.Contains(w.Body.String(), "private-business") {
		t.Fatal("foreign/unbound snapshot reached DB")
	}
}
func TestMigrationSnapshotDatabaseAbsenceRequiresVisibleNamespace(t *testing.T) {
	for _, variant := range []string{"visible", "hidden", "different_semantics"} {
		t.Run(variant, func(t *testing.T) {
			s, f, _ := snapshotFixture(t)
			f.missingDatabase = true
			f.adminNoVisibility = variant == "hidden"
			f.partialRevokes = variant == "different_semantics"
			err := s.absentApplicationDatabase(context.Background(), "app1")
			if (err == nil) != (variant == "visible") {
				t.Fatal("filtered zero treated as database absence")
			}
			if variant != "visible" {
				for _, q := range f.events {
					if strings.HasPrefix(q, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA") {
						t.Fatal("unproven namespace queried as genuine absence")
					}
				}
			}
			if f.writes != 0 {
				t.Fatal("visibility audit mutated permissions")
			}
		})
	}
}
func TestMigrationAdmissionHistoricalRecoveryNeedsOnlyActualLedger(t *testing.T) {
	s, f, _ := snapshotFixture(t)
	f.ledger["m1"] = strings.Repeat("d", 64)
	f.value.Applied["m1"] = f.ledger["m1"]
	f.extra = "auto_increment"
	f.noPrimary = true
	s.snapshotAuditorOpen = nil
	retainSnapshotResource(t, s, f)
	if fresh, err := s.migrationAdmission(context.Background(), "app1", []Migration{}, nil, false); err != nil || fresh {
		t.Fatal("no-DDL historical recovery acquired capture restrictions")
	}
	if f.metadataReads != 0 || f.writes != 0 {
		t.Fatal("ledger recovery queried capture schema or mutated DB")
	}
}
func TestMigrationSnapshotRowBudgetCheckedBeforeCustomerValues(t *testing.T) {
	for _, variant := range []string{"oversize", "too_many_rows"} {
		t.Run(variant, func(t *testing.T) {
			s, f, q := snapshotFixture(t)
			f.ledger = nil
			if variant == "oversize" {
				f.maximumRaw = (512 << 10) + 1
			} else {
				f.tableRows = snapshotMaximumRows + 1
			}
			db, _ := s.snapshotDatabase(f.value)
			defer db.Close()
			c, _ := db.Conn(context.Background())
			defer c.Close()
			meta, err := snapshotMetadataRead(context.Background(), c, f.value.Database)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.CreateTemp(t.TempDir(), "stream-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			key := bytes.Repeat([]byte{8}, 32)
			block, _ := aes.NewCipher(key)
			a, _ := cipher.NewGCM(block)
			w := snapshotStream{file: file, a: a, prefix: bytes.Repeat([]byte{9}, 8), digest: sha256.New(), binding: accessHash(q)}
			if _, _, err = captureSnapshotRows(context.Background(), c, f.value.Database, meta, &w, key); err == nil {
				t.Fatal("row budget bypassed")
			}
			for _, query := range f.events {
				if strings.Contains(query, "FROM `"+f.value.Database+"`.`records` ORDER BY") {
					t.Fatal("customer values loaded before row budget rejection")
				}
			}
			if f.writes != 0 {
				t.Fatal("bounded capture made live writes")
			}
		})
	}
}
func TestMigrationSnapshotInterruptedTransactionRetainedUnavailableLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file+directory sync requires actual Linux; no native MySQL evidence")
	}
	for _, variant := range []string{"schema_drift", "cancel_after_start"} {
		t.Run(variant, func(t *testing.T) {
			s, f, q := snapshotFixture(t)
			retainSnapshotResource(t, s, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.hook = func(query string) {
				if query == "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY" {
					if variant == "schema_drift" {
						f.createSuffix = " COMMENT='changed schema'"
					} else {
						cancel()
					}
				}
			}
			r, err := s.captureMigrationSnapshot(ctx, q, []Migration{})
			if err == nil || r.Status != "unavailable" {
				t.Fatal("interrupted snapshot accepted")
			}
			retained, err := s.readSnapshot(q)
			if err != nil || retained.Receipt.Status != "unavailable" {
				t.Fatal("unavailable capture intent not retained")
			}
			connections := f.connections
			r, err = s.captureMigrationSnapshot(context.Background(), q, []Migration{})
			if err != nil || r.Status != "unavailable" || f.connections != connections {
				t.Fatal("lost transaction recaptured or retried")
			}
			if f.writes != 0 {
				t.Fatal("interrupted snapshot changed live data")
			}
		})
	}
}
func TestMigrationSnapshotDurableCaptureAndReadbackLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual file+directory fsync ownership/durability requires Linux; no native MySQL proof claimed")
	}
	s, f, q := snapshotFixture(t)
	retainSnapshotResource(t, s, f)
	r, e := s.captureMigrationSnapshot(context.Background(), q, []Migration{})
	if e != nil || r.Status != "captured" || r.Rows != 2 || r.PublicationEligible || r.Compatibility != "not_run" {
		t.Fatalf("capture failed %v %+v", e, r)
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, []byte("private-business-canary")) || bytes.Contains(raw, []byte(f.value.Password)) {
		t.Fatal("private rows/credentials in receipt")
	}
	v, e := s.readSnapshot(q)
	if e != nil || s.verifySnapshotStream(context.Background(), v) != nil {
		t.Fatal("durable reopen failed")
	}
	connections := f.connections
	r2, e := s.captureMigrationSnapshot(context.Background(), q, []Migration{})
	if e != nil || !reflect.DeepEqual(r, r2) || f.connections != connections {
		t.Fatal("repeat recaptured a different consistent snapshot")
	}
	b, _ := os.ReadFile(filepath.Join(s.snapshotDirectory(q), "rows.enc"))
	b[len(b)-1] ^= 1
	_ = os.WriteFile(filepath.Join(s.snapshotDirectory(q), "rows.enc"), b, 0600)
	if s.verifySnapshotStream(context.Background(), v) == nil {
		t.Fatal("corrupted stream accepted")
	}
}
