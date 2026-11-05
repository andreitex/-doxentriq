package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func importFixtureMeta() snapshotMetadata {
	col := func(name, kind, full, nullable string, n int) snapshotColumn {
		return snapshotColumn{Name: name, DataType: kind, ColumnType: full, Nullable: nullable, Ordinal: n}
	}
	id := col("id", "bigint", "bigint unsigned", "NO", 1)
	amount := col("amount", "decimal", "decimal(65,30)", "NO", 2)
	payload := col("payload", "varbinary", "varbinary(64)", "YES", 3)
	optional := col("optional", "varchar", "varchar(32)", "YES", 4)
	optional.Charset = sql.NullString{String: "utf8mb4", Valid: true}
	optional.Collation = sql.NullString{String: "utf8mb4_bin", Valid: true}
	return snapshotMetadata{Tables: []snapshotTable{{Name: "records", Create: "CREATE TABLE `records` (`id` bigint unsigned, PRIMARY KEY (`id`)) ENGINE=InnoDB", Columns: []string{"id", "amount", "payload", "optional"}, Primary: []string{"id"}, Definitions: []snapshotColumn{id, amount, payload, optional}}}, Ledger: map[string]string{}}
}
func importFixtureRows() [][]any {
	return [][]any{{[]byte("1"), []byte("99999999999999999999999999999999999.123456789012345678901234567890"), []byte{0, 255, 1}, nil}, {[]byte("2"), []byte("0.000000000000000000000000000001"), []byte{}, []byte("private-canary-'\\-")}}
}
func importFixture(t *testing.T, meta snapshotMetadata, rows [][]any) (migrationImportRequest, migrationSnapshotRecord, []byte) {
	byTable := map[string][][]any{}
	for _, table := range meta.Tables {
		byTable[table.Name] = rows
	}
	return importFixtureByTable(t, meta, byTable)
}
func importFixtureByTable(t *testing.T, meta snapshotMetadata, rows map[string][][]any) (migrationImportRequest, migrationSnapshotRecord, []byte) {
	t.Helper()
	base := "release1"
	q := migrationSnapshotRequest{Version: 1, AppID: "app1", JobID: "job1", AttemptID: "attempt1", Fence: 7, BaseReleaseID: &base, BaseHash: strings.Repeat("a", 64), BaseImage: "registry/base@sha256:" + strings.Repeat("b", 64), SourceHash: strings.Repeat("c", 64), MigrationHash: migrationSetHash([]Migration{})}
	v := migrationSnapshotRecord{Receipt: emptySnapshot(q), Key: bytes.Repeat([]byte{3}, 32), NoncePrefix: bytes.Repeat([]byte{4}, 8), ResourceHash: strings.Repeat("5", 64)}
	frames := []any{map[string]any{"type": "snapshot", "requestHash": accessHash(q), "metadata": meta}}
	digest := importerDigest(v.Key, accessHash(q))
	for _, table := range meta.Tables {
		frames = append(frames, map[string]any{"type": "table", "schema": table})
		for _, row := range rows[table.Name] {
			frames = append(frames, map[string]any{"type": "row", "table": table.Name, "values": row})
			if importerDigestRow(digest, table.Name, row) != nil {
				t.Fatal("digest")
			}
		}
	}
	v.Receipt.Status = "captured"
	v.Receipt.Preservation = "captured_only"
	v.Receipt.Reason = "none"
	for _, table := range meta.Tables {
		v.Receipt.Rows += len(rows[table.Name])
	}
	v.Receipt.Tables = len(meta.Tables)
	v.Receipt.SchemaHash = accessHash(meta.Tables)
	v.Receipt.LedgerHash = accessHash(meta.Ledger)
	v.Receipt.RowDigest = hex.EncodeToString(digest.Sum(nil))
	frames = append(frames, map[string]any{"type": "complete", "rows": v.Receipt.Rows, "schemaHash": v.Receipt.SchemaHash, "ledgerHash": v.Receipt.LedgerHash})
	b := importFixtureFrames(t, v, frames)
	v.Receipt.Bytes = int64(len(b))
	v.Receipt.StreamHash = hashBytes(b)
	return migrationImportRequest{Version: 1, Snapshot: q, StreamHash: v.Receipt.StreamHash, CandidateImage: "registry/candidate@sha256:" + strings.Repeat("d", 64)}, v, b
}
func importFixtureFrames(t *testing.T, v migrationSnapshotRecord, frames []any) []byte {
	t.Helper()
	block, _ := aes.NewCipher(v.Key)
	a, _ := cipher.NewGCM(block)
	out := []byte{}
	for i, value := range frames {
		plain, e := json.Marshal(value)
		if raw, ok := value.(json.RawMessage); ok {
			plain = raw
		}
		if e != nil {
			t.Fatal(e)
		}
		nonce := append(append([]byte{}, v.NoncePrefix...), make([]byte, 4)...)
		binary.BigEndian.PutUint32(nonce[8:], uint32(i))
		sealed := a.Seal(nil, nonce, plain, []byte(v.Receipt.RequestHash+":"+strconv.Itoa(i)))
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(sealed)))
		out = append(out, header[:]...)
		out = append(out, sealed...)
	}
	return out
}

func TestMigrationImportAuthenticatedDecodeRetainsExactRawValues(t *testing.T) {
	_, v, b := importFixture(t, importFixtureMeta(), importFixtureRows())
	gotRows := [][]any{}
	got, e := decodeImportSnapshot(context.Background(), bytes.NewReader(b), v, func(_ snapshotTable, row []any) error { gotRows = append(gotRows, row); return nil })
	if e != nil || got.Rows != 2 || got.RowDigest != v.Receipt.RowDigest || !reflect.DeepEqual(gotRows, importFixtureRows()) {
		t.Fatalf("bounded raw roundtrip failed: %v", e)
	}
	public, _ := json.Marshal(v.Receipt)
	if bytes.Contains(public, []byte("private-canary")) {
		t.Fatal("private row in receipt")
	}
}

func TestMigrationImportRejectsCorruptedFrameFooterAndBindingBeforeSQL(t *testing.T) {
	q, v, b := importFixture(t, importFixtureMeta(), importFixtureRows())
	for _, name := range []string{"cipher", "truncated", "trailing", "request", "crossapp", "fence", "rowdigest", "footer"} {
		t.Run(name, func(t *testing.T) {
			qq, vv, data := q, v, append([]byte{}, b...)
			switch name {
			case "cipher":
				data[8] ^= 1
			case "truncated":
				data = data[:len(data)-4]
			case "trailing":
				data = append(data, 0)
			case "request":
				qq.StreamHash = strings.Repeat("a", 64)
			case "crossapp":
				qq.Snapshot.AppID = "foreign"
			case "fence":
				qq.Snapshot.Fence++
			case "rowdigest":
				vv.Receipt.RowDigest = strings.Repeat("1", 64)
			case "footer":
				data = importFixtureFrames(t, v, []any{map[string]any{"type": "snapshot", "requestHash": v.Receipt.RequestHash, "metadata": importFixtureMeta()}, map[string]any{"type": "complete", "rows": 2, "schemaHash": v.Receipt.SchemaHash, "ledgerHash": v.Receipt.LedgerHash}})
				vv.Receipt.Bytes = int64(len(data))
				vv.Receipt.StreamHash = hashBytes(data)
				qq.StreamHash = vv.Receipt.StreamHash
			}
			store := &importTestStore{data: data}
			db := &importTestDB{expected: vv, meta: importFixtureMeta(), request: q}
			_, e := runMigrationImport(context.Background(), qq, vv, store, db)
			if e == nil || db.creates != 0 || db.inserts != 0 || store.retains != 0 {
				t.Fatalf("invalid snapshot dispatched: %v, %+v", e, db)
			}
		})
	}
}

func TestMigrationImportStrictJSONAndDuplicatePrimaryReject(t *testing.T) {
	for _, plain := range []string{`{"type":"row","type":"row"}`, `{"type":"row","Type":"row"}`, `{"Type":"row"}`, `{}`, `{"type":"row","unknown":1}`, `{"type":"row","values":[NaN]}`} {
		var v struct {
			Type string `json:"type"`
		}
		if importerJSON([]byte(plain), &v) == nil {
			t.Fatal("alias accepted")
		}
	}
	rows := importFixtureRows()
	rows[1][0] = []byte("1")
	_, v, b := importFixture(t, importFixtureMeta(), rows)
	if _, e := decodeImportSnapshot(context.Background(), bytes.NewReader(b), v, nil); e == nil {
		t.Fatal("duplicate primary accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := decodeImportSnapshot(ctx, bytes.NewReader(b), v, nil); e == nil {
		t.Fatal("cancellation accepted")
	}
}

func TestMigrationImportAuthenticatedFrameSemanticsAndRawBudget(t *testing.T) {
	for _, kind := range []string{"nullable-PK", "raw-budget", "bad-base64", "row-shape", "footer-alias", "missing-table", "extra-table", "wrong-table"} {
		t.Run(kind, func(t *testing.T) {
			meta := importFixtureMeta()
			rows := importFixtureRows()
			_, v, _ := importFixture(t, meta, rows)
			frames := []any{map[string]any{"type": "snapshot", "requestHash": v.Receipt.RequestHash, "metadata": meta}, map[string]any{"type": "table", "schema": meta.Tables[0]}}
			var row any = map[string]any{"type": "row", "table": "records", "values": rows[0]}
			switch kind {
			case "nullable-PK":
				values := append([]any{}, rows[0]...)
				values[0] = nil
				row = map[string]any{"type": "row", "table": "records", "values": values}
			case "raw-budget":
				values := append([]any{}, rows[0]...)
				values[2] = bytes.Repeat([]byte{1}, 512<<10+1)
				row = map[string]any{"type": "row", "table": "records", "values": values}
			case "bad-base64":
				row = json.RawMessage(`{"type":"row","table":"records","values":["MQ==","MA==","AB==",null]}`)
			case "row-shape":
				row = map[string]any{"type": "row", "table": "records", "values": []any{[]byte("1")}}
			case "wrong-table":
				row = map[string]any{"type": "row", "table": "foreign", "values": rows[0]}
			}
			frames = append(frames, row, map[string]any{"type": "row", "table": "records", "values": rows[1]})
			footer := any(map[string]any{"type": "complete", "rows": 2, "schemaHash": v.Receipt.SchemaHash, "ledgerHash": v.Receipt.LedgerHash})
			if kind == "footer-alias" {
				footer = map[string]any{"Type": "complete", "rows": 2, "schemaHash": v.Receipt.SchemaHash, "ledgerHash": v.Receipt.LedgerHash}
			}
			if kind == "missing-table" {
				frames = append(frames[:1], frames[2:]...)
			}
			if kind == "extra-table" {
				frames = append(frames, map[string]any{"type": "table", "schema": meta.Tables[0]})
			}
			frames = append(frames, footer)
			b := importFixtureFrames(t, v, frames)
			v.Receipt.StreamHash = hashBytes(b)
			v.Receipt.Bytes = int64(len(b))
			if _, e := decodeImportSnapshot(context.Background(), bytes.NewReader(b), v, nil); e == nil {
				t.Fatal("authenticated but invalid stream accepted")
			}
		})
	}
}

func TestMigrationImportTypedDDLRejectsExecutableMetadata(t *testing.T) {
	meta := importFixtureMeta()
	sql, e := importerCreateTable("app_"+strings.Repeat("a", 24), meta.Tables[0])
	if e != nil || !strings.Contains(sql, "decimal(65,30)") || strings.Contains(sql, meta.Tables[0].Create) {
		t.Fatal("DDL was not derived from typed columns")
	}
	for _, name := range []string{"name", "type", "charset", "generated", "extra", "primary", "constraint", "null-default"} {
		t.Run(name, func(t *testing.T) {
			m := importFixtureMeta()
			switch name {
			case "name":
				m.Tables[0].Definitions[0].Name = "id`); DROP DATABASE live; --"
			case "type":
				m.Tables[0].Definitions[0].ColumnType = "bigint); SELECT secret"
			case "charset":
				m.Tables[0].Definitions[3].Charset.String = "utf8mb4; DROP USER x"
			case "generated":
				m.Tables[0].Definitions[0].Generation = "(select 1)"
			case "extra":
				m.Tables[0].Definitions[0].Extra = "auto_increment"
			case "primary":
				m.Tables[0].Primary = []string{"foreign"}
			case "constraint":
				m.Tables[0].Create += " CHECK (`id` > 0)"
			case "null-default":
				m.Tables[0].Definitions[0].Default.String = "hidden"
			}
			if importerTables(m) == nil {
				t.Fatal("malicious/unsupported metadata admitted")
			}
		})
	}
	m := importFixtureMeta()
	m.Tables[0].Definitions[3].Default = sqlNull("x'); DROP DATABASE live; \\foo")
	ddl, e := importerCreateTable("app_"+strings.Repeat("a", 24), m.Tables[0])
	if e != nil || !strings.Contains(ddl, "DEFAULT 'x''); DROP DATABASE live; \\foo'") {
		t.Fatal("literal default did not remain one quoted value under fixed SQL mode")
	}
}
func sqlNull(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

type importTestStore struct {
	data                        []byte
	record                      *migrationImportRecord
	retains, streams            int
	failInitial, failCompletion bool
	second                      []byte
}

func (s *importTestStore) Read(migrationImportRequest) (migrationImportRecord, error) {
	if s.record == nil {
		return migrationImportRecord{}, os.ErrNotExist
	}
	return *s.record, nil
}
func (s *importTestStore) Retain(v migrationImportRecord, initial bool) error {
	s.retains++
	if initial && s.record != nil {
		return errors.New("existing")
	}
	copy := v
	s.record = &copy
	if initial && s.failInitial || !initial && v.Receipt.Status == "imported" && s.failCompletion {
		return errors.New("sync")
	}
	return nil
}
func (s *importTestStore) Stream(migrationSnapshotRecord) (io.ReadCloser, error) {
	s.streams++
	data := s.data
	if s.streams > 1 && s.second != nil {
		data = s.second
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type importTestDB struct {
	expected                           migrationSnapshotRecord
	meta                               snapshotMetadata
	request                            migrationImportRequest
	rows                               [][]any
	creates, inserts, currents, proofs int
	failAt                             int
	driftAt                            int
	proofDrift                         bool
}

func (d *importTestDB) Prepare(_ context.Context, name string, meta snapshotMetadata) error {
	if name != importCloneDatabase(d.request) || !importerEqual(meta, d.meta) {
		return errors.New("foreign clone")
	}
	d.creates++
	return nil
}
func (d *importTestDB) Insert(_ context.Context, _ string, _ snapshotTable, row []any) error {
	d.inserts++
	if d.failAt == d.inserts {
		return errors.New("uncertain insert")
	}
	d.rows = append(d.rows, row)
	return nil
}
func (d *importTestDB) Proof(_ context.Context, _ string, v migrationSnapshotRecord, _ snapshotMetadata) (int, string, error) {
	d.proofs++
	digest := importerDigest(v.Key, v.Receipt.RequestHash)
	for _, row := range d.rows {
		_ = importerDigestRow(digest, d.meta.Tables[0].Name, row)
	}
	if d.proofDrift {
		return 0, "", snapshotUnavailable
	}
	return len(d.rows), hex.EncodeToString(digest.Sum(nil)), nil
}
func (d *importTestDB) Current(_ context.Context, v migrationSnapshotRecord, _ snapshotMetadata) error {
	d.currents++
	if !reflect.DeepEqual(v, d.expected) || d.driftAt == d.currents {
		return snapshotUnavailable
	}
	return nil
}
func (d *importTestDB) Close() error { return nil }

func TestMigrationImportOneShotAndIndependentPreservation(t *testing.T) {
	q, v, b := importFixture(t, importFixtureMeta(), importFixtureRows())
	store := &importTestStore{data: b}
	db := &importTestDB{expected: v, meta: importFixtureMeta(), request: q}
	r, e := runMigrationImport(context.Background(), q, v, store, db)
	if e != nil || r.Status != "imported" || r.PublicationEligible || r.Compatibility != "not_run" || r.WriteQuiescence != "not_run" || r.MigrationDDL != "not_run" || r.Preservation != "snapshot_import_only" || db.creates != 1 || db.inserts != 2 || store.record == nil || validateImportRecord(*store.record) != nil {
		t.Fatalf("import failed: %v %+v", e, r)
	}
	_, e = runMigrationImport(context.Background(), q, v, store, db)
	if e != nil || db.creates != 1 || db.inserts != 2 || db.proofs != 2 {
		t.Fatal("duplicate dispatched writes or omitted independent proof")
	}
	db.proofDrift = true
	_, e = runMigrationImport(context.Background(), q, v, store, db)
	if e == nil || db.creates != 1 || db.inserts != 2 {
		t.Fatal("drifted clone was accepted/reimported")
	}
}
func TestMigrationImportFailurePreservesCloneAndBlocksReplay(t *testing.T) {
	for _, name := range []string{"initial-sync", "partial-insert", "current-drift", "proof-drift", "completion-sync", "second-stream-drift"} {
		t.Run(name, func(t *testing.T) {
			q, v, b := importFixture(t, importFixtureMeta(), importFixtureRows())
			store := &importTestStore{data: b}
			db := &importTestDB{expected: v, meta: importFixtureMeta(), request: q}
			switch name {
			case "initial-sync":
				store.failInitial = true
			case "partial-insert":
				db.failAt = 2
			case "current-drift":
				db.driftAt = 3
			case "proof-drift":
				db.proofDrift = true
			case "completion-sync":
				store.failCompletion = true
			case "second-stream-drift":
				store.second = append([]byte{}, b...)
				store.second[10] ^= 1
			}
			_, e := runMigrationImport(context.Background(), q, v, store, db)
			if e == nil || store.record == nil || store.record.Receipt.Status != "pending" && store.record.Receipt.Status != "quarantined" {
				t.Fatal("uncertainty not retained")
			}
			creates, inserts := db.creates, db.inserts
			db.driftAt = 0
			db.proofDrift = false
			store.failInitial = false
			store.second = nil
			_, e = runMigrationImport(context.Background(), q, v, store, db)
			if e == nil || db.creates != creates || db.inserts != inserts {
				t.Fatal("uncertain operation replayed")
			}
			if name == "partial-insert" && len(db.rows) != 1 {
				t.Fatal("partial clone was removed")
			}
			if name == "initial-sync" && creates != 0 {
				t.Fatal("failed durability dispatched SQL")
			}
		})
	}
}

type importExecFixture struct {
	query    string
	args     []driver.NamedValue
	affected int64
}
type importExecConnector struct{ f *importExecFixture }

func (c importExecConnector) Connect(context.Context) (driver.Conn, error) {
	return &importExecConnection{c.f}, nil
}
func (importExecConnector) Driver() driver.Driver { return grantSQLDriver{} }

type importExecConnection struct{ f *importExecFixture }

func (*importExecConnection) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (*importExecConnection) Close() error                        { return nil }
func (*importExecConnection) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }
func (c *importExecConnection) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.f.query = q
	c.f.args = append([]driver.NamedValue{}, args...)
	return driver.RowsAffected(c.f.affected), nil
}
func TestMigrationImportSQLUsesOnlyBoundValuesAndRejectsNonunitInsert(t *testing.T) {
	f := &importExecFixture{affected: 1}
	db := sql.OpenDB(importExecConnector{f})
	defer db.Close()
	c, e := db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	row := importFixtureRows()[1]
	name := "app_" + strings.Repeat("a", 24)
	if importerInsert(context.Background(), c, name, importFixtureMeta().Tables[0], row) != nil || f.query != "INSERT INTO `"+name+"`.`records` (`id`,`amount`,`payload`,`optional`) VALUES (?,?,?,?)" || len(f.args) != 4 || !bytes.Equal(f.args[3].Value.([]byte), row[3].([]byte)) || strings.Contains(f.query, "private-canary") {
		t.Fatal("row bytes entered SQL text or binding changed")
	}
	f.affected = 0
	if importerInsert(context.Background(), c, name, importFixtureMeta().Tables[0], row) == nil {
		t.Fatal("zero affected insert accepted")
	}
}

func TestMigrationImportDurableExclusiveClaimLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux file/directory sync and link/mode enforcement require native Linux")
	}
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("mode")
	}
	key := filepath.Join(root, "vault")
	if os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))), 0600) != nil {
		t.Fatal("vault")
	}
	t.Setenv("BROKER_VAULT_KEY_FILE", key)
	q, v, _ := importFixture(t, importFixtureMeta(), importFixtureRows())
	s := &server{data: root}
	record := migrationImportRecord{Receipt: emptyImportReceipt(q), CloneDatabase: importCloneDatabase(q), SnapshotResourceHash: v.ResourceHash}
	if s.retainMigrationImport(record, true) != nil {
		t.Fatal("durable claim")
	}
	actual, e := s.readMigrationImport(q)
	if e != nil || !reflect.DeepEqual(actual, record) {
		t.Fatal("reopen mismatch")
	}
	if s.retainMigrationImport(record, true) == nil {
		t.Fatal("exclusive claim overwritten")
	}
	file := filepath.Join(s.importDirectory(q), "state.enc")
	link := filepath.Join(s.importDirectory(q), "linked")
	if os.Link(file, link) != nil {
		t.Fatal("hardlink")
	}
	if _, e = s.readMigrationImport(q); e == nil {
		t.Fatal("linked state accepted")
	}
	_ = os.Remove(link)
	if os.Chmod(file, 0644) != nil {
		t.Fatal("chmod")
	}
	if _, e = s.readMigrationImport(q); e == nil {
		t.Fatal("public state accepted")
	}
}

type importSQLFixture struct {
	database                                          string
	meta                                              snapshotMetadata
	rows                                              map[string][][]any
	grants                                            []string
	role, cipher, encryption                          string
	partial, existing, failMode, failRollback         bool
	creates, inserts, valuesRead, connections, closes int
	proofMaximum, proofCount                          int64
}
type importSQLConnector struct{ f *importSQLFixture }

func (c importSQLConnector) Connect(context.Context) (driver.Conn, error) {
	c.f.connections++
	return &importSQLConnection{c.f}, nil
}
func (importSQLConnector) Driver() driver.Driver { return grantSQLDriver{} }

type importSQLConnection struct{ f *importSQLFixture }

func (*importSQLConnection) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *importSQLConnection) Close() error                      { c.f.closes++; return nil }
func (*importSQLConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction only")
}
func (c *importSQLConnection) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f := c.f
	if strings.HasPrefix(q, "SET SESSION sql_mode") && f.failMode || q == "ROLLBACK" && f.failRollback {
		return nil, errors.New("fixed failure")
	}
	if strings.HasPrefix(q, "SET ") || q == "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY" || q == "ROLLBACK" {
		return driver.RowsAffected(0), nil
	}
	if q == "CREATE DATABASE `"+f.database+"` CHARACTER SET utf8mb4 ENCRYPTION='Y'" {
		if f.existing {
			return nil, errors.New("collision")
		}
		f.creates++
		f.existing = true
		return driver.RowsAffected(1), nil
	}
	for _, table := range f.meta.Tables {
		ddl, _ := importerCreateTable(f.database, table)
		if q == ddl {
			f.creates++
			return driver.RowsAffected(0), nil
		}
		cols := []string{}
		marks := []string{}
		for _, col := range table.Columns {
			cols = append(cols, "`"+col+"`")
			marks = append(marks, "?")
		}
		expected := "INSERT INTO `" + f.database + "`.`" + table.Name + "` (" + strings.Join(cols, ",") + ") VALUES (" + strings.Join(marks, ",") + ")"
		if q == expected {
			if len(args) != len(table.Columns) {
				return nil, errors.New("argument count")
			}
			row := make([]any, len(args))
			for i, arg := range args {
				if b, ok := arg.Value.([]byte); ok {
					row[i] = append([]byte{}, b...)
				} else {
					row[i] = arg.Value
				}
			}
			f.rows[table.Name] = append(f.rows[table.Name], row)
			f.inserts++
			return driver.RowsAffected(1), nil
		}
	}
	return nil, errors.New("unapproved SQL")
}
func (c *importSQLConnection) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f := c.f
	result := func(cols []string, rows ...[]driver.Value) (driver.Rows, error) {
		return &grantSQLRows{columns: cols, values: rows}, nil
	}
	switch q {
	case "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport":
		return result([]string{"partial", "roles", "secure"}, []driver.Value{f.partial, "", true})
	case "SELECT CURRENT_USER(), CURRENT_ROLE()":
		return result([]string{"user", "role"}, []driver.Value{"provisioner@%", f.role})
	case "SHOW SESSION STATUS LIKE 'Ssl_cipher'":
		return result([]string{"name", "cipher"}, []driver.Value{"Ssl_cipher", f.cipher})
	case "SELECT @@SESSION.autocommit":
		return result([]string{"autocommit"}, []driver.Value{true})
	case "SHOW GRANTS":
		rows := [][]driver.Value{}
		for _, g := range f.grants {
			rows = append(rows, []driver.Value{g})
		}
		return result([]string{"grant"}, rows...)
	}
	if strings.Contains(q, "INFORMATION_SCHEMA.") && len(args) > 0 && args[0].Value != f.database {
		return nil, errors.New("foreign database")
	}
	if strings.HasPrefix(q, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA") {
		n := int64(0)
		if f.existing {
			n = 1
		}
		return result([]string{"count"}, []driver.Value{n})
	}
	if strings.HasPrefix(q, "SELECT DEFAULT_ENCRYPTION FROM") {
		return result([]string{"encryption"}, []driver.Value{f.encryption})
	}
	if strings.HasPrefix(q, "SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION") {
		return result([]string{"name", "encryption"}, []driver.Value{f.database, f.encryption})
	}
	if strings.Contains(q, "INFORMATION_SCHEMA.TABLES") {
		rows := [][]driver.Value{}
		for _, t := range f.meta.Tables {
			rows = append(rows, []driver.Value{t.Name, "InnoDB", "BASE TABLE"})
		}
		return result([]string{"name", "engine", "type"}, rows...)
	}
	for _, t := range f.meta.Tables {
		if q == "SHOW CREATE TABLE `"+f.database+"`.`"+t.Name+"`" {
			return result([]string{"name", "create"}, []driver.Value{t.Name, t.Create})
		}
		if len(args) == 2 && args[1].Value == t.Name && strings.Contains(q, "INFORMATION_SCHEMA.COLUMNS") {
			rows := [][]driver.Value{}
			for _, col := range t.Definitions {
				nullable := func(s sql.NullString) driver.Value {
					if s.Valid {
						return s.String
					}
					return nil
				}
				rows = append(rows, []driver.Value{col.Name, col.DataType, col.ColumnType, col.Nullable, nullable(col.Default), nullable(col.Charset), nullable(col.Collation), col.Extra, col.Generation, int64(col.Ordinal)})
			}
			return result([]string{"name", "type", "fulltype", "nullable", "default", "charset", "collation", "extra", "generation", "ordinal"}, rows...)
		}
		if len(args) == 2 && args[1].Value == t.Name && strings.Contains(q, "INFORMATION_SCHEMA.STATISTICS") {
			rows := [][]driver.Value{}
			for i, col := range t.Primary {
				rows = append(rows, []driver.Value{col, int64(i + 1), nil})
			}
			return result([]string{"col", "seq", "part"}, rows...)
		}
		if strings.HasPrefix(q, "SELECT COALESCE(MAX(") && strings.HasSuffix(q, " FROM `"+f.database+"`.`"+t.Name+"`") {
			maximum, count := int64(0), int64(len(f.rows[t.Name]))
			for _, row := range f.rows[t.Name] {
				size := 0
				for _, value := range row {
					if b, ok := value.([]byte); ok {
						size += len(b)
					}
				}
				if int64(size) > maximum {
					maximum = int64(size)
				}
			}
			if f.proofMaximum != 0 {
				maximum = f.proofMaximum
			}
			if f.proofCount != 0 {
				count = f.proofCount
			}
			return result([]string{"maximum", "count"}, []driver.Value{maximum, count})
		}
		if strings.HasPrefix(q, "SELECT ") && strings.HasSuffix(q, " FROM `"+f.database+"`.`"+t.Name+"` ORDER BY `"+t.Primary[0]+"`") {
			f.valuesRead++
			rows := [][]driver.Value{}
			for _, row := range f.rows[t.Name] {
				values := make([]driver.Value, len(row))
				for i, v := range row {
					values[i] = v
				}
				rows = append(rows, values)
			}
			return result(t.Columns, rows...)
		}
	}
	if q == "SELECT id, checksum FROM `"+f.database+"`.`_autosoft_migrations` ORDER BY id" {
		rows := [][]driver.Value{}
		for _, row := range f.rows["_autosoft_migrations"] {
			rows = append(rows, []driver.Value{row[0], row[1]})
		}
		return result([]string{"id", "checksum"}, rows...)
	}
	return nil, errors.New("unapproved query")
}
func newImportSQLFixture(t *testing.T) (*sqlMigrationImport, *importSQLFixture) {
	t.Helper()
	t.Setenv("MYSQL_USER", "provisioner")
	f := &importSQLFixture{database: "app_" + strings.Repeat("a", 24), meta: importFixtureMeta(), rows: map[string][][]any{}, role: "NONE", cipher: "TLS_AES_256_GCM_SHA384", encryption: "Y", grants: []string{"GRANT CREATE USER ON *.* TO 'provisioner'@'%'", "GRANT CREATE, ALTER, INDEX, SELECT, INSERT, UPDATE, DELETE, REFERENCES ON `app\\_%`.* TO 'provisioner'@'%' WITH GRANT OPTION"}}
	s := &server{snapshotAdminOpen: func() (*sql.DB, error) { return sql.OpenDB(importSQLConnector{f}), nil }}
	p := &sqlMigrationImport{s: s, clone: f.database}
	t.Cleanup(func() { _ = p.Close() })
	return p, f
}
func TestMigrationImportRejectedSessionIsNeverCached(t *testing.T) {
	for _, kind := range []string{"roles", "TLS", "flags", "mode"} {
		t.Run(kind, func(t *testing.T) {
			p, f := newImportSQLFixture(t)
			switch kind {
			case "roles":
				f.role = "foreign"
			case "TLS":
				f.cipher = ""
			case "flags":
				f.partial = true
			case "mode":
				f.failMode = true
			}
			for i := 0; i < 2; i++ {
				if p.connection(context.Background()) == nil || p.c != nil || p.db != nil {
					t.Fatal("rejected connection was cached")
				}
			}
			if f.connections != 2 || f.closes != 2 || f.creates != 0 || f.inserts != 0 {
				t.Fatal("session leak or SQL dispatch")
			}
		})
	}
}
func TestMigrationImportAdminConfigurationUsesRawVerifiedTLS(t *testing.T) {
	t.Setenv("MYSQL_HOST", "mysql")
	t.Setenv("MYSQL_PORT", "3306")
	cfg := importerAdminConfig("provisioner", "synthetic-only")
	if cfg.ParseTime || cfg.MultiStatements || cfg.InterpolateParams || cfg.Net != "tcp" || cfg.Addr != "mysql:3306" || cfg.TLSConfig != "autosoft-verified" || cfg.DBName != "" || cfg.User != "provisioner" || cfg.Timeout.Seconds() != 15 || cfg.ReadTimeout.Seconds() != 30 || cfg.WriteTimeout.Seconds() != 30 {
		t.Fatal("clone raw/TLS/statement bounds changed")
	}
}
func TestMigrationImportActualSQLReadbackDetectsOldColumnLedgerAndRowDrift(t *testing.T) {
	p, f := newImportSQLFixture(t)
	_, v, _ := importFixture(t, f.meta, importFixtureRows())
	if p.Prepare(context.Background(), f.database, f.meta) != nil {
		t.Fatal("typed prepare")
	}
	for _, row := range importFixtureRows() {
		if p.Insert(context.Background(), f.database, f.meta.Tables[0], row) != nil {
			t.Fatal("parameter import")
		}
	}
	rows, digest, e := p.Proof(context.Background(), f.database, v, f.meta)
	if e != nil || rows != v.Receipt.Rows || digest != v.Receipt.RowDigest {
		t.Fatalf("independent SQL proof failed: %v", e)
	}
	old := f.meta.Tables[0].Definitions[1].ColumnType
	f.meta.Tables[0].Definitions[1].ColumnType = "decimal(64,30)"
	if _, _, e = p.Proof(context.Background(), f.database, v, importFixtureMeta()); e == nil {
		t.Fatal("old column drift accepted")
	}
	f.meta.Tables[0].Definitions[1].ColumnType = old
	f.rows["records"][0][2] = []byte{0, 254, 1}
	_, digest, e = p.Proof(context.Background(), f.database, v, f.meta)
	if e != nil || digest == v.Receipt.RowDigest {
		t.Fatal("raw byte drift not detected")
	}
	f.encryption = "N"
	if _, _, e = p.Proof(context.Background(), f.database, v, f.meta); e == nil {
		t.Fatal("unencrypted clone accepted")
	}
}
func TestMigrationImportActualNonemptyLedgerIsIndependentlyReadBack(t *testing.T) {
	p, f := newImportSQLFixture(t)
	id := snapshotColumn{Name: "id", DataType: "varchar", ColumnType: "varchar(80)", Nullable: "NO", Ordinal: 1, Charset: sqlNull("utf8mb4"), Collation: sqlNull("utf8mb4_bin")}
	sum := snapshotColumn{Name: "checksum", DataType: "char", ColumnType: "char(64)", Nullable: "NO", Ordinal: 2, Charset: sqlNull("utf8mb4"), Collation: sqlNull("utf8mb4_bin")}
	ledgerTable := snapshotTable{Name: "_autosoft_migrations", Create: "CREATE TABLE `_autosoft_migrations` (PRIMARY KEY (`id`)) ENGINE=InnoDB", Columns: []string{"id", "checksum"}, Primary: []string{"id"}, Definitions: []snapshotColumn{id, sum}}
	f.meta.Tables = append([]snapshotTable{ledgerTable}, f.meta.Tables...)
	f.meta.Ledger = map[string]string{"m1": strings.Repeat("e", 64)}
	data := map[string][][]any{"_autosoft_migrations": {{[]byte("m1"), []byte(strings.Repeat("e", 64))}}, "records": importFixtureRows()}
	_, v, b := importFixtureByTable(t, f.meta, data)
	if _, e := decodeImportSnapshot(context.Background(), bytes.NewReader(b), v, nil); e != nil {
		t.Fatal("nonempty authenticated ledger")
	}
	if p.Prepare(context.Background(), f.database, f.meta) != nil {
		t.Fatal("ledger clone prepare")
	}
	for _, table := range f.meta.Tables {
		for _, row := range data[table.Name] {
			if p.Insert(context.Background(), f.database, table, row) != nil {
				t.Fatal("ledger parameter import")
			}
		}
	}
	n, digest, e := p.Proof(context.Background(), f.database, v, f.meta)
	if e != nil || n != 3 || digest != v.Receipt.RowDigest {
		t.Fatalf("ledger readback: %v", e)
	}
	f.rows["_autosoft_migrations"][0][1] = []byte(strings.Repeat("f", 64))
	if _, _, e = p.Proof(context.Background(), f.database, v, f.meta); e == nil {
		t.Fatal("changed actual ledger accepted")
	}
	meta := f.meta
	meta.Ledger = map[string]string{"m1": strings.Repeat("f", 64)}
	_, changed, changedBytes := importFixtureByTable(t, meta, data)
	if _, e := decodeImportSnapshot(context.Background(), bytes.NewReader(changedBytes), changed, nil); e == nil {
		t.Fatal("ledger header/rows mismatch accepted")
	}
}
func TestMigrationImportSQLRefusesExistingAndForeignPrivilegeTargets(t *testing.T) {
	for _, kind := range []string{"existing", "global", "foreign", "missing", "role"} {
		t.Run(kind, func(t *testing.T) {
			p, f := newImportSQLFixture(t)
			switch kind {
			case "existing":
				f.existing = true
			case "global":
				f.grants = []string{"GRANT ALL PRIVILEGES ON *.* TO 'provisioner'@'%'"}
			case "foreign":
				f.grants = []string{"GRANT CREATE, SELECT, INSERT ON `other`.* TO 'provisioner'@'%'"}
			case "missing":
				f.grants = []string{"GRANT CREATE USER ON *.* TO 'provisioner'@'%'"}
			case "role":
				f.role = "some_role"
			}
			if p.Prepare(context.Background(), f.database, f.meta) == nil || f.creates != 0 || f.inserts != 0 {
				t.Fatal("unsafe preparation modified a database")
			}
		})
	}
}
func TestMigrationImportSQLBackendNeverTargetsAnUnownedSchema(t *testing.T) {
	p, f := newImportSQLFixture(t)
	foreign := "app_" + strings.Repeat("b", 24)
	_, v, _ := importFixture(t, f.meta, importFixtureRows())
	if p.Prepare(context.Background(), foreign, f.meta) == nil || p.Insert(context.Background(), f.database, f.meta.Tables[0], importFixtureRows()[0]) == nil || f.connections != 0 || f.creates != 0 || f.inserts != 0 {
		t.Fatal("unowned target reached SQL")
	}
	if p.Prepare(context.Background(), f.database, f.meta) != nil {
		t.Fatal("owned prepare")
	}
	inserts := f.inserts
	valuesRead := f.valuesRead
	if p.Insert(context.Background(), foreign, f.meta.Tables[0], importFixtureRows()[0]) == nil || p.Prepare(context.Background(), f.database, f.meta) == nil || f.inserts != inserts {
		t.Fatal("foreign/repeated mutation permitted")
	}
	if _, _, e := p.Proof(context.Background(), foreign, v, f.meta); e == nil || f.valuesRead != valuesRead {
		t.Fatal("foreign proof queried rows")
	}
}
func TestMigrationImportSQLBoundsAndRollbackUncertainty(t *testing.T) {
	for _, kind := range []string{"row-budget", "count-budget", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			p, f := newImportSQLFixture(t)
			_, v, _ := importFixture(t, f.meta, importFixtureRows())
			f.rows["records"] = importFixtureRows()
			f.existing = true
			switch kind {
			case "row-budget":
				f.proofMaximum = 512<<10 + 1
			case "count-budget":
				f.proofCount = snapshotMaximumRows + 1
			case "rollback":
				f.failRollback = true
			}
			if _, _, e := p.Proof(context.Background(), f.database, v, f.meta); e == nil {
				t.Fatal("unsafe proof accepted")
			}
			if kind != "rollback" && f.valuesRead != 0 {
				t.Fatal("budget checked after row values")
			}
			if f.creates != 0 || f.inserts != 0 {
				t.Fatal("readback wrote data")
			}
		})
	}
}
func TestMigrationImportConstructorPinsProtectedVerificationBeforeSQL(t *testing.T) {
	for _, kind := range []string{"candidate", "app", "source", "migration", "base", "fence"} {
		t.Run(kind, func(t *testing.T) {
			s, sqlFixture, snapshot := snapshotFixture(t)
			base := "base1"
			snapshot.BaseReleaseID = &base
			snapshot.BaseHash = strings.Repeat("a", 64)
			snapshot.BaseImage = "registry/base@sha256:" + strings.Repeat("b", 64)
			if e := atomicJSON(filepath.Join(s.data, "active", snapshot.AppID+".json"), activeDeployment{ReleaseID: base, Hash: snapshot.BaseHash, Image: snapshot.BaseImage}); e != nil {
				t.Fatal(e)
			}
			q := migrationImportRequest{Version: 1, Snapshot: snapshot, StreamHash: strings.Repeat("c", 64), CandidateImage: "registry/candidate@sha256:" + strings.Repeat("d", 64)}
			receipt := emptySnapshot(snapshot)
			verification := Verification{AppID: snapshot.AppID, AttemptID: snapshot.AttemptID, SourceHash: snapshot.SourceHash, Images: []string{q.CandidateImage}, Migrations: []Migration{}, MigrationSnapshot: &receipt}
			switch kind {
			case "candidate":
				verification.Images[0] = "registry/foreign@sha256:" + strings.Repeat("e", 64)
			case "app":
				verification.AppID = "foreign"
			case "source":
				verification.SourceHash = strings.Repeat("e", 64)
			case "migration":
				verification.Migrations = []Migration{{ID: "new", Checksum: strings.Repeat("e", 64)}}
			case "base":
				verification.MigrationSnapshot.Binding.BaseHash = strings.Repeat("e", 64)
			case "fence":
				q.Snapshot.Fence++
			}
			if e := atomicJSON(filepath.Join(s.data, "receipts", snapshot.AttemptID+".json"), verification); e != nil {
				t.Fatal(e)
			}
			if _, e := s.importMigrationSnapshot(context.Background(), q); e == nil || sqlFixture.connections != 0 || sqlFixture.writes != 0 {
				t.Fatal("foreign source/base/candidate admitted SQL")
			}
		})
	}
}
func TestMigrationImportConstructorBusyOrCancelledNeverDispatches(t *testing.T) {
	s, f, snapshot := snapshotFixture(t)
	base := "base1"
	snapshot.BaseReleaseID = &base
	snapshot.BaseHash = strings.Repeat("a", 64)
	snapshot.BaseImage = "registry/base@sha256:" + strings.Repeat("b", 64)
	q := migrationImportRequest{Version: 1, Snapshot: snapshot, StreamHash: strings.Repeat("c", 64), CandidateImage: "registry/candidate@sha256:" + strings.Repeat("d", 64)}
	unlock := s.lock("app-" + snapshot.AppID)
	if _, e := s.importMigrationSnapshot(context.Background(), q); e == nil {
		t.Fatal("busy app lock admitted import")
	}
	unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.importMigrationSnapshot(ctx, q); e == nil {
		t.Fatal("cancelled request admitted import")
	}
	if f.connections != 0 || f.writes != 0 {
		t.Fatal("busy/cancelled entry made SQL calls")
	}
}

func TestMigrationImportCurrentProofChecksActualProtectedFenceResourceAndMetadata(t *testing.T) {
	for _, kind := range []string{"valid", "fence", "resource", "schema", "ledger", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, f, q := snapshotFixture(t)
			base := "base1"
			q.BaseReleaseID = &base
			q.BaseHash = strings.Repeat("a", 64)
			q.BaseImage = "registry/base@sha256:" + strings.Repeat("b", 64)
			if e := atomicJSON(filepath.Join(s.data, "active", q.AppID+".json"), activeDeployment{ReleaseID: base, Hash: q.BaseHash, Image: q.BaseImage}); e != nil {
				t.Fatal(e)
			}
			retainSnapshotResource(t, s, f)
			resource, e := snapshotFile(s, filepath.Join(s.data, "resources", q.AppID+".enc"), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			db, e := s.snapshotDatabase(f.value)
			if e != nil {
				t.Fatal(e)
			}
			c, e := db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			meta, e := snapshotMetadataRead(context.Background(), c, f.value.Database)
			_ = c.Close()
			_ = db.Close()
			if e != nil {
				t.Fatal(e)
			}
			v := migrationSnapshotRecord{Receipt: emptySnapshot(q), ResourceHash: hashBytes(resource)}
			ctx := context.Background()
			switch kind {
			case "fence":
				if s.acceptFence(q.AppID, "other-job", "other-attempt", q.Fence+1) != nil {
					t.Fatal("advance fence")
				}
			case "resource":
				f.value.Schema++
				retainSnapshotResource(t, s, f)
			case "schema":
				f.createSuffix = " COMMENT='changed'"
			case "ledger":
				f.ledger["m1"] = strings.Repeat("e", 64)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			p := &sqlMigrationImport{s: s}
			e = p.Current(ctx, v, meta)
			if kind == "valid" && e != nil || kind != "valid" && e == nil || f.writes != 0 {
				t.Fatalf("current protected proof %s: %v", kind, e)
			}
		})
	}
}
