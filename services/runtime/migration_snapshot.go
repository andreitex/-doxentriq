package main

// Capture is deliberately not a migration compatibility certificate. The rows
// stay encrypted in broker storage and are never mounted into a preview.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const snapshotMaximumBytes = 256 << 20
const snapshotMaximumRows = 100000

var snapshotSQLName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
var snapshotUnavailable = errors.New("Protected migration snapshot is unavailable; no record-preservation or release-compatibility proof was established")

type migrationSnapshotRequest struct {
	Version       int     `json:"schemaVersion"`
	AppID         string  `json:"appId"`
	JobID         string  `json:"jobId"`
	AttemptID     string  `json:"attemptId"`
	Fence         uint64  `json:"fence"`
	BaseReleaseID *string `json:"baseReleaseId"`
	BaseHash      string  `json:"baseArtifactHash"`
	BaseImage     string  `json:"baseImage"`
	SourceHash    string  `json:"sourceHash"`
	MigrationHash string  `json:"migrationSetHash"`
}
type migrationSnapshotReceipt struct {
	Version             int                      `json:"schemaVersion"`
	Binding             migrationSnapshotRequest `json:"binding"`
	RequestHash         string                   `json:"requestHash"`
	Status              string                   `json:"status"`
	CheckedAt           string                   `json:"checkedAt"`
	SchemaEpoch         int                      `json:"schemaEpoch"`
	SchemaHash          string                   `json:"schemaFingerprintHash"`
	LedgerHash          string                   `json:"migrationLedgerHash"`
	StreamHash          string                   `json:"streamHash"`
	RowDigest           string                   `json:"rowDigest"`
	Tables              int                      `json:"tableCount"`
	Rows                int                      `json:"rowCount"`
	Bytes               int64                    `json:"byteCount"`
	Unapplied           []string                 `json:"unappliedMigrationIds"`
	Preservation        string                   `json:"dataPreservation"`
	Compatibility       string                   `json:"previousReleaseCompatibility"`
	PublicationEligible bool                     `json:"publicationEligible"`
	Reason              string                   `json:"reason"`
}
type migrationSnapshotRecord struct {
	Receipt      migrationSnapshotReceipt `json:"receipt"`
	Key          []byte                   `json:"key"`
	NoncePrefix  []byte                   `json:"noncePrefix"`
	ResourceHash string                   `json:"resourceHash"`
}
type snapshotTable struct {
	Name        string
	Create      string
	Columns     []string
	Primary     []string
	Definitions []snapshotColumn
}
type snapshotColumn struct {
	Name, DataType, ColumnType, Nullable, Extra, Generation string
	Default, Charset, Collation                             sql.NullString
	Ordinal                                                 int
}

var snapshotRawTypes = map[string]bool{"tinyint": true, "smallint": true, "mediumint": true, "int": true, "bigint": true, "decimal": true, "bit": true, "binary": true, "varbinary": true, "tinyblob": true, "blob": true, "mediumblob": true, "longblob": true, "char": true, "varchar": true, "tinytext": true, "text": true, "mediumtext": true, "longtext": true, "date": true, "datetime": true, "timestamp": true, "time": true, "year": true, "json": true}

type snapshotMetadata struct {
	Tables []snapshotTable
	Ledger map[string]string
}

func migrationSetHash(migrations []Migration) string {
	values := []map[string]string{}
	for _, m := range migrations {
		values = append(values, map[string]string{"id": m.ID, "checksum": m.Checksum})
	}
	return accessHash(values)
}
func validateSnapshotRequest(q migrationSnapshotRequest) error {
	if q.Version != 1 || !identity.MatchString(q.AppID) || !identity.MatchString(q.JobID) || !identity.MatchString(q.AttemptID) || q.Fence == 0 || q.Fence > 9007199254740991 || !accessHex.MatchString(q.SourceHash) || !accessHex.MatchString(q.MigrationHash) {
		return snapshotUnavailable
	}
	if q.BaseReleaseID == nil {
		if q.BaseHash != "" || q.BaseImage != "" {
			return snapshotUnavailable
		}
	} else if !identity.MatchString(*q.BaseReleaseID) || !accessHex.MatchString(q.BaseHash) || !digestImage.MatchString(q.BaseImage) {
		return snapshotUnavailable
	}
	return nil
}
func emptySnapshot(q migrationSnapshotRequest) migrationSnapshotReceipt {
	zero := strings.Repeat("0", 64)
	return migrationSnapshotReceipt{Version: 1, Binding: q, RequestHash: accessHash(q), Status: "pending", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), SchemaEpoch: 1, SchemaHash: zero, LedgerHash: zero, StreamHash: zero, RowDigest: zero, Unapplied: []string{}, Preservation: "not_captured", Compatibility: "not_run", Reason: "snapshot_unavailable"}
}
func (s *server) snapshotDirectory(q migrationSnapshotRequest) string {
	return filepath.Join(s.data, "migration-snapshots", q.AppID, q.AttemptID)
}

func snapshotFile(s *server, path string, maximum int64) ([]byte, error) {
	if withdrawalAncestors(s.data, filepath.Dir(path), false) != nil {
		return nil, snapshotUnavailable
	}
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !snapshotOrdinary(info, maximum) {
		return nil, snapshotUnavailable
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, snapshotUnavailable
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, snapshotUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(b)) > maximum {
		return nil, snapshotUnavailable
	}
	return b, nil
}
func snapshotOrdinary(info os.FileInfo, maximum int64) bool {
	if !info.Mode().IsRegular() || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		return false
	}
	sys := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if sys.IsValid() && sys.Kind() == reflect.Struct {
		n := sys.FieldByName("Nlink")
		if n.IsValid() {
			return n.Uint() == 1
		}
	}
	return runtime.GOOS == "windows"
}
func (s *server) readSnapshot(q migrationSnapshotRequest) (migrationSnapshotRecord, error) {
	var v migrationSnapshotRecord
	file := filepath.Join(s.snapshotDirectory(q), "state.enc")
	sealed, e := snapshotFile(s, file, 1<<20)
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
	plain, e := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], []byte("state.enc"))
	if e != nil {
		return v, snapshotUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil || decoder.Decode(new(any)) != io.EOF || !reflect.DeepEqual(v.Receipt.Binding, q) || v.Receipt.RequestHash != accessHash(q) || validateSnapshotReceipt(v.Receipt) != nil {
		return v, snapshotUnavailable
	}
	if len(v.Key) != 32 || len(v.NoncePrefix) != 8 {
		return v, snapshotUnavailable
	}
	return v, nil
}

// A completed receipt remains unavailable if its protected ciphertext is lost,
// linked, truncated, changed or lacks the authenticated final frame.
func (s *server) verifySnapshotStream(ctx context.Context, v migrationSnapshotRecord) error {
	if v.Receipt.Status != "captured" {
		return nil
	}
	file := filepath.Join(s.snapshotDirectory(v.Receipt.Binding), "rows.enc")
	if withdrawalAncestors(s.data, filepath.Dir(file), false) != nil {
		return snapshotUnavailable
	}
	info, e := os.Lstat(file)
	if e != nil || !snapshotOrdinary(info, snapshotMaximumBytes) || info.Size() != v.Receipt.Bytes {
		return snapshotUnavailable
	}
	f, e := os.Open(file)
	if e != nil {
		return snapshotUnavailable
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return snapshotUnavailable
	}
	block, e := aes.NewCipher(v.Key)
	if e != nil {
		return snapshotUnavailable
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return snapshotUnavailable
	}
	h := sha256.New()
	reader := io.TeeReader(f, h)
	seq := uint32(0)
	complete := false
	for {
		if ctx.Err() != nil {
			return snapshotUnavailable
		}
		var header [4]byte
		_, e = io.ReadFull(reader, header[:])
		if e == io.EOF {
			break
		}
		if e != nil || complete {
			return snapshotUnavailable
		}
		length := binary.BigEndian.Uint32(header[:])
		if length < 16 || length > (1<<20)+16 || seq == ^uint32(0) {
			return snapshotUnavailable
		}
		sealed := make([]byte, length)
		if _, e = io.ReadFull(reader, sealed); e != nil {
			return snapshotUnavailable
		}
		nonce := append(append([]byte{}, v.NoncePrefix...), make([]byte, 4)...)
		binary.BigEndian.PutUint32(nonce[8:], seq)
		plain, e := a.Open(nil, nonce, sealed, []byte(fmt.Sprintf("%s:%d", v.Receipt.RequestHash, seq)))
		if e != nil {
			return snapshotUnavailable
		}
		var frame struct {
			Type       string `json:"type"`
			Rows       int    `json:"rows"`
			SchemaHash string `json:"schemaHash"`
			LedgerHash string `json:"ledgerHash"`
		}
		if json.Unmarshal(plain, &frame) != nil || seq == 0 && frame.Type != "snapshot" {
			return snapshotUnavailable
		}
		if frame.Type == "complete" {
			if frame.Rows != v.Receipt.Rows || frame.SchemaHash != v.Receipt.SchemaHash || frame.LedgerHash != v.Receipt.LedgerHash {
				return snapshotUnavailable
			}
			complete = true
		}
		seq++
	}
	if !complete || hex.EncodeToString(h.Sum(nil)) != v.Receipt.StreamHash {
		return snapshotUnavailable
	}
	return nil
}
func validateSnapshotReceipt(v migrationSnapshotReceipt) error {
	if validateSnapshotRequest(v.Binding) != nil || v.Version != 1 || v.RequestHash != accessHash(v.Binding) || v.PublicationEligible || v.SchemaEpoch < 1 || uint64(v.SchemaEpoch) > 9007199254740991 || v.Rows < 0 || v.Rows > snapshotMaximumRows || v.Tables < 0 || v.Tables > 64 || v.Bytes < 0 || v.Bytes > snapshotMaximumBytes || v.Unapplied == nil || len(v.Unapplied) > 1000 {
		return snapshotUnavailable
	}
	if _, e := time.Parse(time.RFC3339Nano, v.CheckedAt); e != nil {
		return snapshotUnavailable
	}
	for _, h := range []string{v.SchemaHash, v.LedgerHash, v.StreamHash, v.RowDigest} {
		if !accessHex.MatchString(h) {
			return snapshotUnavailable
		}
	}
	seen := map[string]bool{}
	for _, id := range v.Unapplied {
		if !identity.MatchString(id) || seen[id] {
			return snapshotUnavailable
		}
		seen[id] = true
	}
	switch v.Status {
	case "captured":
		reason := "none"
		if len(v.Unapplied) > 0 {
			reason = "migration_contract_required"
		}
		if v.Preservation != "captured_only" || v.Compatibility != "not_run" || v.Bytes == 0 || v.Reason != reason {
			return snapshotUnavailable
		}
		for _, h := range []string{v.SchemaHash, v.LedgerHash, v.StreamHash, v.RowDigest} {
			if h == strings.Repeat("0", 64) {
				return snapshotUnavailable
			}
		}
	case "no_previous_release":
		if v.Binding.BaseReleaseID != nil || v.SchemaEpoch != 1 || v.Preservation != "no_previous_release" || v.Compatibility != "no_previous_release" || v.Tables != 0 || v.Rows != 0 || v.Bytes != 0 || len(v.Unapplied) != 0 || v.Reason != "none" {
			return snapshotUnavailable
		}
	case "pending", "unavailable":
		if v.Preservation != "not_captured" || v.Compatibility != "not_run" || v.Tables != 0 || v.Rows != 0 || v.Bytes != 0 || v.Reason != "snapshot_unavailable" {
			return snapshotUnavailable
		}
	default:
		return snapshotUnavailable
	}
	if v.Status != "captured" {
		if len(v.Unapplied) != 0 {
			return snapshotUnavailable
		}
		for _, h := range []string{v.SchemaHash, v.LedgerHash, v.StreamHash, v.RowDigest} {
			if h != strings.Repeat("0", 64) {
				return snapshotUnavailable
			}
		}
	}
	return nil
}

// File + every newly-created directory are synchronized before capture and
// again before accepting completion. A visible but unsynchronized file is not
// authority. Linux is required for this durability contract.
func (s *server) retainSnapshot(v migrationSnapshotRecord) error {
	if runtime.GOOS != "linux" || validateSnapshotReceipt(v.Receipt) != nil {
		return snapshotUnavailable
	}
	dir := s.snapshotDirectory(v.Receipt.Binding)
	if withdrawalAncestors(s.data, dir, true) != nil {
		return snapshotUnavailable
	}
	file := filepath.Join(dir, "state.enc")
	if info, e := os.Lstat(file); e == nil && !withdrawalOrdinary(info) || e != nil && !os.IsNotExist(e) {
		return snapshotUnavailable
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
	sealed := a.Seal(nonce, nonce, plain, []byte("state.enc"))
	f, e := os.CreateTemp(dir, ".snapshot-")
	if e != nil {
		return snapshotUnavailable
	}
	name := f.Name()
	defer os.Remove(name)
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
	if e != nil || os.Rename(name, file) != nil {
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
	actual, e := s.readSnapshot(v.Receipt.Binding)
	if e != nil || !reflect.DeepEqual(actual, v) {
		return snapshotUnavailable
	}
	return nil
}

func (s *server) snapshotContext(q migrationSnapshotRequest) error {
	if validateSnapshotRequest(q) != nil {
		return snapshotUnavailable
	}
	b, e := snapshotFile(s, filepath.Join(s.data, "fences", q.AppID+".json"), 65536)
	var fence workerFence
	if e != nil || json.Unmarshal(b, &fence) != nil || fence != (workerFence{q.AppID, q.JobID, q.AttemptID, q.Fence}) {
		return snapshotUnavailable
	}
	b, e = snapshotFile(s, filepath.Join(s.data, "active", q.AppID+".json"), 1<<20)
	if os.IsNotExist(e) {
		if q.BaseReleaseID != nil {
			return snapshotUnavailable
		}
	} else {
		var current activeDeployment
		if e != nil || json.Unmarshal(b, &current) != nil || q.BaseReleaseID == nil || current.ReleaseID != *q.BaseReleaseID || current.Hash != q.BaseHash || current.Image != q.BaseImage {
			return snapshotUnavailable
		}
	}
	source := filepath.Join(s.data, "sources", q.AttemptID)
	h, e := sourceDigest(source)
	if e != nil || h != q.SourceHash {
		return snapshotUnavailable
	}
	m, e := readMigrations(source)
	if e != nil || migrationSetHash(m) != q.MigrationHash {
		return snapshotUnavailable
	}
	return nil
}

func (s *server) snapshotAccount(appID string) (resources, bool, error) {
	var v resources
	file := filepath.Join(s.data, "resources", appID+".enc")
	sealed, e := snapshotFile(s, file, 1<<20)
	if os.IsNotExist(e) {
		return v, false, nil
	}
	if e != nil || decryptSnapshotResource(sealed, filepath.Base(file), &v) != nil || v.AppID != appID || applicationSQLNames(appID, v.Database, v.User) != nil || !applicationSQLPassword.MatchString(v.Password) || v.MySQLGrantVersion != 1 || !v.MySQLGrantVerified || v.Schema < 1 {
		return v, false, snapshotUnavailable
	}
	return v, true, nil
}
func decryptSnapshotResource(sealed []byte, name string, value *resources) error {
	key, e := vaultKey()
	if e != nil {
		return snapshotUnavailable
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return snapshotUnavailable
	}
	a, e := cipher.NewGCM(block)
	if e != nil || len(sealed) < a.NonceSize() {
		return snapshotUnavailable
	}
	plain, e := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], []byte(name))
	if e != nil || json.Unmarshal(plain, value) != nil {
		return snapshotUnavailable
	}
	return nil
}
func (s *server) snapshotAdmin() (*sql.DB, error) {
	if s.snapshotAdminOpen != nil {
		return s.snapshotAdminOpen()
	}
	return mysqlConnection()
}
func (s *server) snapshotDatabase(v resources) (*sql.DB, error) {
	if s.snapshotOpen != nil {
		return s.snapshotOpen(v)
	}
	// Register the existing verified TLS configuration without retaining a second
	// connection; snapshot values use RawBytes, not driver's time conversions.
	registered, e := mysqlConnectionAs(v.User, v.Password)
	if e != nil {
		return nil, e
	}
	_ = registered.Close()
	cfg := mysql.NewConfig()
	cfg.User = v.User
	cfg.Passwd = v.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(env("MYSQL_HOST", "mysql"), env("MYSQL_PORT", "3306"))
	cfg.DBName = v.Database
	cfg.TLSConfig = "autosoft-verified"
	cfg.Timeout = 15 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.ParseTime = false
	cfg.MultiStatements = false
	return sql.Open("mysql", cfg.FormatDSN())
}
func (s *server) absentApplicationDatabase(ctx context.Context, appID string) error {
	d := sha256.Sum256([]byte(appID))
	name := "app_" + hex.EncodeToString(d[:])[:24]
	db, e := s.snapshotAdmin()
	if e != nil {
		return snapshotUnavailable
	}
	defer db.Close()
	// SCHEMATA hides databases without a visible privilege. A filtered zero is
	// not evidence of genesis: prove the configured provisioner's own TLS,
	// role-free identity and SELECT coverage of this exact namespace first.
	user := env("MYSQL_USER", "provisioner")
	if !identity.MatchString(user) {
		return snapshotUnavailable
	}
	var partial, secure bool
	var mandatory string
	if db.QueryRowContext(ctx, "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport").Scan(&partial, &mandatory, &secure) != nil || partial || mandatory != "" || !secure {
		return snapshotUnavailable
	}
	grants, e := ownApplicationSQLGrants(ctx, db, applicationSQLAccount{User: user})
	if e != nil || !snapshotSchemaVisible(user, name, grants) {
		return snapshotUnavailable
	}
	var count int
	if db.QueryRowContext(ctx, "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&count) != nil || count != 0 {
		return snapshotUnavailable
	}
	return nil
}
func snapshotSchemaVisible(user, database string, grants []string) bool {
	for _, g := range grants {
		if len(g) > 16384 || strings.ContainsAny(g, "\x00\r\n\t") {
			return false
		}
		g = strings.TrimSuffix(g, " WITH GRANT OPTION")
		body := ""
		for _, account := range []string{"`" + user + "`@`%`", "'" + user + "'@'%'"} {
			if strings.HasSuffix(g, " TO "+account) {
				body = strings.TrimSuffix(g, " TO "+account)
			}
		}
		privileges, scope, ok := strings.Cut(strings.TrimPrefix(body, "GRANT "), " ON ")
		if !strings.HasPrefix(body, "GRANT ") || !ok {
			continue
		}
		if scope != "`app\\_%`.*" && scope != "`app\\_"+database[4:]+"`.*" {
			continue
		}
		for _, p := range strings.Split(privileges, ",") {
			if strings.TrimSpace(p) == "SELECT" {
				return true
			}
		}
	}
	return false
}
func (s *server) auditSnapshotAccount(ctx context.Context, v resources, db *sql.DB) error {
	admin, e := s.snapshotAdmin()
	if e != nil {
		return snapshotUnavailable
	}
	defer admin.Close()
	account := applicationSQLAccount{ResourceID: v.AppID, Database: v.Database, User: v.User, Password: v.Password, Version: 1, Verified: true}
	if verifyApplicationDatabase(ctx, admin, account) != nil {
		return snapshotUnavailable
	}
	grants, e := ownApplicationSQLGrants(ctx, db, account)
	if e != nil {
		return snapshotUnavailable
	}
	exact, e := inspectApplicationSQLGrants(v.AppID, v.Database, v.User, grants)
	if e != nil || !exact {
		return snapshotUnavailable
	}
	return nil
}

// TRIGGER metadata is privilege filtered. The company auditor grant itself is
// NOT read-only (TRIGGER permits create/drop); this trusted code executes fixed
// reads only and never creates or expands that account's privileges.
func (s *server) auditSnapshotObjects(ctx context.Context, v resources) error {
	var db *sql.DB
	var e error
	user := os.Getenv("MYSQL_SNAPSHOT_AUDITOR_USER")
	if !identity.MatchString(user) {
		return snapshotUnavailable
	}
	if s.snapshotAuditorOpen != nil {
		db, e = s.snapshotAuditorOpen()
	} else {
		password, pe := secret("MYSQL_SNAPSHOT_AUDITOR_PASSWORD")
		if pe != nil {
			return snapshotUnavailable
		}
		db, e = mysqlConnectionAs(user, password)
	}
	if e != nil {
		return snapshotUnavailable
	}
	defer db.Close()
	account := applicationSQLAccount{User: user}
	grants, e := ownApplicationSQLGrants(ctx, db, account)
	if e != nil {
		return snapshotUnavailable
	}
	scope, e := applicationSQLScope(v.AppID, v.Database, v.User)
	if e != nil || !snapshotAuditorGrants(user, scope, grants) {
		return snapshotUnavailable
	}
	for _, q := range []string{"SELECT COUNT(*) FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA=?", "SELECT COUNT(*) FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=?"} {
		var n int
		if db.QueryRowContext(ctx, q, v.Database).Scan(&n) != nil || n != 0 {
			return snapshotUnavailable
		}
	}
	return nil
}
func snapshotAuditorGrants(user, scope string, grants []string) bool {
	if len(grants) < 1 || len(grants) > 2 {
		return false
	}
	seen := false
	usage := false
	for _, g := range grants {
		if len(g) > 16384 || strings.ContainsAny(g, "\x00\r\n\t") {
			return false
		}
		body := ""
		for _, account := range []string{"`" + user + "`@`%`", "'" + user + "'@'%'"} {
			if strings.HasSuffix(g, " TO "+account) {
				body = strings.TrimSuffix(g, " TO "+account)
			}
		}
		if body == "GRANT USAGE ON *.*" && !usage {
			usage = true
			continue
		}
		privileges, target, ok := strings.Cut(strings.TrimPrefix(body, "GRANT "), " ON ")
		if !strings.HasPrefix(body, "GRANT ") || !ok || target != scope || seen {
			return false
		}
		parts := strings.Split(privileges, ",")
		if len(parts) != 2 {
			return false
		}
		names := map[string]bool{}
		for _, part := range parts {
			names[strings.TrimSpace(part)] = true
		}
		if !names["SELECT"] || !names["TRIGGER"] {
			return false
		}
		seen = true
	}
	return seen
}
func snapshotMetadataRead(ctx context.Context, c *sql.Conn, database string) (snapshotMetadata, error) {
	v := snapshotMetadata{Tables: []snapshotTable{}, Ledger: map[string]string{}}
	rows, e := c.QueryContext(ctx, "SELECT TABLE_NAME, ENGINE, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=? ORDER BY TABLE_NAME", database)
	if e != nil {
		return v, snapshotUnavailable
	}
	names := []string{}
	for rows.Next() {
		var name, engine, kind string
		if rows.Scan(&name, &engine, &kind) != nil || !snapshotSQLName.MatchString(name) || engine != "InnoDB" || kind != "BASE TABLE" || len(names) >= 64 || len(names) > 0 && name <= names[len(names)-1] {
			_ = rows.Close()
			return v, snapshotUnavailable
		}
		names = append(names, name)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return v, snapshotUnavailable
	}
	for _, name := range names {
		t := snapshotTable{Name: name, Columns: []string{}, Primary: []string{}}
		var actual string
		if c.QueryRowContext(ctx, "SHOW CREATE TABLE `"+database+"`.`"+name+"`").Scan(&actual, &t.Create) != nil || actual != name || len(t.Create) > 1<<20 || len(t.Create) == 0 {
			return v, snapshotUnavailable
		}
		if strings.Contains(strings.ToUpper(t.Create), "FOREIGN KEY") {
			return v, snapshotUnavailable
		}
		rows, e = c.QueryContext(ctx, "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA, GENERATION_EXPRESSION, ORDINAL_POSITION FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", database, name)
		if e != nil {
			return v, snapshotUnavailable
		}
		seen := map[string]bool{}
		for rows.Next() {
			var col snapshotColumn
			if rows.Scan(&col.Name, &col.DataType, &col.ColumnType, &col.Nullable, &col.Default, &col.Charset, &col.Collation, &col.Extra, &col.Generation, &col.Ordinal) != nil || !snapshotSQLName.MatchString(col.Name) || seen[col.Name] || len(t.Columns) >= 128 || col.Ordinal != len(t.Columns)+1 || !snapshotRawTypes[col.DataType] || len(col.ColumnType) > 1024 || col.Nullable != "YES" && col.Nullable != "NO" || col.Generation != "" || col.Extra != "" && !(name == "_autosoft_migrations" && col.Name == "applied_at" && col.DataType == "timestamp" && col.Extra == "DEFAULT_GENERATED" && col.Default.Valid && strings.EqualFold(col.Default.String, "CURRENT_TIMESTAMP")) {
				_ = rows.Close()
				return v, snapshotUnavailable
			}
			if len(col.Default.String) > 65536 || len(col.Charset.String) > 64 || len(col.Collation.String) > 128 {
				_ = rows.Close()
				return v, snapshotUnavailable
			}
			seen[col.Name] = true
			t.Columns = append(t.Columns, col.Name)
			t.Definitions = append(t.Definitions, col)
		}
		e = rows.Err()
		_ = rows.Close()
		if e != nil || len(t.Columns) == 0 {
			return v, snapshotUnavailable
		}
		rows, e = c.QueryContext(ctx, "SELECT COLUMN_NAME, SEQ_IN_INDEX, SUB_PART FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX", database, name)
		if e != nil {
			return v, snapshotUnavailable
		}
		for rows.Next() {
			var col string
			var seq int
			var part sql.NullInt64
			if rows.Scan(&col, &seq, &part) != nil || !seen[col] || seq != len(t.Primary)+1 || part.Valid || len(t.Primary) >= 8 {
				_ = rows.Close()
				return v, snapshotUnavailable
			}
			for _, prev := range t.Primary {
				if col == prev {
					_ = rows.Close()
					return v, snapshotUnavailable
				}
			}
			t.Primary = append(t.Primary, col)
		}
		e = rows.Err()
		_ = rows.Close()
		if e != nil || len(t.Primary) == 0 {
			return v, snapshotUnavailable
		}
		v.Tables = append(v.Tables, t)
		if name == "_autosoft_migrations" {
			v.Ledger, e = snapshotLedgerRead(ctx, c, database)
			if e != nil {
				return v, snapshotUnavailable
			}
		}
	}
	return v, nil
}

// Ledger-only admission authorizes no schema change and claims no schema
// compatibility. Old code-only/recovery releases need no capture metadata.
func snapshotLedgerRead(ctx context.Context, c *sql.Conn, database string) (map[string]string, error) {
	ledger := map[string]string{}
	rows, e := c.QueryContext(ctx, "SELECT id, checksum FROM `"+database+"`.`_autosoft_migrations` ORDER BY id")
	if e != nil {
		return nil, snapshotUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var id, sum string
		if rows.Scan(&id, &sum) != nil || !identity.MatchString(id) || !accessHex.MatchString(sum) || len(ledger) >= 1000 || ledger[id] != "" {
			return nil, snapshotUnavailable
		}
		ledger[id] = sum
	}
	if rows.Err() != nil {
		return nil, snapshotUnavailable
	}
	return ledger, nil
}
func snapshotUnapplied(m []Migration, ledger map[string]string) ([]string, error) {
	missing := []string{}
	seen := map[string]bool{}
	for _, v := range m {
		if !identity.MatchString(v.ID) || !accessHex.MatchString(v.Checksum) || seen[v.ID] {
			return nil, snapshotUnavailable
		}
		seen[v.ID] = true
		if existing, ok := ledger[v.ID]; ok {
			if existing != v.Checksum {
				return nil, snapshotUnavailable
			}
		} else {
			missing = append(missing, v.ID)
		}
	}
	return missing, nil
}
func snapshotRetainedLedger(m []Migration, ledger, applied map[string]string, completeHistory bool) error {
	if applied == nil || !reflect.DeepEqual(ledger, applied) {
		return snapshotUnavailable
	}
	if completeHistory {
		supplied := map[string]string{}
		for _, v := range m {
			supplied[v.ID] = v.Checksum
		}
		for id, sum := range ledger {
			if supplied[id] != sum {
				return snapshotUnavailable
			}
		}
	}
	return nil
}

type snapshotStream struct {
	file     *os.File
	a        cipher.AEAD
	prefix   []byte
	sequence uint32
	bytes    int64
	digest   hash.Hash
	binding  string
}

func (w *snapshotStream) write(value any) error {
	plain, e := json.Marshal(value)
	if e != nil || len(plain) > 1<<20 || w.sequence == ^uint32(0) {
		return snapshotUnavailable
	}
	nonce := append(append([]byte{}, w.prefix...), make([]byte, 4)...)
	binary.BigEndian.PutUint32(nonce[8:], w.sequence)
	aad := []byte(fmt.Sprintf("%s:%d", w.binding, w.sequence))
	sealed := w.a.Seal(nil, nonce, plain, aad)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(sealed)))
	frame = append(frame, sealed...)
	if w.bytes+int64(len(frame)) > snapshotMaximumBytes {
		return snapshotUnavailable
	}
	if _, e = w.file.Write(frame); e != nil {
		return snapshotUnavailable
	}
	_, _ = w.digest.Write(frame)
	w.bytes += int64(len(frame))
	w.sequence++
	return nil
}
func captureSnapshotRows(ctx context.Context, c *sql.Conn, database string, meta snapshotMetadata, w *snapshotStream, key []byte) (int, string, error) {
	rowsTotal := 0
	derive := hmac.New(sha256.New, key)
	_, _ = derive.Write([]byte("autosoft:migration-snapshot:row-digest:v1:" + w.binding))
	digest := hmac.New(sha256.New, derive.Sum(nil))
	for _, t := range meta.Tables {
		if e := w.write(map[string]any{"type": "table", "schema": t}); e != nil {
			return 0, "", e
		}
		quoted := func(values []string) string {
			parts := []string{}
			for _, s := range values {
				parts = append(parts, "`"+s+"`")
			}
			return strings.Join(parts, ",")
		}
		lengths := []string{}
		for _, col := range t.Columns {
			lengths = append(lengths, "COALESCE(OCTET_LENGTH(`"+col+"`),0)")
		}
		var maximum, count int64
		if c.QueryRowContext(ctx, "SELECT COALESCE(MAX("+strings.Join(lengths, "+")+"),0), COUNT(*) FROM `"+database+"`.`"+t.Name+"`").Scan(&maximum, &count) != nil || maximum < 0 || maximum > 512<<10 || count < 0 || count > snapshotMaximumRows-int64(rowsTotal) {
			return 0, "", snapshotUnavailable
		}
		rows, e := c.QueryContext(ctx, "SELECT "+quoted(t.Columns)+" FROM `"+database+"`.`"+t.Name+"` ORDER BY "+quoted(t.Primary))
		if e != nil {
			return 0, "", snapshotUnavailable
		}
		readCount := int64(0)
		for rows.Next() {
			if ctx.Err() != nil || rowsTotal >= snapshotMaximumRows {
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
			value := map[string]any{"type": "row", "table": t.Name, "values": values}
			plain, e := json.Marshal(value)
			if e != nil {
				_ = rows.Close()
				return 0, "", snapshotUnavailable
			}
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(plain)))
			_, _ = digest.Write(length[:])
			_, _ = digest.Write(plain)
			if e = w.write(value); e != nil {
				_ = rows.Close()
				return 0, "", e
			}
			rowsTotal++
			readCount++
		}
		e = rows.Err()
		_ = rows.Close()
		if e != nil || readCount != count {
			return 0, "", snapshotUnavailable
		}
	}
	return rowsTotal, hex.EncodeToString(digest.Sum(nil)), nil
}

func (s *server) captureMigrationSnapshot(ctx context.Context, q migrationSnapshotRequest, migrations []Migration) (migrationSnapshotReceipt, error) {
	value := emptySnapshot(q)
	if ctx.Err() != nil || s.snapshotContext(q) != nil || q.MigrationHash != migrationSetHash(migrations) {
		return value, snapshotUnavailable
	}
	if retained, e := s.readSnapshot(q); e == nil {
		if s.verifySnapshotStream(ctx, retained) != nil || s.retainSnapshot(retained) != nil || ctx.Err() != nil || s.snapshotContext(q) != nil {
			return value, snapshotUnavailable
		}
		return retained.Receipt, nil
	} else if !os.IsNotExist(e) {
		return value, snapshotUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	record := migrationSnapshotRecord{Receipt: value, Key: make([]byte, 32), NoncePrefix: make([]byte, 8)}
	if _, e := rand.Read(record.Key); e != nil {
		return value, snapshotUnavailable
	}
	if _, e := rand.Read(record.NoncePrefix); e != nil {
		return value, snapshotUnavailable
	}
	if s.retainSnapshot(record) != nil {
		return value, snapshotUnavailable
	}
	failCapture := func() (migrationSnapshotReceipt, error) {
		record.Receipt = emptySnapshot(q)
		record.Receipt.Status = "unavailable"
		_ = s.retainSnapshot(record)
		return record.Receipt, snapshotUnavailable
	}
	v, exists, e := s.snapshotAccount(q.AppID)
	if e != nil {
		return failCapture()
	}
	if !exists {
		if q.BaseReleaseID != nil || s.absentApplicationDatabase(ctx, q.AppID) != nil || ctx.Err() != nil || s.snapshotContext(q) != nil {
			return failCapture()
		}
		record.Receipt.Status = "no_previous_release"
		record.Receipt.Preservation = "no_previous_release"
		record.Receipt.Compatibility = "no_previous_release"
		record.Receipt.Reason = "none"
		record.Receipt.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if s.retainSnapshot(record) != nil || ctx.Err() != nil || s.snapshotContext(q) != nil {
			return failCapture()
		}
		return record.Receipt, nil
	}
	resourceBytes, e := snapshotFile(s, filepath.Join(s.data, "resources", q.AppID+".enc"), 1<<20)
	if e != nil {
		return failCapture()
	}
	record.ResourceHash = hashBytes(resourceBytes)
	db, e := s.snapshotDatabase(v)
	if e != nil {
		return failCapture()
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if s.auditSnapshotAccount(ctx, v, db) != nil {
		return failCapture()
	}
	c, e := db.Conn(ctx)
	if e != nil {
		return failCapture()
	}
	defer c.Close()
	before, e := snapshotMetadataRead(ctx, c, v.Database)
	if e != nil || s.auditSnapshotObjects(ctx, v) != nil {
		return failCapture()
	}
	if _, e = c.ExecContext(ctx, "SET SESSION time_zone='+00:00'"); e != nil {
		return failCapture()
	}
	if _, e = c.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); e != nil {
		return failCapture()
	}
	if _, e = c.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"); e != nil {
		return failCapture()
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = c.ExecContext(cleanup, "ROLLBACK")
	}()
	inside, e := snapshotMetadataRead(ctx, c, v.Database)
	if e != nil || !reflect.DeepEqual(before, inside) || snapshotRetainedLedger(migrations, inside.Ledger, v.Applied, true) != nil {
		return failCapture()
	}
	unapplied, e := snapshotUnapplied(migrations, inside.Ledger)
	if e != nil {
		return failCapture()
	}
	file := filepath.Join(s.snapshotDirectory(q), "rows.enc")
	f, e := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return failCapture()
	}
	defer f.Close()
	block, e := aes.NewCipher(record.Key)
	if e != nil {
		return failCapture()
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return failCapture()
	}
	stream := snapshotStream{file: f, a: a, prefix: record.NoncePrefix, digest: sha256.New(), binding: value.RequestHash}
	if stream.write(map[string]any{"type": "snapshot", "requestHash": value.RequestHash, "metadata": inside}) != nil {
		return failCapture()
	}
	rows, rowDigest, e := captureSnapshotRows(ctx, c, v.Database, inside, &stream, record.Key)
	if e != nil {
		return failCapture()
	}
	after, e := snapshotMetadataRead(ctx, c, v.Database)
	currentResource, re := snapshotFile(s, filepath.Join(s.data, "resources", q.AppID+".enc"), 1<<20)
	if e != nil || re != nil || hashBytes(currentResource) != record.ResourceHash || !reflect.DeepEqual(inside, after) || s.auditSnapshotObjects(ctx, v) != nil || s.snapshotContext(q) != nil || ctx.Err() != nil {
		return failCapture()
	}
	if stream.write(map[string]any{"type": "complete", "rows": rows, "schemaHash": accessHash(inside.Tables), "ledgerHash": accessHash(inside.Ledger)}) != nil || f.Sync() != nil || f.Close() != nil {
		return failCapture()
	}
	// Read back ciphertext without ever placing row plaintext in an API receipt.
	f, e = os.Open(file)
	if e != nil {
		return failCapture()
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, snapshotMaximumBytes+1))
	_ = f.Close()
	if e != nil || n != stream.bytes || hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(stream.digest.Sum(nil)) || ctx.Err() != nil || s.snapshotContext(q) != nil {
		return failCapture()
	}
	record.Receipt.Status = "captured"
	record.Receipt.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	record.Receipt.SchemaEpoch = v.Schema
	record.Receipt.SchemaHash = accessHash(inside.Tables)
	record.Receipt.LedgerHash = accessHash(inside.Ledger)
	record.Receipt.StreamHash = hex.EncodeToString(h.Sum(nil))
	record.Receipt.RowDigest = rowDigest
	record.Receipt.Tables = len(inside.Tables)
	record.Receipt.Rows = rows
	record.Receipt.Bytes = n
	record.Receipt.Unapplied = unapplied
	record.Receipt.Preservation = "captured_only"
	record.Receipt.Reason = "none"
	if len(unapplied) > 0 {
		record.Receipt.Reason = "migration_contract_required"
	}
	if s.verifySnapshotStream(ctx, record) != nil || s.retainSnapshot(record) != nil || ctx.Err() != nil || s.snapshotContext(q) != nil {
		return failCapture()
	}
	return record.Receipt, nil
}

// This guard is shared by publish, ordinary/emergency rollback and automatic
// recovery. Existing databases can execute no new DDL until the later complete
// preservation + old/new functional compatibility proof is implemented.
func (s *server) migrationAdmission(ctx context.Context, appID string, migrations []Migration, proof *migrationSnapshotReceipt, completeHistory bool) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	v, exists, e := s.snapshotAccount(appID)
	if e != nil {
		return false, snapshotUnavailable
	}
	if !exists {
		if _, e := snapshotFile(s, filepath.Join(s.data, "active", appID+".json"), 1<<20); !os.IsNotExist(e) {
			return false, snapshotUnavailable
		}
		return true, s.absentApplicationDatabase(ctx, appID)
	}
	db, e := s.snapshotDatabase(v)
	if e != nil {
		return false, snapshotUnavailable
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if s.auditSnapshotAccount(ctx, v, db) != nil {
		return false, snapshotUnavailable
	}
	c, e := db.Conn(ctx)
	if e != nil {
		return false, snapshotUnavailable
	}
	defer c.Close()
	ledger, e := snapshotLedgerRead(ctx, c, v.Database)
	if e != nil || snapshotRetainedLedger(migrations, ledger, v.Applied, completeHistory) != nil {
		return false, snapshotUnavailable
	}
	if proof != nil {
		if validateSnapshotReceipt(*proof) != nil || proof.Binding.AppID != appID || proof.Binding.MigrationHash != migrationSetHash(migrations) || proof.SchemaEpoch != v.Schema || proof.Status != "captured" {
			return false, snapshotUnavailable
		}
		retained, re := s.readSnapshot(proof.Binding)
		if re != nil || !reflect.DeepEqual(retained.Receipt, *proof) || s.verifySnapshotStream(ctx, retained) != nil || s.retainSnapshot(retained) != nil {
			return false, snapshotUnavailable
		}
		meta, me := snapshotMetadataRead(ctx, c, v.Database)
		if me != nil || proof.SchemaHash != accessHash(meta.Tables) || proof.LedgerHash != accessHash(meta.Ledger) || s.auditSnapshotObjects(ctx, v) != nil {
			return false, snapshotUnavailable
		}
	}
	missing, e := snapshotUnapplied(migrations, ledger)
	if e != nil {
		return false, snapshotUnavailable
	}
	if len(missing) > 0 {
		return false, errors.New("Existing application migrations require record-preservation and previous-release compatibility proof before any live DDL; capture alone is insufficient")
	}
	if ctx.Err() != nil {
		return false, snapshotUnavailable
	}
	return false, nil
}
func (s *server) registerMigrationSnapshotRoutes(mux *http.ServeMux) {
	handler := func(capture bool) http.HandlerFunc {
		return s.authenticated(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				fail(w, 405, snapshotUnavailable)
				return
			}
			var q migrationSnapshotRequest
			body, e := io.ReadAll(io.LimitReader(r.Body, 65537))
			if e != nil || len(body) > 65536 || len(s.approvalKey) != 32 || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
				fail(w, 400, snapshotUnavailable)
				return
			}
			d := json.NewDecoder(bytes.NewReader(body))
			d.DisallowUnknownFields()
			if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || validateSnapshotRequest(q) != nil {
				fail(w, 400, snapshotUnavailable)
				return
			}
			unlock := s.lock("app-" + q.AppID)
			defer unlock()
			if s.snapshotContext(q) != nil {
				fail(w, 409, snapshotUnavailable)
				return
			}
			if !capture {
				v, e := s.readSnapshot(q)
				if e != nil || s.verifySnapshotStream(r.Context(), v) != nil || s.retainSnapshot(v) != nil || r.Context().Err() != nil || s.snapshotContext(q) != nil {
					fail(w, 409, snapshotUnavailable)
					return
				}
				respond(w, v.Receipt)
				return
			}
			m, e := readMigrations(filepath.Join(s.data, "sources", q.AttemptID))
			if e != nil {
				fail(w, 409, snapshotUnavailable)
				return
			}
			v, e := s.captureMigrationSnapshot(r.Context(), q, m)
			if e != nil {
				respond(w, v)
				return
			}
			respond(w, v)
		})
	}
	mux.HandleFunc("/v1/migrations/snapshot", handler(true))
	mux.HandleFunc("/v1/migrations/snapshot-status", handler(false))
}
