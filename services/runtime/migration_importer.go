package main

// A snapshot import proves only that retained rows can be reconstructed in a
// private clone. It supplies neither application compatibility nor permission
// to alter the live database.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type importedSnapshot struct {
	Metadata  snapshotMetadata
	Rows      int
	RowDigest string
}

// Reject duplicate JSON keys instead of accepting decoder's last-value wins.
// The frame size is bounded before this decoder sees any bytes.
func importerJSON(plain []byte, value any) error {
	if !utf8.Valid(plain) {
		return snapshotUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 16 {
			return snapshotUnavailable
		}
		t, e := d.Token()
		if e != nil {
			return snapshotUnavailable
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					key, ok := k.(string)
					if e != nil || !ok || seen[key] {
						return snapshotUnavailable
					}
					seen[key] = true
					if visit(depth+1) != nil {
						return snapshotUnavailable
					}
				}
				if t, e = d.Token(); e != nil || t != json.Delim('}') {
					return snapshotUnavailable
				}
			case '[':
				for d.More() {
					if visit(depth+1) != nil {
						return snapshotUnavailable
					}
				}
				if t, e = d.Token(); e != nil || t != json.Delim(']') {
					return snapshotUnavailable
				}
			default:
				return snapshotUnavailable
			}
		}
		return nil
	}
	if visit(0) != nil {
		return snapshotUnavailable
	}
	if _, e := d.Token(); e != io.EOF {
		return snapshotUnavailable
	}
	d = json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return snapshotUnavailable
	}
	// Struct fields must use their exact serialized names and presence. This
	// rejects case-insensitive aliases as well as omitted required frame keys.
	var shape any
	if json.Unmarshal(plain, &shape) != nil || accessHash(shape) != accessHash(value) {
		return snapshotUnavailable
	}
	return nil
}

func importerDigest(key []byte, requestHash string) hash.Hash {
	derive := hmac.New(sha256.New, key)
	_, _ = derive.Write([]byte("autosoft:migration-snapshot:row-digest:v1:" + requestHash))
	return hmac.New(sha256.New, derive.Sum(nil))
}

func importerDigestRow(digest hash.Hash, table string, values []any) error {
	plain, e := json.Marshal(map[string]any{"type": "row", "table": table, "values": values})
	if e != nil {
		return snapshotUnavailable
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(plain)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(plain)
	return nil
}

// Each call validates a complete authenticated stream. The first call has no
// row callback; it must finish before any clone SQL. The import call checks the
// same full proof again and quarantines the clone on a changed second pass.
func decodeImportSnapshot(ctx context.Context, reader io.Reader, record migrationSnapshotRecord, row func(snapshotTable, []any) error) (importedSnapshot, error) {
	var out importedSnapshot
	v := record.Receipt
	if validateSnapshotReceipt(v) != nil || v.Status != "captured" || len(record.Key) != 32 || len(record.NoncePrefix) != 8 {
		return out, snapshotUnavailable
	}
	block, e := aes.NewCipher(record.Key)
	if e != nil {
		return out, snapshotUnavailable
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return out, snapshotUnavailable
	}
	h := sha256.New()
	limited := &io.LimitedReader{R: reader, N: v.Bytes + 1}
	r := io.TeeReader(limited, h)
	digest := importerDigest(record.Key, v.RequestHash)
	seq := uint32(0)
	tableIndex := -1
	completed := false
	keys := map[string]bool{}
	ledger := map[string]string{}
	for {
		if ctx.Err() != nil {
			return out, snapshotUnavailable
		}
		var header [4]byte
		_, e = io.ReadFull(r, header[:])
		if e == io.EOF {
			break
		}
		if e != nil || completed || seq == ^uint32(0) {
			return out, snapshotUnavailable
		}
		length := binary.BigEndian.Uint32(header[:])
		if length < uint32(a.Overhead()) || length > (1<<20)+uint32(a.Overhead()) || int64(length) > limited.N {
			return out, snapshotUnavailable
		}
		sealed := make([]byte, int(length))
		if _, e = io.ReadFull(r, sealed); e != nil {
			return out, snapshotUnavailable
		}
		nonce := append(append([]byte{}, record.NoncePrefix...), make([]byte, 4)...)
		binary.BigEndian.PutUint32(nonce[8:], seq)
		plain, e := a.Open(nil, nonce, sealed, []byte(fmt.Sprintf("%s:%d", v.RequestHash, seq)))
		if e != nil || len(plain) > 1<<20 {
			return out, snapshotUnavailable
		}
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(plain, &kind) != nil {
			return out, snapshotUnavailable
		}
		switch kind.Type {
		case "snapshot":
			var frame struct {
				Type        string           `json:"type"`
				RequestHash string           `json:"requestHash"`
				Metadata    snapshotMetadata `json:"metadata"`
			}
			if seq != 0 || importerJSON(plain, &frame) != nil || frame.RequestHash != v.RequestHash || importerTables(frame.Metadata) != nil || len(frame.Metadata.Tables) != v.Tables || accessHash(frame.Metadata.Tables) != v.SchemaHash || accessHash(frame.Metadata.Ledger) != v.LedgerHash {
				return out, snapshotUnavailable
			}
			out.Metadata = frame.Metadata
		case "table":
			var frame struct {
				Type   string        `json:"type"`
				Schema snapshotTable `json:"schema"`
			}
			tableIndex++
			if seq == 0 || importerJSON(plain, &frame) != nil || tableIndex >= len(out.Metadata.Tables) || !importerEqual(frame.Schema, out.Metadata.Tables[tableIndex]) {
				return out, snapshotUnavailable
			}
			keys = map[string]bool{}
		case "row":
			var frame struct {
				Type   string            `json:"type"`
				Table  string            `json:"table"`
				Values []json.RawMessage `json:"values"`
			}
			if tableIndex < 0 || importerJSON(plain, &frame) != nil || out.Rows >= snapshotMaximumRows {
				return out, snapshotUnavailable
			}
			t := out.Metadata.Tables[tableIndex]
			if frame.Table != t.Name || len(frame.Values) != len(t.Columns) {
				return out, snapshotUnavailable
			}
			values := make([]any, len(frame.Values))
			size := 0
			for i, raw := range frame.Values {
				if bytes.Equal(raw, []byte("null")) {
					if t.Definitions[i].Nullable != "YES" {
						return out, snapshotUnavailable
					}
					continue
				}
				var encoded string
				if json.Unmarshal(raw, &encoded) != nil {
					return out, snapshotUnavailable
				}
				b, e := base64.StdEncoding.DecodeString(encoded)
				if e != nil || base64.StdEncoding.EncodeToString(b) != encoded {
					return out, snapshotUnavailable
				}
				size += len(b)
				if size > 512<<10 {
					return out, snapshotUnavailable
				}
				values[i] = b
			}
			pk := []any{}
			for _, name := range t.Primary {
				for i, col := range t.Columns {
					if col == name {
						if values[i] == nil {
							return out, snapshotUnavailable
						}
						pk = append(pk, values[i])
					}
				}
			}
			// The keyed, length-delimited encoding distinguishes composite keys,
			// NULL and empty values without retaining plaintext PKs in the set.
			p, _ := json.Marshal(pk)
			derive := hmac.New(sha256.New, record.Key)
			_, _ = derive.Write([]byte("autosoft:migration-import:primary-key:v1:" + v.RequestHash + ":" + t.Name))
			pd := hmac.New(sha256.New, derive.Sum(nil))
			_, _ = pd.Write(p)
			key := hex.EncodeToString(pd.Sum(nil))
			if keys[key] {
				return out, snapshotUnavailable
			}
			keys[key] = true
			if t.Name == "_autosoft_migrations" {
				if len(values) < 2 || values[0] == nil || values[1] == nil {
					return out, snapshotUnavailable
				}
				id, sum := string(values[0].([]byte)), string(values[1].([]byte))
				if !identity.MatchString(id) || !accessHex.MatchString(sum) || ledger[id] != "" {
					return out, snapshotUnavailable
				}
				ledger[id] = sum
			}
			if importerDigestRow(digest, t.Name, values) != nil {
				return out, snapshotUnavailable
			}
			if row != nil && row(t, values) != nil {
				return out, snapshotUnavailable
			}
			out.Rows++
		case "complete":
			var frame struct {
				Type       string `json:"type"`
				Rows       int    `json:"rows"`
				SchemaHash string `json:"schemaHash"`
				LedgerHash string `json:"ledgerHash"`
			}
			if seq == 0 || importerJSON(plain, &frame) != nil || tableIndex+1 != len(out.Metadata.Tables) || frame.Rows != out.Rows || out.Rows != v.Rows || frame.SchemaHash != v.SchemaHash || frame.LedgerHash != v.LedgerHash {
				return out, snapshotUnavailable
			}
			completed = true
		default:
			return out, snapshotUnavailable
		}
		seq++
	}
	out.RowDigest = hex.EncodeToString(digest.Sum(nil))
	if !completed || v.Bytes+1-limited.N != v.Bytes || hex.EncodeToString(h.Sum(nil)) != v.StreamHash || out.RowDigest != v.RowDigest || !importerEqual(ledger, out.Metadata.Ledger) {
		return out, snapshotUnavailable
	}
	return out, nil
}

func importerEqual(a, b any) bool { return accessHash(a) == accessHash(b) }

var importerType = regexp.MustCompile(`^([a-z]+)(?:\(([0-9]+)(?:,([0-9]+))?\))?( unsigned)?$`)
var importerCharset = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func importerColumn(c snapshotColumn, table string) (string, error) {
	if !snapshotSQLName.MatchString(c.Name) || c.Generation != "" || c.Nullable != "YES" && c.Nullable != "NO" || c.Extra != "" && !(table == "_autosoft_migrations" && c.Name == "applied_at" && c.DataType == "timestamp" && c.Extra == "DEFAULT_GENERATED" && c.Default.Valid && strings.EqualFold(c.Default.String, "CURRENT_TIMESTAMP")) {
		return "", snapshotUnavailable
	}
	m := importerType.FindStringSubmatch(c.ColumnType)
	if m == nil || m[1] != c.DataType || !snapshotRawTypes[c.DataType] {
		return "", snapshotUnavailable
	}
	n, scale := 0, 0
	var e error
	if m[2] != "" {
		n, e = strconv.Atoi(m[2])
		if e != nil || n < 1 || n > 65535 {
			return "", snapshotUnavailable
		}
	}
	if m[3] != "" {
		scale, e = strconv.Atoi(m[3])
		if e != nil || scale > 30 || scale > n {
			return "", snapshotUnavailable
		}
	}
	integer := c.DataType == "tinyint" || c.DataType == "smallint" || c.DataType == "mediumint" || c.DataType == "int" || c.DataType == "bigint"
	character := c.DataType == "char" || c.DataType == "varchar" || strings.HasSuffix(c.DataType, "text")
	switch {
	case integer:
		if m[3] != "" || n > 255 {
			return "", snapshotUnavailable
		}
	case c.DataType == "decimal":
		if n < 1 || n > 65 {
			return "", snapshotUnavailable
		}
	case c.DataType == "char" || c.DataType == "binary":
		if n < 1 || n > 255 || m[3] != "" {
			return "", snapshotUnavailable
		}
	case c.DataType == "varchar" || c.DataType == "varbinary":
		if n < 1 || m[3] != "" {
			return "", snapshotUnavailable
		}
	case c.DataType == "bit":
		if n < 1 || n > 64 || m[3] != "" {
			return "", snapshotUnavailable
		}
	case c.DataType == "datetime" || c.DataType == "timestamp" || c.DataType == "time":
		if n > 6 || m[3] != "" {
			return "", snapshotUnavailable
		}
	default:
		if m[2] != "" || m[3] != "" {
			return "", snapshotUnavailable
		}
	}
	if m[4] != "" && !integer && c.DataType != "decimal" {
		return "", snapshotUnavailable
	}
	if character {
		if !c.Charset.Valid || !c.Collation.Valid || !importerCharset.MatchString(c.Charset.String) || !importerCharset.MatchString(c.Collation.String) || !strings.HasPrefix(c.Collation.String, c.Charset.String+"_") {
			return "", snapshotUnavailable
		}
	} else if c.Charset.Valid || c.Collation.Valid {
		return "", snapshotUnavailable
	}
	if !c.Default.Valid && c.Default.String != "" || !c.Charset.Valid && c.Charset.String != "" || !c.Collation.Valid && c.Collation.String != "" {
		return "", snapshotUnavailable
	}
	ddl := "`" + c.Name + "` " + c.ColumnType
	if character {
		ddl += " CHARACTER SET " + c.Charset.String + " COLLATE " + c.Collation.String
	}
	if c.Nullable == "NO" {
		ddl += " NOT NULL"
	} else {
		ddl += " NULL"
	}
	if c.Default.Valid {
		if len(c.Default.String) > 65536 || !utf8.ValidString(c.Default.String) || strings.ContainsRune(c.Default.String, 0) {
			return "", snapshotUnavailable
		}
		if c.Extra == "DEFAULT_GENERATED" {
			ddl += " DEFAULT CURRENT_TIMESTAMP"
		} else { // fixed NO_BACKSLASH_ESCAPES session
			ddl += " DEFAULT '" + strings.ReplaceAll(c.Default.String, "'", "''") + "'"
		}
	} else if c.Nullable == "YES" {
		ddl += " DEFAULT NULL"
	}
	return ddl, nil
}

func importerTables(meta snapshotMetadata) error {
	if meta.Tables == nil || len(meta.Tables) > 64 || meta.Ledger == nil || len(meta.Ledger) > 1000 {
		return snapshotUnavailable
	}
	ledgerTable := false
	for ti, t := range meta.Tables {
		if !snapshotSQLName.MatchString(t.Name) || ti > 0 && t.Name <= meta.Tables[ti-1].Name || len(t.Columns) == 0 || len(t.Columns) > 128 || len(t.Definitions) != len(t.Columns) || len(t.Primary) == 0 || len(t.Primary) > 8 || len(t.Create) == 0 || len(t.Create) > 1<<20 {
			return snapshotUnavailable
		}
		// Secondary constraints and known unsupported storage clauses are
		// unavailable. The receipt covers the typed old columns and PK, rather
		// than claiming equivalence of every SHOW CREATE table option.
		upper := strings.ToUpper(t.Create)
		for _, unsupported := range []string{"FOREIGN KEY", "UNIQUE KEY", "UNIQUE INDEX", "CONSTRAINT", "CHECK (", "CHECK(", "AUTO_INCREMENT", "PARTITION", "TABLESPACE", "DATA DIRECTORY", "INDEX DIRECTORY", " FULLTEXT ", " SPATIAL ", " KEY `"} {
			if strings.Contains(upper, unsupported) {
				return snapshotUnavailable
			}
		}
		seen := map[string]bool{}
		for i, c := range t.Definitions {
			if c.Name != t.Columns[i] || c.Ordinal != i+1 || seen[c.Name] {
				return snapshotUnavailable
			}
			seen[c.Name] = true
			if _, e := importerColumn(c, t.Name); e != nil {
				return e
			}
		}
		pk := map[string]bool{}
		for _, name := range t.Primary {
			if !seen[name] || pk[name] {
				return snapshotUnavailable
			}
			pk[name] = true
			for _, c := range t.Definitions {
				if c.Name == name && c.Nullable != "NO" {
					return snapshotUnavailable
				}
			}
		}
		if t.Name == "_autosoft_migrations" {
			ledgerTable = true
			if len(t.Columns) < 2 || t.Columns[0] != "id" || t.Columns[1] != "checksum" || len(t.Primary) != 1 || t.Primary[0] != "id" {
				return snapshotUnavailable
			}
		}
	}
	for id, sum := range meta.Ledger {
		if !identity.MatchString(id) || !accessHex.MatchString(sum) || !ledgerTable {
			return snapshotUnavailable
		}
	}
	return nil
}

func importerCreateTable(database string, t snapshotTable) (string, error) {
	if !applicationSQLDatabase.MatchString(database) || importerTables(snapshotMetadata{Tables: []snapshotTable{t}, Ledger: map[string]string{}}) != nil {
		return "", snapshotUnavailable
	}
	parts := []string{}
	for _, c := range t.Definitions {
		text, e := importerColumn(c, t.Name)
		if e != nil {
			return "", e
		}
		parts = append(parts, text)
	}
	pk := []string{}
	for _, c := range t.Primary {
		pk = append(pk, "`"+c+"`")
	}
	parts = append(parts, "PRIMARY KEY ("+strings.Join(pk, ",")+")")
	return "CREATE TABLE `" + database + "`.`" + t.Name + "` (" + strings.Join(parts, ",") + ") ENGINE=InnoDB ENCRYPTION='Y'", nil
}

func importerInsert(ctx context.Context, c *sql.Conn, database string, t snapshotTable, values []any) error {
	if !applicationSQLDatabase.MatchString(database) || len(values) != len(t.Columns) {
		return snapshotUnavailable
	}
	cols, marks := []string{}, []string{}
	for _, name := range t.Columns {
		if !snapshotSQLName.MatchString(name) {
			return snapshotUnavailable
		}
		cols = append(cols, "`"+name+"`")
		marks = append(marks, "?")
	}
	result, e := c.ExecContext(ctx, "INSERT INTO `"+database+"`.`"+t.Name+"` ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")", values...)
	if e != nil {
		return snapshotUnavailable
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return snapshotUnavailable
	}
	return nil
}
