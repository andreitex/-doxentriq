package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const mysqlGrantPolicyVersion = 1

type applicationSQLAccount struct {
	ResourceID, Database, User, Password string
	Version                              int
	Verified                             bool
}

func retainApplicationSQLResources(file string, value resources) error {
	if e := writeEncrypted(file, value); e != nil {
		return errors.New("Encrypted application privilege initialization state could not be retained")
	}
	handle, e := os.Open(file)
	if e != nil {
		return errors.New("Encrypted application privilege initialization state is unavailable")
	}
	e = handle.Sync()
	_ = handle.Close()
	if e != nil {
		return errors.New("Encrypted application privilege initialization state could not be synchronized")
	}
	directory, e := os.Open(filepath.Dir(file))
	if e != nil {
		return errors.New("Encrypted application privilege initialization directory is unavailable")
	}
	defer directory.Close()
	if e = directory.Sync(); e != nil {
		return errors.New("Encrypted application privilege initialization directory could not be synchronized")
	}
	return nil
}

var applicationSQLResource = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,87}$`)
var applicationSQLDatabase = regexp.MustCompile(`^app_[a-f0-9]{24}$`)
var applicationSQLPassword = regexp.MustCompile(`^[a-f0-9]{64}$`)

func applicationSQLNames(resourceID, database, user string) error {
	if !applicationSQLResource.MatchString(resourceID) {
		return errors.New("Application database resource identity is invalid")
	}
	digest := sha256.Sum256([]byte(resourceID))
	expected := "app_" + hex.EncodeToString(digest[:])[:24]
	if database != expected || user != expected || !applicationSQLDatabase.MatchString(database) {
		return errors.New("Application database or account is not bound to its exact resource identity")
	}
	return nil
}

// Database-level GRANT interprets underscore as a wildcard even inside backticks
// when partial_revokes is OFF. CREATE DATABASE/USE must keep the literal name;
// only the privilege pattern receives this escape.
func applicationSQLScope(resourceID, database, user string) (string, error) {
	if e := applicationSQLNames(resourceID, database, user); e != nil {
		return "", e
	}
	return "`app\\_" + database[4:] + "`.*", nil
}

func applicationSQLGrant(resourceID, database, user string) (string, error) {
	scope, e := applicationSQLScope(resourceID, database, user)
	if e != nil {
		return "", e
	}
	return "GRANT SELECT, INSERT, UPDATE ON " + scope + " TO '" + user + "'@'%'", nil
}

// inspectApplicationSQLGrants accepts only the account's own USAGE and complete
// literal SELECT/INSERT/UPDATE grant. It never treats adding a second literal
// grant as removal of a retained legacy wildcard, global grant, or role.
func inspectApplicationSQLGrants(resourceID, database, user string, rows []string) (hasExact bool, e error) {
	scope, e := applicationSQLScope(resourceID, database, user)
	if e != nil {
		return false, e
	}
	if len(rows) < 1 || len(rows) > 16 {
		return false, errors.New("Application privilege evidence is unavailable or oversized")
	}
	seenUsage := false
	for _, row := range rows {
		if len(row) > 16384 || strings.ContainsAny(row, "\x00\r\n\t") {
			return false, errors.New("Application privilege evidence is malformed")
		}
		body := ""
		for _, account := range []string{"`" + user + "`@`%`", "'" + user + "'@'%'"} {
			if strings.HasSuffix(row, " TO "+account) {
				body = strings.TrimSuffix(row, " TO "+account)
				break
			}
		}
		if !strings.HasPrefix(body, "GRANT ") {
			return false, errors.New("Unexpected application account, role, or privilege statement requires company review")
		}
		privileges, target, found := strings.Cut(strings.TrimPrefix(body, "GRANT "), " ON ")
		if !found {
			return false, errors.New("Application privilege target is malformed")
		}
		if target == "*.*" && privileges == "USAGE" && !seenUsage {
			seenUsage = true
			continue
		}
		if target == "`"+database+"`.*" {
			return false, errors.New("Legacy database wildcard grant requires separately reviewed company permission tightening")
		}
		if target != scope || hasExact {
			return false, errors.New("Unexpected or duplicate application database privilege scope requires company review")
		}
		parts := strings.Split(privileges, ",")
		permitted := map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true}
		if len(parts) != 3 {
			return false, errors.New("Changed application database privileges require company review")
		}
		for _, part := range parts {
			name := strings.TrimSpace(part)
			if !permitted[name] {
				return false, errors.New("Changed application database privileges require company review")
			}
			delete(permitted, name)
		}
		hasExact = true
	}
	return hasExact, nil
}

// A pending v1 encrypted resource is the durable initial-grant intent, written
// before CREATE USER. USAGE-only can then recover a crash before initial GRANT.
// Legacy/verified accounts never have missing rights automatically restored.
func applicationSQLGrantNeeded(resourceID, database, user string, version int, verified bool, rows []string) (bool, error) {
	if (version != 0 && version != mysqlGrantPolicyVersion) || (version == 0 && verified) {
		return false, errors.New("Application database grant initialization evidence is invalid")
	}
	exact, e := inspectApplicationSQLGrants(resourceID, database, user, rows)
	if e != nil {
		return false, e
	}
	if exact {
		return false, nil
	}
	if version == mysqlGrantPolicyVersion && !verified {
		return true, nil
	}
	return false, errors.New("Existing application database privileges are incomplete; preserve them for company review")
}

func ownApplicationSQLGrants(ctx context.Context, db *sql.DB, account applicationSQLAccount) ([]string, error) {
	var tlsName, tlsCipher string
	if e := db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&tlsName, &tlsCipher); e != nil || tlsName != "Ssl_cipher" || tlsCipher == "" || len(tlsCipher) > 256 {
		return nil, errors.New("Authenticated application MySQL TLS evidence is unavailable; preserve permissions for company review")
	}
	var current, roles string
	if e := db.QueryRowContext(ctx, "SELECT CURRENT_USER(), CURRENT_ROLE()").Scan(&current, &roles); e != nil || current != account.User+"@%" || roles != "NONE" {
		return nil, errors.New("Exact application account identity or role evidence is unavailable; preserve permissions for company review")
	}
	rows, e := db.QueryContext(ctx, "SHOW GRANTS")
	if e != nil {
		return nil, errors.New("Application privilege evidence is unavailable; preserve permissions for company review")
	}
	defer rows.Close()
	grants := []string{}
	for rows.Next() {
		var grant string
		if e = rows.Scan(&grant); e != nil || len(grants) == 16 || len(grant) > 16384 {
			return nil, errors.New("Application privilege evidence is malformed or oversized")
		}
		grants = append(grants, grant)
	}
	if rows.Err() != nil {
		return nil, errors.New("Application privilege evidence was interrupted; preserve permissions for company review")
	}
	return grants, nil
}

func verifyApplicationDatabase(ctx context.Context, admin *sql.DB, account applicationSQLAccount) error {
	var name, encryption string
	if e := admin.QueryRowContext(ctx, "SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?", account.Database).Scan(&name, &encryption); e != nil || name != account.Database || (encryption != "Y" && encryption != "YES") {
		return errors.New("Exact encrypted application database evidence is unavailable; preserve the existing database and permissions for company review")
	}
	return nil
}

// A persisted pending account may finish its first exact grant. Existing legacy
// or verified accounts are audited without CREATE/GRANT before further work.
// Credentials and raw MySQL errors never enter returned diagnostics.
func ensureApplicationSQLGrants(ctx context.Context, admin *sql.DB, account applicationSQLAccount, openOwn func() (*sql.DB, error), persistVerified func() error) error {
	if e := applicationSQLNames(account.ResourceID, account.Database, account.User); e != nil {
		return e
	}
	if !applicationSQLPassword.MatchString(account.Password) || (account.Version != 0 && account.Version != mysqlGrantPolicyVersion) || (account.Version == 0 && account.Verified) {
		return errors.New("Application database initialization evidence is invalid")
	}
	var partial bool
	var secure bool
	var mandatory string
	if e := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport").Scan(&partial, &mandatory, &secure); e != nil || partial || mandatory != "" || !secure {
		return errors.New("MySQL privilege semantics are unsupported or unavailable; no global configuration was changed")
	}
	if account.Version == mysqlGrantPolicyVersion && !account.Verified {
		// CREATE USER IF NOT EXISTS cannot reset an existing password. A stale
		// pre-existing account must still authenticate with the retained random
		// password and pass its exact own-grants audit before receiving rights.
		for _, statement := range []string{"CREATE DATABASE IF NOT EXISTS `" + account.Database + "` CHARACTER SET utf8mb4 ENCRYPTION='Y'", "CREATE USER IF NOT EXISTS '" + account.User + "'@'%' IDENTIFIED BY '" + account.Password + "' REQUIRE SSL"} {
			if _, e := admin.ExecContext(ctx, statement); e != nil {
				return errors.New("Scoped MySQL initialization outcome is unavailable; retain the encrypted initialization record for inspection")
			}
		}
	}
	if e := verifyApplicationDatabase(ctx, admin, account); e != nil {
		return e
	}
	own, e := openOwn()
	if e != nil {
		return errors.New("Exact application credential verification is unavailable; no password was reset")
	}
	defer own.Close()
	grants, e := ownApplicationSQLGrants(ctx, own, account)
	if e != nil {
		return e
	}
	needed, e := applicationSQLGrantNeeded(account.ResourceID, account.Database, account.User, account.Version, account.Verified, grants)
	if e != nil {
		return e
	}
	if needed {
		statement, e := applicationSQLGrant(account.ResourceID, account.Database, account.User)
		if e != nil {
			return e
		}
		if _, e = admin.ExecContext(ctx, statement); e != nil {
			return errors.New("Exact application grant outcome is unavailable; retained permissions require authenticated readback")
		}
		grants, e = ownApplicationSQLGrants(ctx, own, account)
		if e != nil {
			return e
		}
		if exact, audit := inspectApplicationSQLGrants(account.ResourceID, account.Database, account.User, grants); audit != nil || !exact {
			return errors.New("Exact application grant was not independently verified; preserve current permissions for company review")
		}
	}
	if e = persistVerified(); e != nil {
		return errors.New("Verified application privilege state could not be retained; retry only with exact authenticated privilege readback")
	}
	return nil
}
