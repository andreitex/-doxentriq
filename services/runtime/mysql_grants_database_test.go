package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type grantSQLState struct {
	account                                   applicationSQLAccount
	grants                                    []string
	events                                    []string
	partial                                   bool
	secure                                    bool
	tlsCipher                                 string
	databaseMissing                           bool
	databaseEncryption                        string
	mandatory, current, roles                 string
	created                                   bool
	grantCount, reads, saves                  int
	loseCreate, loseGrant, loseRead, loseSave bool
}
type grantSQLConnector struct {
	state *grantSQLState
	admin bool
}

func (c grantSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &grantSQLConnection{c.state, c.admin}, nil
}
func (c grantSQLConnector) Driver() driver.Driver { return grantSQLDriver{} }

type grantSQLDriver struct{}

func (grantSQLDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("test requires its exact connector")
}

type grantSQLConnection struct {
	state *grantSQLState
	admin bool
}

func (*grantSQLConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements unavailable")
}
func (*grantSQLConnection) Close() error { return nil }
func (*grantSQLConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unavailable")
}
func (c *grantSQLConnection) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !c.admin {
		return nil, errors.New("app account may not change privileges")
	}
	s := c.state
	switch {
	case strings.HasPrefix(query, "CREATE DATABASE IF NOT EXISTS "):
		s.events = append(s.events, "create-database")
	case strings.HasPrefix(query, "CREATE USER IF NOT EXISTS "):
		s.events = append(s.events, "create-user-if-missing")
		s.created = true
		if s.loseCreate {
			s.loseCreate = false
			return nil, errors.New("lost CREATE response " + s.account.Password)
		}
	case strings.HasPrefix(query, "GRANT "):
		exact, _ := applicationSQLGrant(s.account.ResourceID, s.account.Database, s.account.User)
		if query != exact {
			return nil, errors.New("wrong grant")
		}
		s.events = append(s.events, "grant-exact")
		s.grantCount++
		_, _, _, usage, grant := appGrantFixture()
		s.grants = []string{usage, grant}
		if s.loseGrant {
			s.loseGrant = false
			return nil, errors.New("lost GRANT response " + s.account.Password)
		}
	default:
		return nil, errors.New("unexpected permission mutation")
	}
	return driver.RowsAffected(0), nil
}
func (c *grantSQLConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	s := c.state
	if c.admin && query == "SELECT @@GLOBAL.partial_revokes, @@GLOBAL.mandatory_roles, @@GLOBAL.require_secure_transport" {
		s.events = append(s.events, "global-semantics")
		return &grantSQLRows{[]string{"partial_revokes", "mandatory_roles", "require_secure_transport"}, [][]driver.Value{{s.partial, s.mandatory, s.secure}}}, nil
	}
	if c.admin && query == "SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=?" {
		s.events = append(s.events, "encrypted-database")
		if len(arguments) != 1 || arguments[0].Value != s.account.Database {
			return nil, errors.New("exact database parameter missing")
		}
		if s.databaseMissing {
			return &grantSQLRows{[]string{"SCHEMA_NAME", "DEFAULT_ENCRYPTION"}, nil}, nil
		}
		return &grantSQLRows{[]string{"SCHEMA_NAME", "DEFAULT_ENCRYPTION"}, [][]driver.Value{{s.account.Database, s.databaseEncryption}}}, nil
	}
	if !c.admin && query == "SHOW SESSION STATUS LIKE 'Ssl_cipher'" {
		s.events = append(s.events, "own-tls")
		return &grantSQLRows{[]string{"Variable_name", "Value"}, [][]driver.Value{{"Ssl_cipher", s.tlsCipher}}}, nil
	}
	if !c.admin && query == "SELECT CURRENT_USER(), CURRENT_ROLE()" {
		s.events = append(s.events, "own-identity")
		return &grantSQLRows{[]string{"CURRENT_USER()", "CURRENT_ROLE()"}, [][]driver.Value{{s.current, s.roles}}}, nil
	}
	if !c.admin && query == "SHOW GRANTS" {
		s.events = append(s.events, "own-grants")
		s.reads++
		if s.loseRead && s.grantCount != 0 {
			s.loseRead = false
			return nil, errors.New("lost grant readback " + s.account.Password)
		}
		rows := make([][]driver.Value, len(s.grants))
		for i, grant := range s.grants {
			rows[i] = []driver.Value{grant}
		}
		return &grantSQLRows{[]string{"Grants"}, rows}, nil
	}
	return nil, errors.New("unexpected privilege query")
}

type grantSQLRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *grantSQLRows) Columns() []string { return r.columns }
func (*grantSQLRows) Close() error        { return nil }
func (r *grantSQLRows) Next(values []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(values, r.values[0])
	r.values = r.values[1:]
	return nil
}

func applicationSQLState() *grantSQLState {
	id, database, _, usage, _ := appGrantFixture()
	return &grantSQLState{account: applicationSQLAccount{ResourceID: id, Database: database, User: database, Password: strings.Repeat("e", 64), Version: 1}, grants: []string{usage}, current: database + "@%", roles: "NONE", secure: true, tlsCipher: "TLS_AES_256_GCM_SHA384", databaseEncryption: "YES"}
}
func executeApplicationSQLState(ctx context.Context, s *grantSQLState) error {
	admin := sql.OpenDB(grantSQLConnector{s, true})
	defer admin.Close()
	return ensureApplicationSQLGrants(ctx, admin, s.account, func() (*sql.DB, error) { return sql.OpenDB(grantSQLConnector{s, false}), nil }, func() error {
		s.saves++
		s.events = append(s.events, "persist-verified")
		if s.loseSave {
			s.loseSave = false
			return errors.New("state write interrupted " + s.account.Password)
		}
		s.account.Version = 1
		s.account.Verified = true
		return nil
	})
}
func noApplicationSQLMutation(t *testing.T, s *grantSQLState) {
	t.Helper()
	for _, event := range s.events {
		if strings.HasPrefix(event, "create-") || event == "grant-exact" || event == "persist-verified" {
			t.Fatal("existing permission baseline was mutated")
		}
	}
}
func TestApplicationGrantNativeSQLBoundaryInitializesOnlyAfterAuthenticatedAudit(t *testing.T) {
	s := applicationSQLState()
	if e := executeApplicationSQLState(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	expected := "global-semantics,create-database,create-user-if-missing,encrypted-database,own-tls,own-identity,own-grants,grant-exact,own-tls,own-identity,own-grants,persist-verified"
	if strings.Join(s.events, ",") != expected || s.grantCount != 1 || !s.account.Verified {
		t.Fatal("grant was not authenticated and independently verified in order")
	}
}
func TestApplicationGrantDatabaseLegacyAndVerifiedRightsRemainUnchanged(t *testing.T) {
	for _, mode := range []string{"legacy-wildcard", "legacy-usage-only", "verified-usage-only", "verified-subset", "verified-global", "verified-role"} {
		t.Run(mode, func(t *testing.T) {
			s := applicationSQLState()
			_, database, account, usage, exact := appGrantFixture()
			s.account.Version = 0
			switch mode {
			case "legacy-wildcard":
				s.grants = []string{usage, "GRANT SELECT, INSERT, UPDATE ON `" + database + "`.* TO " + account}
			case "legacy-usage-only":
			default:
				s.account.Version = 1
				s.account.Verified = true
				if mode == "verified-subset" {
					s.grants = []string{usage, strings.Replace(exact, "SELECT, INSERT, UPDATE", "SELECT", 1)}
				}
				if mode == "verified-global" {
					s.grants = []string{usage, "GRANT SELECT ON *.* TO " + account}
				}
				if mode == "verified-role" {
					s.grants = []string{usage, "GRANT `role`@`%` TO " + account}
				}
			}
			if e := executeApplicationSQLState(context.Background(), s); e == nil {
				t.Fatal("unreviewed existing privileges passed")
			}
			noApplicationSQLMutation(t, s)
		})
	}
}
func TestApplicationGrantRecoversLostCreationGrantReadbackAndPersistenceResponses(t *testing.T) {
	for _, mode := range []string{"create", "grant", "readback", "persist"} {
		t.Run(mode, func(t *testing.T) {
			s := applicationSQLState()
			s.loseCreate = mode == "create"
			s.loseGrant = mode == "grant"
			s.loseRead = mode == "readback"
			s.loseSave = mode == "persist"
			e := executeApplicationSQLState(context.Background(), s)
			if e == nil || strings.Contains(e.Error(), s.account.Password) {
				t.Fatal("uncertain result or credential redaction failed")
			}
			if e = executeApplicationSQLState(context.Background(), s); e != nil || s.grantCount != 1 || !s.account.Verified {
				t.Fatal("retry did not reconcile exact account without duplicate grant", e)
			}
			grantBefore := s.grantCount
			if e = executeApplicationSQLState(context.Background(), s); e != nil || s.grantCount != grantBefore {
				t.Fatal("verified account was regranted", e)
			}
		})
	}
}
func TestApplicationGrantRejectsGlobalSemanticsIdentityAndRolesWithoutMutation(t *testing.T) {
	for _, mode := range []string{"partial-revokes", "mandatory-role", "wrong-current-user", "active-role", "unsecured-server", "unsecured-session"} {
		t.Run(mode, func(t *testing.T) {
			s := applicationSQLState()
			_, _, _, usage, exact := appGrantFixture()
			s.account.Verified = true
			s.grants = []string{usage, exact}
			s.partial = mode == "partial-revokes"
			if mode == "unsecured-server" {
				s.secure = false
			}
			if mode == "unsecured-session" {
				s.tlsCipher = ""
			}
			if mode == "mandatory-role" {
				s.mandatory = "`role`@`%`"
			}
			if mode == "wrong-current-user" {
				s.current = "other@%"
			}
			if mode == "active-role" {
				s.roles = "`role`@`%`"
			}
			if e := executeApplicationSQLState(context.Background(), s); e == nil {
				t.Fatal("unqualified privilege semantics passed")
			}
			noApplicationSQLMutation(t, s)
		})
	}
}
func TestApplicationGrantRejectsMalformedResourceAndCancellationBeforeAnySQL(t *testing.T) {
	s := applicationSQLState()
	s.account.Database = "appX" + s.account.Database[4:]
	if e := executeApplicationSQLState(context.Background(), s); e == nil || len(s.events) != 0 {
		t.Fatal("malformed stored scope reached SQL")
	}
	s = applicationSQLState()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := executeApplicationSQLState(ctx, s); e == nil || len(s.events) != 0 {
		t.Fatal("cancelled initialization reached SQL")
	}
}
func TestApplicationGrantExistingLiteralAccountAdoptsEvidenceWithoutPermissionMutation(t *testing.T) {
	s := applicationSQLState()
	s.account.Version = 0
	_, _, _, usage, exact := appGrantFixture()
	s.grants = []string{usage, exact}
	if e := executeApplicationSQLState(context.Background(), s); e != nil || s.grantCount != 0 || !s.account.Verified {
		t.Fatal("exact privileges could not adopt evidence without regrant", e)
	}
	if strings.Join(s.events, ",") != "global-semantics,encrypted-database,own-tls,own-identity,own-grants,persist-verified" {
		t.Fatal("existing account was changed during adoption")
	}
}

func TestApplicationGrantMissingOrUnencryptedDatabaseNeverReceivesPrivilegesOrAdoption(t *testing.T) {
	for _, pending := range []bool{true, false} {
		for _, evidence := range []string{"missing", "N", "NO", "", "unknown"} {
			t.Run(evidence, func(t *testing.T) {
				s := applicationSQLState()
				s.databaseMissing = evidence == "missing"
				s.databaseEncryption = evidence
				if !pending {
					s.account.Version = 0
					_, _, _, usage, exact := appGrantFixture()
					s.grants = []string{usage, exact}
				}
				if e := executeApplicationSQLState(context.Background(), s); e == nil || s.grantCount != 0 || s.saves != 0 {
					t.Fatal("missing/unencrypted database acquired grant or verified metadata")
				}
				if !pending {
					noApplicationSQLMutation(t, s)
				}
			})
		}
	}
}
