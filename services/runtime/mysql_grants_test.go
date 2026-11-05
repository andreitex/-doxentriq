package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func appGrantFixture() (string, string, string, string, string) {
	id := "grant-fixture-preview"
	digest := sha256.Sum256([]byte(id))
	database := "app_" + hex.EncodeToString(digest[:])[:24]
	account := "`" + database + "`@`%`"
	usage := "GRANT USAGE ON *.* TO " + account
	exact := "GRANT SELECT, INSERT, UPDATE ON `app\\_" + database[4:] + "`.* TO " + account
	return id, database, account, usage, exact
}

func TestApplicationGrantEscapesOnlyDatabasePrivilegeScope(t *testing.T) {
	id, database, _, _, _ := appGrantFixture()
	statement, e := applicationSQLGrant(id, database, database)
	if e != nil || statement != "GRANT SELECT, INSERT, UPDATE ON `app\\_"+database[4:]+"`.* TO '"+database+"'@'%'" {
		t.Fatalf("exact database grant missing: %s, %v", statement, e)
	}
	if strings.Count(statement, `\_`) != 1 || strings.Contains(statement, "WITH GRANT OPTION") {
		t.Fatal("database privilege escape or account authority changed")
	}
}

func TestApplicationGrantRejectsWrongResourceDatabaseUserAndSQLSyntax(t *testing.T) {
	id, database, _, _, _ := appGrantFixture()
	for _, values := range [][3]string{{id, "appX" + database[4:], database}, {id, database, "other-user"}, {"another-resource", database, database}, {id, "app_" + strings.Repeat("a", 24), database}, {"../scope", database, database}, {id, "app_%", database}, {id, database + "`.*; GRANT ALL", database}} {
		if _, e := applicationSQLGrant(values[0], values[1], values[2]); e == nil {
			t.Fatalf("wrong scope accepted: %v", values)
		}
	}
}

func TestApplicationGrantAuditRejectsRetainedLegacyEvenAlongsideLiteralGrant(t *testing.T) {
	id, database, account, usage, exact := appGrantFixture()
	legacy := "GRANT SELECT, INSERT, UPDATE ON `" + database + "`.* TO " + account
	for _, rows := range [][]string{{usage, legacy}, {usage, exact, legacy}, {usage, legacy, exact}} {
		if _, e := inspectApplicationSQLGrants(id, database, database, rows); e == nil || !strings.Contains(e.Error(), "Legacy database wildcard") {
			t.Fatalf("retained wildcard passed: %v, %v", rows, e)
		}
	}
}

func TestApplicationGrantAuditRejectsBroaderRolesWrongPrivilegesAndMalformedEvidence(t *testing.T) {
	id, database, account, usage, exact := appGrantFixture()
	for name, row := range map[string]string{
		"global":         "GRANT SELECT, INSERT, UPDATE ON *.* TO " + account,
		"extra-delete":   strings.Replace(exact, "SELECT, INSERT, UPDATE", "SELECT, INSERT, UPDATE, DELETE", 1),
		"subset":         strings.Replace(exact, "SELECT, INSERT, UPDATE", "SELECT", 1),
		"duplicate":      strings.Replace(exact, "SELECT, INSERT, UPDATE", "SELECT, SELECT, UPDATE", 1),
		"role":           "GRANT `external-role`@`%` TO " + account,
		"grant-option":   exact + " WITH GRANT OPTION",
		"wrong-account":  strings.Replace(exact, account, "`other-user`@`%`", 1),
		"wrong-database": strings.Replace(exact, database[4:], strings.Repeat("f", 24), 1),
		"partial-revoke": "REVOKE SELECT ON `" + database + "`.* FROM " + account,
		"control":        exact + "\n",
		"oversized":      strings.Repeat("x", 16385),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := inspectApplicationSQLGrants(id, database, database, []string{usage, row}); e == nil {
				t.Fatal("unreviewed or malformed application privileges accepted")
			}
		})
	}
	for _, rows := range [][]string{nil, {usage, exact, exact}, {usage, usage}, make([]string, 17)} {
		if _, e := inspectApplicationSQLGrants(id, database, database, rows); e == nil {
			t.Fatal("missing or duplicate privilege evidence accepted")
		}
	}
}

func TestApplicationGrantInitializationRecoversOnlyBoundPendingV1Usage(t *testing.T) {
	id, database, _, usage, exact := appGrantFixture()
	if needed, e := applicationSQLGrantNeeded(id, database, database, 1, false, []string{usage}); e != nil || !needed {
		t.Fatal("new pending initial grant cannot resume")
	}
	for _, metadata := range []struct {
		version  int
		verified bool
	}{{0, false}, {0, true}, {1, true}, {2, false}} {
		if _, e := applicationSQLGrantNeeded(id, database, database, metadata.version, metadata.verified, []string{usage}); e == nil {
			t.Fatalf("legacy/verified account rights silently expanded: %+v", metadata)
		}
	}
	for _, metadata := range []struct {
		version  int
		verified bool
	}{{0, false}, {1, false}, {1, true}} {
		if needed, e := applicationSQLGrantNeeded(id, database, database, metadata.version, metadata.verified, []string{usage, exact}); e != nil || needed {
			t.Fatalf("literal privileges require mutation: %+v, %v", metadata, e)
		}
	}
}

func TestApplicationGrantAuditAcceptsCanonicalEquivalentPrivilegeOrder(t *testing.T) {
	id, database, _, usage, exact := appGrantFixture()
	for _, row := range []string{exact, strings.Replace(exact, "SELECT, INSERT, UPDATE", "UPDATE, SELECT, INSERT", 1), strings.Replace(exact, "`"+database+"`@`%`", "'"+database+"'@'%'", 1)} {
		if present, e := inspectApplicationSQLGrants(id, database, database, []string{usage, row}); e != nil || !present {
			t.Fatal("valid exact grant rejected", e)
		}
	}
}
