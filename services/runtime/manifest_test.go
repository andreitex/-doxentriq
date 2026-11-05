package main

import "testing"

func TestHostedMCPRequiresAuthentication(t *testing.T) {
	m := AppManifest{Version: 1, ID: "app1", Slug: "documents", Kind: "mcp", Template: "node-mcp", Auth: "public"}
	m.Resources.CPU = 1
	m.Resources.Memory = 128
	m.Resources.Pids = 32
	m.Health.Path = "/healthz"
	m.Health.Port = 8080
	if err := validateApp(m, m.ID, m.Template); err == nil {
		t.Fatal("Public hosted MCP passed the independent broker policy")
	}
	for _, auth := range []string{"sso", "local"} {
		m.Auth = auth
		if err := validateApp(m, m.ID, m.Template); err != nil {
			t.Fatalf("Authenticated MCP %s rejected: %v", auth, err)
		}
	}
	m.Auth, m.Kind = "public", "api"
	if err := validateApp(m, m.ID, m.Template); err == nil {
		t.Fatal("Public MCP template bypassed the policy through another app kind")
	}
	m.Kind, m.Template = "mcp", "python-api"
	if err := validateApp(m, m.ID, m.Template); err == nil {
		t.Fatal("Public Python MCP bypassed the policy through another template")
	}
	m.Kind, m.Template = "web", "node-web"
	if err := validateApp(m, m.ID, m.Template); err != nil {
		t.Fatalf("Explicit public web application rejected: %v", err)
	}
}
