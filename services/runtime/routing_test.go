package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoutingReplacesWithExactConcurrencyToken(t *testing.T) {
	for _, mode := range []string{"accepted", "conflict", "missing-token"} {
		t.Run(mode, func(t *testing.T) {
			directory, err := os.MkdirTemp("", "as-route-")
			if err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(directory, "admin.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				os.RemoveAll(directory)
				t.Fatal(err)
			}
			mutations := 0
			etag := `"/config/apps/http/servers/apps/routes exact-starting-version"`
			api := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/config/apps/http/servers/apps/routes" {
					t.Errorf("Unexpected route scope %s", r.URL.Path)
				}
				if r.Method == http.MethodGet {
					if mode != "missing-token" {
						w.Header().Set("ETag", etag)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`[{"@id":"platform-route","terminal":true},{"@id":"autosoft-app-preview-app","old":true}]`))
					return
				}
				mutations++
				if r.Method != http.MethodPatch || r.Header.Get("If-Match") != etag {
					t.Errorf("Route replacement must PATCH the exact starting version: method=%s token=%q", r.Method, r.Header.Get("If-Match"))
				}
				var routes []map[string]any
				if json.NewDecoder(r.Body).Decode(&routes) != nil || len(routes) != 2 || routes[0]["@id"] != "autosoft-app-preview-app" || routes[1]["@id"] != "platform-route" || routes[0]["old"] != nil {
					t.Error("Replacement must preserve foreign routes and replace only the owned route")
				}
				if mode == "conflict" {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				w.WriteHeader(http.StatusOK)
			})}
			go func() { _ = api.Serve(listener) }()
			t.Cleanup(func() { _ = api.Close(); _ = os.RemoveAll(directory) })
			t.Setenv("CADDY_ADMIN_SOCKET_FILE", socket)
			t.Setenv("CADDY_SERVER_NAME", "apps")
			s := &server{}
			err = s.route(context.Background(), "preview-app", "preview.example.test", "as-preview-app", 8080, true)
			switch mode {
			case "accepted":
				if err != nil || mutations != 1 {
					t.Fatalf("Exact route replacement failed: %v, mutations=%d", err, mutations)
				}
			case "conflict":
				if err == nil || !strings.Contains(err.Error(), "concurrently") || mutations != 1 {
					t.Fatalf("Concurrent route change was not refused: %v, mutations=%d", err, mutations)
				}
			case "missing-token":
				if err == nil || mutations != 0 {
					t.Fatalf("Missing starting-version evidence allowed mutation: %v, mutations=%d", err, mutations)
				}
			}
		})
	}
}
