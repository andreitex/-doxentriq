package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublicationNameCollisionPreservesActiveRuntimeAndData(t *testing.T) {
	for _, sameRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "distinct_release_same_prefix", true: "active_release_new_operation"}[sameRelease], func(t *testing.T) {
			f := newObservationFixture(t, "local")
			f.current.ReleaseID = "cafebabe-prior"
			f.current.Container = "as-app-app1-cafebabe"
			if err := atomicJSON(filepath.Join(f.server.data, "active", "app1.json"), f.current); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(f.server.data, "documents", "business-record")
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("preserved-current-record"), 0600); err != nil {
				t.Fatal(err)
			}
			in := deployment{OperationID: "new-publication", Action: "publish", Release: release{ID: "cafebabe-next", AppID: "app1", Hash: strings.Repeat("d", 64)}, Approval: approval{ID: "new-approval"}}
			in.App.ID = "app1"
			if sameRelease {
				in.Release.ID = f.current.ReleaseID
			}
			response := httptest.NewRecorder()
			f.server.executeDeployment(response, httptest.NewRequest("POST", "/v1/deploy", nil), in)
			var result struct {
				RejectedBeforeExecution bool `json:"rejectedBeforeExecution"`
			}
			if response.Code != 409 || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.RejectedBeforeExecution || f.calls != 0 {
				t.Fatalf("Collision did not reject before host actions: %d %s", response.Code, response.Body.String())
			}
			var active activeDeployment
			if readBoundedJSON(filepath.Join(f.server.data, "active", "app1.json"), &active) != nil || !reflect.DeepEqual(active, f.current) {
				t.Fatal("Collision changed the active release")
			}
			if b, err := os.ReadFile(file); err != nil || string(b) != "preserved-current-record" {
				t.Fatal("Collision changed business data")
			}
			if _, err := os.Stat(filepath.Join(f.server.data, "operations", in.OperationID+".json")); !os.IsNotExist(err) {
				t.Fatal("Collision began or consumed a publication operation")
			}
		})
	}
}
