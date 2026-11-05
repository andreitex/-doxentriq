package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

// A durable negative receipt closes the race between absence checking and late dispatch.
func (s *server) cancelOperation(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		fail(w, 400, err)
		return
	}
	if !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		fail(w, 403, errors.New("Exact cancellation proof required"))
		return
	}
	var in struct {
		OperationID string `json:"operationId"`
		AppID       string `json:"appId"`
		ReleaseID   string `json:"releaseId"`
		ApprovalID  string `json:"approvalId"`
		Hash        string `json:"artifactHash"`
	}
	if json.Unmarshal(body, &in) != nil || !identity.MatchString(in.OperationID) || !identity.MatchString(in.AppID) || !identity.MatchString(in.ReleaseID) || !identity.MatchString(in.ApprovalID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.Hash) {
		fail(w, 400, errors.New("Invalid cancellation identity"))
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	file := filepath.Join(s.data, "operations", in.OperationID+".json")
	var receipt deployReceipt
	existing, err := os.ReadFile(file)
	if err == nil {
		if json.Unmarshal(existing, &receipt) != nil || receipt.AppID != in.AppID || receipt.ReleaseID != in.ReleaseID || receipt.Hash != in.Hash || receipt.ApprovalID != in.ApprovalID {
			fail(w, 409, errors.New("Cancellation identity conflicts with existing operation"))
			return
		}
		status := "running"
		if receipt.Phase == "failed" {
			status = "failed"
		}
		respond(w, map[string]any{"status": status, "appId": in.AppID, "releaseId": in.ReleaseID})
		return
	}
	if !os.IsNotExist(err) {
		fail(w, 500, err)
		return
	}
	receipt = deployReceipt{OperationID: in.OperationID, AppID: in.AppID, ReleaseID: in.ReleaseID, ApprovalID: in.ApprovalID, Hash: in.Hash, Phase: "failed"}
	if err = atomicJSON(file, receipt); err != nil {
		fail(w, 500, err)
		return
	}
	respond(w, map[string]any{"status": "failed", "appId": in.AppID, "releaseId": in.ReleaseID})
}
