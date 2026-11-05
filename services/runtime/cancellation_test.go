package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func proofFor(key, body []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
func TestCancellationTombstoneRejectsLateDeploymentAndDoesNotCancelStartedWork(t *testing.T) {
	calls := 0
	key := bytes.Repeat([]byte{4}, 32)
	s := server{data: t.TempDir(), approvalKey: key, runner: func(context.Context, string, ...string) (string, error) {
		calls++
		return "", errors.New("must not execute")
	}}
	in, _ := goodDeployment()
	in.OperationID = "operation1"
	in.Release.ID = "release0001"
	in.Approval.ReleaseID = in.Release.ID
	in.Release.Hash = strings.Repeat("a", 64)
	in.Approval.Hash = in.Release.Hash
	cancel := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"operationId": in.OperationID, "appId": in.App.ID, "releaseId": in.Release.ID, "approvalId": in.Approval.ID, "artifactHash": in.Release.Hash})
		request := httptest.NewRequest("POST", "/v1/cancel-operation", bytes.NewReader(body))
		request.Header.Set("X-Autosoft-Proof", proofFor(key, body))
		response := httptest.NewRecorder()
		s.cancelOperation(response, request)
		return response
	}
	response := cancel()
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"status":"failed"`) {
		t.Fatal(response.Body.String())
	}
	body, _ := json.Marshal(in)
	request := httptest.NewRequest("POST", "/v1/deploy", bytes.NewReader(body))
	request.Header.Set("X-Autosoft-Proof", proofFor(key, body))
	response = httptest.NewRecorder()
	s.deploy(response, request)
	if response.Code != 409 || calls != 0 || !strings.Contains(response.Body.String(), `"rejectedBeforeExecution":true`) {
		t.Fatal("Late cancelled dispatch reached privileged execution", response.Body.String())
	}
	in.OperationID = "operation2"
	started := deployReceipt{OperationID: in.OperationID, AppID: in.App.ID, ReleaseID: in.Release.ID, ApprovalID: in.Approval.ID, Hash: in.Release.Hash, Phase: "started"}
	file := filepath.Join(s.data, "operations", in.OperationID+".json")
	if err := atomicJSON(file, started); err != nil {
		t.Fatal(err)
	}
	response = cancel()
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"status":"running"`) {
		t.Fatal("Started work was incorrectly cancelled", response.Body.String())
	}
	saved, _ := os.ReadFile(file)
	if !strings.Contains(string(saved), `"phase": "started"`) {
		t.Fatal("Started receipt overwritten")
	}
}
