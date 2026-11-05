package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Recorded before deployment begins. Reconciliation may retire this original
// runtime only; a replacement at its name is never an authorized target.
type retirementBinding struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	ReleaseID   string `json:"releaseId"`
	Hash        string `json:"artifactHash"`
	OperationID string `json:"operationId"`
}

// Called with the shared application lock, after independently verifying the
// candidate's current route and health. Completion also requires retirement of
// the exact previous runtime, even after an interrupted deployment request.
func (s *server) retirePreviousRuntime(_ context.Context, receipt deployReceipt, active activeDeployment) error {
	unavailable := errors.New("Previous runtime retirement is unconfirmed; publication remains pending")
	previous, binding := active.Previous, receipt.PreviousRuntime
	if previous == nil {
		if binding != nil {
			return unavailable
		}
		return nil
	}
	if binding == nil || !identity.MatchString(receipt.AppID) || !exactDockerID.MatchString(binding.ID) || !identity.MatchString(binding.Name) || !strings.HasPrefix(binding.Name, "as-app-"+receipt.AppID+"-") || !digestImage.MatchString(binding.Image) || binding.Name == active.Container || binding.ID == "" || binding.Name != previous.Container || binding.Image != previous.Image || binding.ReleaseID != previous.ReleaseID || binding.Hash != previous.Hash || binding.OperationID != previous.OperationID {
		return unavailable
	}
	request := observationRequest{ID: "runtime-retirement", AppID: receipt.AppID, ReleaseID: binding.ReleaseID, Hash: binding.Hash, Images: []string{binding.Image}, OperationID: binding.OperationID}
	publication, verified, manifest, err := s.publicationReceipt(request)
	if err != nil || previous.URL != "https://"+manifest.Slug+"."+s.appsHost() || previous.Schema < 1 || publication.Schema != previous.Schema || previous.Schema < verified.SchemaMin || previous.Schema > verified.SchemaMax {
		return unavailable
	}
	// The original operation already authorizes this bounded cleanup. Client
	// cancellation must not leave an unretired competing runtime behind.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := s.exactAppContainerID(ctx, binding.Name)
	if err != nil || id != binding.ID {
		return unavailable
	}
	owned, err := s.inspectTLSContainer(ctx, binding.Name, receipt.AppID, receipt.AppID, binding.Image)
	if err != nil || owned.ID != binding.ID {
		return unavailable
	}
	unchanged := func() bool {
		var current activeDeployment
		return readBoundedJSON(filepath.Join(s.data, "active", receipt.AppID+".json"), &current) == nil && reflect.DeepEqual(current, active)
	}
	if !unchanged() {
		return unavailable
	}
	if err = s.stopRuntimeCandidate(binding.Name, receipt.AppID, receipt.AppID, binding.Image, binding.ID); err != nil {
		return unavailable
	}
	if !unchanged() {
		return unavailable
	}
	return nil
}
