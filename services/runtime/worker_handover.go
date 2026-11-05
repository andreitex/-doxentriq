package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"
)

type pinnedRuntime struct {
	ID, Name, Image string
	Manifest        AppManifest
	WasRunning      bool
}

func (s *server) pinPublishedRuntime(ctx context.Context, appID string, current *activeDeployment) (*pinnedRuntime, error) {
	if current == nil || !identity.MatchString(current.Container) || !digestImage.MatchString(current.Image) {
		return nil, errors.New("Previous published runtime identity is invalid")
	}
	request := observationRequest{ID: "worker-handover", AppID: appID, ReleaseID: current.ReleaseID, Hash: current.Hash, Images: []string{current.Image}, OperationID: current.OperationID}
	_, verified, manifest, err := s.publicationReceipt(request)
	if err != nil || current.URL != "https://"+manifest.Slug+"."+s.appsHost() || current.Schema < verified.SchemaMin || current.Schema > verified.SchemaMax {
		return nil, errors.New("Previous immutable publication/source evidence is unavailable")
	}
	id, err := s.exactAppContainerID(ctx, current.Container)
	if err != nil || id == "" {
		return nil, errors.New("Previous exact runtime discovery is unavailable")
	}
	owned, err := s.inspectTLSContainer(ctx, current.Container, appID, appID, current.Image)
	if err != nil || owned.ID != id {
		return nil, errors.New("Previous runtime ownership changed")
	}
	matched, err := s.routeMatches(ctx, appID, manifest.Slug+"."+s.appsHost(), current.Container)
	if err != nil || !matched {
		return nil, errors.New("Previous runtime route cannot be independently confirmed")
	}
	return &pinnedRuntime{ID: id, Name: current.Container, Image: current.Image, Manifest: manifest, WasRunning: owned.State.Running}, nil
}

// This is fallback within the original authorized operation, not a new rollback.
// The caller has already confirmed candidate shutdown. Lost/canceled routing
// responses require an actual route read and confirmed restoration, not guesses.
func (s *server) restorePinnedRuntime(appID string, current *activeDeployment, previous *pinnedRuntime, candidate string, routingAttempted bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	unavailable := errors.New("Previous runtime/route restoration is unconfirmed; publication remains pending and requires company reconciliation")
	if current == nil || previous == nil || previous.Name != current.Container || previous.Image != current.Image || !exactDockerID.MatchString(previous.ID) {
		return unavailable
	}
	var live activeDeployment
	if readBoundedJSON(filepath.Join(s.data, "active", appID+".json"), &live) != nil || !reflect.DeepEqual(live, *current) {
		return unavailable
	}
	id, err := s.exactAppContainerID(ctx, previous.Name)
	owned, inspectErr := s.inspectTLSContainer(ctx, previous.Name, appID, appID, previous.Image)
	if err != nil || inspectErr != nil || id != previous.ID || owned.ID != previous.ID {
		return unavailable
	}
	host := previous.Manifest.Slug + "." + s.appsHost()
	matched, err := s.routeMatches(ctx, appID, host, previous.Name)
	if err != nil {
		return unavailable
	}
	if !matched {
		if !routingAttempted {
			return unavailable
		}
		candidateMatched, routeErr := s.routeMatches(ctx, appID, host, candidate)
		if routeErr != nil || !candidateMatched {
			return unavailable
		}
	}
	if previous.WasRunning {
		if _, err = s.runner(ctx, "docker", "start", previous.ID); err != nil {
			return unavailable
		}
		if err = s.healthy(ctx, previous.ID, previous.Manifest); err != nil {
			return unavailable
		}
	}
	if matched {
		return nil
	}
	if err = s.route(ctx, appID, host, previous.Name, 8080, false); err != nil {
		return unavailable
	}
	matched, err = s.routeMatches(ctx, appID, host, previous.Name)
	if err != nil || !matched {
		return unavailable
	}
	return nil
}
