package main

import (
	"errors"
	"os"
)

// An approval may select one fixed company adapter only. Ambiguous retained
// state is blocked before starting, scanning or retiring either service.
func (s *server) filesystemConnection(appID, id string) (bool, error) {
	filesystem, err := s.filesystemConnectorExists(appID, id)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(s.connectorStatePath(appID, id))
	if err != nil && !os.IsNotExist(err) {
		return false, errors.New("Connector approval provenance is unavailable")
	}
	if err == nil && (!info.Mode().IsRegular() || filesystem) {
		return false, errors.New("Connector type is ambiguous or retained approval is unsafe")
	}
	return filesystem, nil
}
