package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
)

// Only called after ownership of the app realm has been independently checked.
// Invitation ownership attributes must survive administrative writes, while
// end users must never be able to set those attributes themselves.
func ensureAppUserProfile(ctx context.Context, client *http.Client, base, token, realm string) error {
	endpoint := base + "/admin/realms/" + url.PathEscape(realm) + "/users/profile"
	var profile map[string]any
	if _, err := identityGET(ctx, client, endpoint, token, &profile, false); err != nil {
		return err
	}
	policy, present := profile["unmanagedAttributePolicy"]
	if policy == "ADMIN_EDIT" {
		return nil
	}
	if present && policy != nil && policy != "DISABLED" {
		return errors.New("App account metadata policy requires a separate company review")
	}
	attributes, valid := profile["attributes"].([]any)
	if !valid || len(attributes) == 0 || len(attributes) > 100 {
		return errors.New("App user profile metadata is unavailable")
	}
	profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"
	body, err := json.Marshal(profile)
	if err != nil || len(body) > 1<<20 {
		return errors.New("App user profile exceeds its bounded contract")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("App ownership metadata setup awaits company confirmation")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return errors.New("App ownership metadata setup was refused")
	}
	var after map[string]any
	if _, err = identityGET(ctx, client, endpoint, token, &after, false); err != nil || after["unmanagedAttributePolicy"] != "ADMIN_EDIT" || !reflect.DeepEqual(after["attributes"], attributes) {
		return errors.New("Administrator-only app metadata setup could not be verified")
	}
	return nil
}
