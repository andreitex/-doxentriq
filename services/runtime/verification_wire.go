package main

import "encoding/json"

// Failed verification can precede packaging and preview creation. Preserve its
// real checks in the API protocol using empty arrays and a null preview URL,
// while keeping the internal resource/replay representation unchanged.
func (v Verification) MarshalJSON() ([]byte, error) {
	type wire Verification
	value := wire(v)
	if value.Evidence.Findings == nil {
		value.Evidence.Findings = []Finding{}
	}
	if value.Evidence.Checks == nil {
		value.Evidence.Checks = []Check{}
	}
	if value.Images == nil {
		value.Images = []string{}
	}
	if value.Migrations == nil {
		value.Migrations = []Migration{}
	}
	var preview *string
	if v.PreviewURL != "" {
		preview = &v.PreviewURL
	}
	return json.Marshal(struct {
		*wire
		PreviewURL *string `json:"previewUrl"`
	}{&value, preview})
}
