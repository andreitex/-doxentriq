package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type observationRequest struct {
	ID          string   `json:"observationId"`
	AppID       string   `json:"appId"`
	ReleaseID   string   `json:"releaseId"`
	Hash        string   `json:"artifactHash"`
	Images      []string `json:"images"`
	OperationID string   `json:"publicationOperationId"`
}
type releaseObservation struct {
	observationRequest
	CheckedAt    string `json:"checkedAt"`
	Status       string `json:"status"`
	Detail       string `json:"detail"`
	EvidenceHash string `json:"evidenceHash"`
}

func validObservation(in observationRequest) bool {
	return identity.MatchString(in.ID) && identity.MatchString(in.AppID) && identity.MatchString(in.ReleaseID) && identity.MatchString(in.OperationID) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.Hash) && len(in.Images) == 1 && digestImage.MatchString(in.Images[0])
}

func readBoundedJSON(file string, value any) error {
	info, err := os.Lstat(file)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return errors.New("Trusted state is not a bounded regular file")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

func (s *server) publicationReceipt(in observationRequest) (deployReceipt, Verification, AppManifest, error) {
	var receipt deployReceipt
	var verified Verification
	var manifest AppManifest
	if !validObservation(in) {
		return receipt, verified, manifest, errors.New("Exact immutable observation identity required")
	}
	if err := readBoundedJSON(filepath.Join(s.data, "operations", in.OperationID+".json"), &receipt); err != nil {
		return receipt, verified, manifest, err
	}
	if receipt.Phase != "completed" || receipt.AppID != in.AppID || receipt.ReleaseID != in.ReleaseID || receipt.Hash != in.Hash || !identity.MatchString(receipt.AttemptID) {
		return receipt, verified, manifest, errors.New("Completed exact publication receipt unavailable")
	}
	if err := readBoundedJSON(filepath.Join(s.data, "receipts", receipt.AttemptID+".json"), &verified); err != nil {
		return receipt, verified, manifest, err
	}
	if verified.AppID != in.AppID || !reflect.DeepEqual(verified.Images, in.Images) || verified.Evidence.Status != "passed" || verified.AttemptID != receipt.AttemptID {
		return receipt, verified, manifest, errors.New("Publication verification does not match the immutable observation target")
	}
	source, err := safePath(filepath.Join(s.data, "sources"), verified.AttemptID)
	if err != nil {
		return receipt, verified, manifest, err
	}
	if err = readBoundedJSON(filepath.Join(source, "app.manifest.json"), &manifest); err != nil {
		return receipt, verified, manifest, err
	}
	if validateApp(manifest, in.AppID, verified.Template) != nil {
		return receipt, verified, manifest, errors.New("Protected published manifest is invalid")
	}
	digest, err := sourceDigest(source)
	if err != nil || digest != verified.SourceHash {
		return receipt, verified, manifest, errors.New("Protected source changed after verification")
	}
	return receipt, verified, manifest, nil
}

// Match the actual restricted router, rather than assuming the active-state file proves routing.
func (s *server) routeMatches(ctx context.Context, appID, host, container string) (bool, error) {
	if !identity.MatchString(appID) || !identity.MatchString(container) || !regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(host) {
		return false, errors.New("Invalid observation route identity")
	}
	if s.routeProbe != nil {
		return s.routeProbe(ctx, appID, host, container)
	}
	client := caddyClient(env("CADDY_ADMIN_SOCKET_FILE", "/run/caddy/admin.sock"))
	endpoint := "http://localhost/config/apps/http/servers/" + env("CADDY_SERVER_NAME", "apps") + "/routes"
	request, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	response, err := client.Do(request)
	if err != nil {
		return false, errors.New("Restricted router observation unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return false, errors.New("Restricted router state unavailable")
	}
	var routes []struct {
		ID    string `json:"@id"`
		Match []struct {
			Hosts []string `json:"host"`
		} `json:"match"`
		Handle []struct {
			Handler   string `json:"handler"`
			Upstreams []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
		} `json:"handle"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&routes) != nil {
		return false, errors.New("Restricted router returned invalid evidence")
	}
	for _, route := range routes {
		if route.ID != "autosoft-app-"+appID {
			continue
		}
		if len(route.Match) != 1 || len(route.Match[0].Hosts) != 1 || route.Match[0].Hosts[0] != host {
			return false, nil
		}
		for _, handler := range route.Handle {
			if handler.Handler == "reverse_proxy" && len(handler.Upstreams) == 1 && handler.Upstreams[0].Dial == container+":8080" {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

func (s *server) healthObservation(ctx context.Context, container tlsContainer, manifest AppManifest) (string, string) {
	if !container.State.Running {
		return "unhealthy", "The exact published application container is stopped."
	}
	target := "https://127.0.0.1:8080" + manifest.Health.Path
	var command []string
	if manifest.Template == "python-api" {
		command = []string{"python", "-c", "import urllib.request\ntry:\n r=urllib.request.urlopen(" + strconv.Quote(target) + ",timeout=5); print('AUTOSOFT_HEALTHY' if r.status==200 else 'AUTOSOFT_UNHEALTHY')\nexcept Exception:\n print('AUTOSOFT_UNHEALTHY')"}
	} else {
		command = []string{"node", "--input-type=module", "-e", "try{const r=await fetch(" + strconv.Quote(target) + ",{signal:AbortSignal.timeout(5000)});console.log(r.status===200?'AUTOSOFT_HEALTHY':'AUTOSOFT_UNHEALTHY')}catch{console.log('AUTOSOFT_UNHEALTHY')}"}
	}
	output, err := s.runner(ctx, "docker", append([]string{"exec", container.ID}, command...)...)
	if err != nil {
		return "unavailable", "The runtime could not execute the bounded health probe; no application failure is inferred."
	}
	switch strings.TrimSpace(output) {
	case "AUTOSOFT_HEALTHY":
		return "healthy", "The exact routed release returned HTTPS health status200."
	case "AUTOSOFT_UNHEALTHY":
		return "unhealthy", "The exact routed release failed its bounded HTTPS health probe."
	default:
		return "unavailable", "The health probe did not return recognizable evidence."
	}
}

func (s *server) observeRelease(w http.ResponseWriter, r *http.Request) {
	var in observationRequest
	if !decode(w, r, &in) {
		return
	}
	if !validObservation(in) {
		fail(w, 400, errors.New("Invalid exact observation identity"))
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	file := filepath.Join(s.data, "observations", in.ID+".json")
	var prior releaseObservation
	if err := readBoundedJSON(file, &prior); err == nil {
		if !reflect.DeepEqual(prior.observationRequest, in) {
			fail(w, 409, errors.New("Observation identity conflict"))
			return
		}
		respond(w, prior)
		return
	} else if !os.IsNotExist(err) {
		fail(w, 500, errors.New("Observation receipt cannot be read"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result := releaseObservation{observationRequest: in, Status: "unavailable", Detail: "Published release evidence is unavailable."}
	_, _, manifest, err := s.publicationReceipt(in)
	var active activeDeployment
	if err == nil {
		err = readBoundedJSON(filepath.Join(s.data, "active", in.AppID+".json"), &active)
	}
	if err == nil && (active.ReleaseID != in.ReleaseID || active.Hash != in.Hash || active.OperationID != in.OperationID || active.Image != in.Images[0]) {
		result.Status = "superseded"
		result.Detail = "A different immutable release is now active; the earlier release is not probed."
	} else if err == nil {
		matched, routeErr := s.routeMatches(ctx, in.AppID, manifest.Slug+"."+s.appsHost(), active.Container)
		if routeErr != nil {
			result.Detail = "Restricted router observation is unavailable."
		} else if !matched {
			result.Detail = "Actual routing does not match the recorded release; company reconciliation is required."
		} else {
			container, inspectErr := s.inspectTLSContainer(ctx, active.Container, in.AppID, in.AppID, active.Image)
			if inspectErr == nil {
				result.Status, result.Detail = s.healthObservation(ctx, container, manifest)
			} else {
				result.Detail = "The exact managed container and immutable image could not be independently verified."
			}
		}
	}
	result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(result)
	result.EvidenceHash = hashBytes(b)
	if err = atomicJSON(file, result); err != nil {
		fail(w, 500, err)
		return
	}
	respond(w, result)
}

func (s *server) publicCatalog(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IncludeProtected bool `json:"includeProtected"`
	}
	if !decode(w, r, &input) {
		return
	}
	type card struct {
		AppID     string   `json:"appId"`
		ReleaseID string   `json:"releaseId"`
		Hash      string   `json:"artifactHash"`
		Images    []string `json:"images"`
		Auth      string   `json:"auth"`
	}
	cards := []card{}
	entries, err := os.ReadDir(filepath.Join(s.data, "active"))
	if os.IsNotExist(err) {
		respond(w, map[string]any{"apps": cards})
		return
	}
	if err != nil || len(entries) > 1000 {
		fail(w, 503, errors.New("Bounded published catalog unavailable"))
		return
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !identity.MatchString(id) {
			continue
		}
		unlock := s.lock("app-" + id)
		var active activeDeployment
		if readBoundedJSON(filepath.Join(s.data, "active", entry.Name()), &active) == nil {
			in := observationRequest{ID: "catalog", AppID: id, ReleaseID: active.ReleaseID, Hash: active.Hash, Images: []string{active.Image}, OperationID: active.OperationID}
			_, _, manifest, verifyErr := s.publicationReceipt(in)
			if verifyErr == nil && (manifest.Auth == "public" || input.IncludeProtected && (manifest.Auth == "local" || manifest.Auth == "sso")) && active.URL == "https://"+manifest.Slug+"."+s.appsHost() {
				cards = append(cards, card{id, active.ReleaseID, active.Hash, in.Images, manifest.Auth})
			}
		}
		unlock()
	}
	respond(w, map[string]any{"apps": cards})
}

// Called only with the shared application lock. A healthy historical version does
// not prove that this exact pending operation changed the actual public route.
func (s *server) reconcileHealthyOperation(ctx context.Context, receipt deployReceipt) (activeDeployment, bool) {
	var active activeDeployment
	var verified Verification
	var manifest AppManifest
	if !identity.MatchString(receipt.AttemptID) || !identity.MatchString(receipt.ReleaseID) || readBoundedJSON(filepath.Join(s.data, "active", receipt.AppID+".json"), &active) != nil || active.ReleaseID != receipt.ReleaseID || active.Hash != receipt.Hash || active.OperationID != receipt.OperationID || active.Schema < 1 || !digestImage.MatchString(active.Image) {
		return active, false
	}
	if readBoundedJSON(filepath.Join(s.data, "receipts", receipt.AttemptID+".json"), &verified) != nil || verified.AppID != receipt.AppID || verified.AttemptID != receipt.AttemptID || verified.Evidence.Status != "passed" || !reflect.DeepEqual(verified.Images, []string{active.Image}) || active.Schema < verified.SchemaMin || active.Schema > verified.SchemaMax {
		return active, false
	}
	source, err := safePath(filepath.Join(s.data, "sources"), verified.AttemptID)
	if err != nil || readBoundedJSON(filepath.Join(source, "app.manifest.json"), &manifest) != nil || validateApp(manifest, receipt.AppID, verified.Template) != nil || active.URL != "https://"+manifest.Slug+"."+s.appsHost() {
		return active, false
	}
	digest, err := sourceDigest(source)
	if err != nil || digest != verified.SourceHash {
		return active, false
	}
	probeContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	matched, err := s.routeMatches(probeContext, receipt.AppID, manifest.Slug+"."+s.appsHost(), active.Container)
	if err != nil || !matched {
		return active, false
	}
	container, err := s.inspectTLSContainer(probeContext, active.Container, receipt.AppID, receipt.AppID, active.Image)
	if err != nil {
		return active, false
	}
	status, _ := s.healthObservation(probeContext, container, manifest)
	if status != "healthy" || s.retirePreviousRuntime(ctx, receipt, active) != nil || s.retireAppConnectors(ctx, receipt.AppID, receipt.AppID, active.Container) != nil {
		return active, false
	}
	return active, true
}
