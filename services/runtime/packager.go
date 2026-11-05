package main

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func layerArchive(root string) ([]byte, error) {
	var output bytes.Buffer
	tw := tar.NewWriter(&output)
	count := 0
	var total int64
	e := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() && (d.Name() == ".cache" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("Packager rejects symbolic links")
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("Packager rejects devices, FIFOs and sockets")
		}
		count++
		total += info.Size()
		if count > 100000 || total > 512<<20 {
			return errors.New("Artifact exceeds package limits")
		}
		mode := int64(0444)
		if d.IsDir() {
			mode = 0555
		}
		h := &tar.Header{Name: "app/" + filepath.ToSlash(rel), Mode: mode, Uid: 10001, Gid: 10001, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Size: info.Size()}
		if d.IsDir() {
			h.Typeflag = tar.TypeDir
			h.Size = 0
		}
		if e = tw.WriteHeader(h); e != nil {
			return e
		}
		if !d.IsDir() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			_, e = tw.Write(b)
			return e
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if e = tw.Close(); e != nil {
		return nil, e
	}
	return output.Bytes(), nil
}
func trustedTransport() (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	for _, variable := range []string{"INTERNAL_CA_FILE", "REGISTRY_CA_FILE"} {
		if caFile := os.Getenv(variable); caFile != "" {
			b, e := os.ReadFile(caFile)
			if e != nil {
				return nil, e
			}
			if !pool.AppendCertsFromPEM(b) {
				return nil, fmt.Errorf("Invalid CA in %s", variable)
			}
		}
	}
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return t, nil
}
func registryAuth() (authn.Authenticator, error) {
	b, e := os.ReadFile(env("REGISTRY_CREDENTIALS_FILE", "/run/secrets/registry.json"))
	if e != nil {
		return nil, e
	}
	var value struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.Unmarshal(b, &value) != nil || value.Username == "" || value.Password == "" {
		return nil, errors.New("Registry credentials are required")
	}
	return &authn.Basic{Username: value.Username, Password: value.Password}, nil
}
func (s *server) packageImage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AppID     string `json:"appId"`
		AttemptID string `json:"attemptId"`
		Template  string `json:"template"`
	}
	if !decode(w, r, &in) {
		return
	}
	root, e := safePath(filepath.Join(s.data, "artifacts"), in.AttemptID)
	if e != nil || !identity.MatchString(in.AppID) {
		fail(w, 400, errors.New("Invalid artifact identity"))
		return
	}
	template, ok := s.manifest.Templates[in.Template]
	if !ok || !digestImage.MatchString(template.RuntimeImage) {
		fail(w, 400, errors.New("Company-approved runtime template required"))
		return
	}
	unlock := s.lock(in.AttemptID)
	defer unlock()
	archive, e := layerArchive(root)
	if e != nil {
		fail(w, 400, e)
		return
	}
	layer, e := tarball.LayerFromReader(bytes.NewReader(archive))
	if e != nil {
		fail(w, 500, e)
		return
	}
	base, e := name.NewDigest(template.RuntimeImage, name.StrictValidation)
	if e != nil {
		fail(w, 400, e)
		return
	}
	transport, e := trustedTransport()
	if e != nil {
		fail(w, 500, e)
		return
	}
	auth, e := registryAuth()
	if e != nil {
		fail(w, 500, e)
		return
	}
	options := []remote.Option{remote.WithContext(r.Context()), remote.WithTransport(transport), remote.WithAuth(auth)}
	// The base must already be mirrored into the private registry by company installation.
	if !strings.HasPrefix(template.RuntimeImage, s.manifest.Registry+"/") {
		fail(w, 409, errors.New("Runtime base must be company-mirrored in the private registry"))
		return
	}
	image, e := remote.Image(base, options...)
	if e != nil {
		fail(w, 502, errors.New("Pinned runtime image unavailable"))
		return
	}
	image, e = mutate.AppendLayers(image, layer)
	if e != nil {
		fail(w, 500, e)
		return
	}
	config, e := image.ConfigFile()
	if e != nil {
		fail(w, 500, e)
		return
	}
	config.Config.User = "10001:10001"
	config.Config.WorkingDir = "/app"
	config.Config.Entrypoint = template.Entrypoint
	config.Config.Cmd = nil
	config.Config.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "NODE_ENV=production", "PORT=8080", "PYTHONPATH=/app/vendor", "PYTHONDONTWRITEBYTECODE=1"}
	config.Config.ExposedPorts = map[string]struct{}{"8080/tcp": {}}
	config.Config.Volumes = nil
	config.Config.Labels = map[string]string{"io.autosoft.app": in.AppID, "io.autosoft.attempt": in.AttemptID}
	config.Created = v1.Time{Time: time.Unix(0, 0)}
	image, e = mutate.ConfigFile(image, config)
	if e != nil {
		fail(w, 500, e)
		return
	}
	tag, e := name.NewTag(fmt.Sprintf("%s/apps/%s:%s", s.manifest.Registry, strings.ToLower(in.AppID), strings.ToLower(in.AttemptID)), name.StrictValidation)
	if e != nil {
		fail(w, 400, e)
		return
	}
	if e = remote.Write(tag, image, options...); e != nil {
		fail(w, 502, errors.New("Image publication into the private registry failed"))
		return
	}
	digest, e := image.Digest()
	if e != nil {
		fail(w, 500, e)
		return
	}
	respond(w, map[string]string{"image": tag.Repository.Name() + "@" + digest.String()})
}
