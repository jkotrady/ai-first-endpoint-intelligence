package pilot

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"aiforensics.local/platform/collectors"
)

type buildManifest struct {
	Schema      int                `json:"schema_version"`
	BinaryHash  string             `json:"binary_sha256"`
	BinarySize  int                `json:"binary_size"`
	SourceHash  string             `json:"source_zip_sha256"`
	SourceSize  int                `json:"source_zip_size"`
	Fingerprint string             `json:"source_fingerprint"`
	Collectors  []collectors.Entry `json:"collectors"`
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("artifact exceeds limit or unreadable")
	}
	return data, nil
}
func artifactHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validSHA(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}

// Load an internally consistent build snapshot, before enrolling any identity.
func loadArtifacts(dir string) (binary, source, manifest []byte, err error) {
	manifest, err = readBounded(filepath.Join(dir, "agent-build.json"), 128<<10)
	if err != nil {
		return
	}
	var m buildManifest
	if json.Unmarshal(manifest, &m) != nil || m.Schema != 1 || !validSHA(m.Fingerprint) || !reflect.DeepEqual(m.Collectors, collectors.All()) {
		err = fmt.Errorf("manifest/catalog mismatch")
		return
	}
	binary, err = readBounded(filepath.Join(dir, "forensics-agent-x86.exe"), 8<<20)
	if err != nil {
		return
	}
	source, err = readBounded(filepath.Join(dir, "forensics-agent-source.zip"), 2<<20)
	if err != nil {
		return
	}
	if len(binary) != m.BinarySize || len(source) != m.SourceSize || artifactHash(binary) != m.BinaryHash || artifactHash(source) != m.SourceHash {
		err = fmt.Errorf("artifact hash mismatch")
	}
	return
}
func (a *App) agentArtifact(w http.ResponseWriter, r *http.Request, u string) {
	binary, _, manifest, err := loadArtifacts("work/bin")
	if err != nil {
		fail(w, 503, "agent_build_unverified")
		return
	}
	if r.URL.Path == "/api/agent/update" {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		files := map[string][]byte{"forensics-agent.exe": binary, "agent-build.json": manifest, "README-UPDATE.txt": []byte("INTERNAL PILOT MANUAL UPDATE. Stop the foreground agent first. Verify the SHA-256 of forensics-agent.exe against agent-build.json. Preserve agent.conf, ca.pem, pending.json, last-job.txt and directory ACLs. Replace only the executable. Do not run this archive as a new device identity. Start the existing run.cmd. Refresh the control centre and approve new jobs against the reported source version. Old queued jobs for a different version will expire. Dependency license notices are included in licenses/. Sources will be published separately in GitHub. No automatic updater, signature certification or OS support guarantee.\r\n")}
		for _, name := range []string{"MBEDTLS.txt", "MINGW.txt", "GCC-RUNTIME.txt"} {
			data, e := os.ReadFile(filepath.Join("agent/windows/licenses", name))
			if e != nil {
				fail(w, 503, "license_notice_missing")
				return
			}
			files["licenses/"+name] = data
		}
		for name, data := range files {
			f, e := z.Create(name)
			if e != nil {
				fail(w, 500, "bundle_failed")
				return
			}
			if _, e = f.Write(data); e != nil {
				fail(w, 500, "bundle_failed")
				return
			}
		}
		if z.Close() != nil {
			fail(w, 500, "bundle_failed")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=forensics-agent-update.zip")
		w.Write(buf.Bytes())

	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(manifest)
	}
}
func supports(d *Device, id string) bool {
	return collectors.Allowed(id) && slices.Contains(d.Capabilities, id)
}

// Capability/source headers are authenticated self-reports, not attestation.
func reportedCapabilities(r *http.Request) ([]string, string, bool) {
	value, source := r.Header.Get("X-Agent-Collectors"), r.Header.Get("X-Agent-Source")
	if value == "" && source == "" {
		return []string{"F01", "F04", "F08"}, "", true
	}
	if len(r.Header.Values("X-Agent-Collectors")) != 1 || len(r.Header.Values("X-Agent-Source")) != 1 || len(value) > 199 || !validSHA(source) {
		return nil, "", false
	}
	ids := strings.Split(value, ",")
	seen := map[string]bool{}
	for _, id := range ids {
		if !collectors.Allowed(id) || seen[id] {
			return nil, "", false
		}
		seen[id] = true
	}
	if !seen["F01"] {
		return nil, "", false
	}
	return ids, source, true
}
