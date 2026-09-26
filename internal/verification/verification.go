// Package verification implements `diagpermit verify`:
//
//	schema validity, manifest consistency, artifact hashes, disclosure-plan
//	hash, request hash and archive structure.
//
// It deliberately verifies INTEGRITY only. It never claims privacy:
// verification proves the package has not changed according to the
// verification model; it does not prove no sensitive information remains.
package verification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Irish-Joseph/diagpermit/internal/safezip"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// Check is one verification result line.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Report is the full verification outcome.
type Report struct {
	Artifact string
	Checks   []Check
}

// Verdict returns the top-level verdict.
func (r *Report) Verdict() string {
	for _, c := range r.Checks {
		if !c.OK {
			return "INTEGRITY NOT VERIFIED"
		}
	}
	return "INTEGRITY VERIFIED"
}

// RequiredEntries are the archive entries that must be present.
var RequiredEntries = []string{
	protocol.FileManifest,
	protocol.FileRequest,
	protocol.FileDisclosure,
	protocol.FileCollection,
	protocol.FileTransformations,
	protocol.FileWarnings,
	protocol.FileDisclosureReceipt,
}

// Verify opens the artifact and runs all integrity checks.
func Verify(path string) (*Report, error) {
	r := &Report{Artifact: path}
	add := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
	}

	zr, err := safezip.Open(path, safezip.DefaultLimits())
	if err != nil {
		add("archive", false, err.Error())
		return r, nil
	}
	defer zr.Close()
	add("archive", true, "zip readable within size/entry limits")

	// 1. Archive structure.
	missing := []string{}
	for _, e := range RequiredEntries {
		if zr.Find(e) == nil {
			missing = append(missing, e)
		}
	}
	if len(missing) > 0 {
		add("archive-structure", false, "missing required entries: "+strings.Join(missing, ", "))
	} else {
		add("archive-structure", true, "all required entries present")
	}

	// safezip.Open rejects unsafe and duplicate entry names before any
	// content is read.
	add("path-safety", true, "all entry names are safe, unique relative paths")

	readJSON := func(name string, v any) error {
		b, err := zr.ReadEntry(name)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, v)
	}

	// 2. Schema validity (structural decode into typed documents).
	var manifest protocol.Manifest
	if err := readJSON(protocol.FileManifest, &manifest); err != nil {
		add("schema:manifest", false, err.Error())
		manifest = protocol.Manifest{}
	} else if manifest.ProtocolVersion != protocol.ProtocolVersion || len(manifest.Entries) == 0 {
		add("schema:manifest", false, "manifest invalid: bad protocolVersion or no entries")
	} else {
		add("schema:manifest", true, fmt.Sprintf("%d entries", len(manifest.Entries)))
	}

	var request protocol.DiagnosticRequest
	if err := readJSON(protocol.FileRequest, &request); err != nil {
		add("schema:request", false, err.Error())
	} else if request.ProtocolVersion != protocol.ProtocolVersion {
		add("schema:request", false, "unsupported protocolVersion in request")
	} else {
		add("schema:request", true, "request document valid")
	}

	var plan protocol.EffectiveDisclosurePlan
	if err := readJSON(protocol.FileDisclosure, &plan); err != nil {
		add("schema:disclosure", false, err.Error())
	} else {
		add("schema:disclosure", true, "disclosure plan valid")
	}

	var collection protocol.CollectionReport
	if err := readJSON(protocol.FileCollection, &collection); err != nil {
		add("schema:collection", false, err.Error())
	} else {
		add("schema:collection", true, fmt.Sprintf("%d collector results", len(collection.Results)))
	}

	var transformRep protocol.TransformationReport
	if err := readJSON(protocol.FileTransformations, &transformRep); err != nil {
		add("schema:transformations", false, err.Error())
	} else {
		add("schema:transformations", true, transformRep.Ruleset)
	}

	var receipt protocol.DisclosureReceipt
	receiptOK := true
	if err := readJSON(protocol.FileDisclosureReceipt, &receipt); err != nil {
		add("schema:receipt", false, err.Error())
		receiptOK = false
	} else {
		add("schema:receipt", true, "disclosure receipt valid")
	}

	// 3. Manifest consistency: hash + size of every entry.
	hashFails := []string{}
	for _, e := range manifest.Entries {
		b, err := zr.ReadEntry(e.Path)
		if err != nil {
			hashFails = append(hashFails, fmt.Sprintf("%s (missing)", e.Path))
			continue
		}
		if int64(len(b)) != e.Size {
			hashFails = append(hashFails, fmt.Sprintf("%s (size)", e.Path))
			continue
		}
		if protocol.SHA256(b) != e.SHA256 {
			hashFails = append(hashFails, fmt.Sprintf("%s (sha256)", e.Path))
		}
	}
	if len(hashFails) > 0 {
		add("artifact-hashes", false, strings.Join(hashFails, "; "))
	} else {
		add("artifact-hashes", true, fmt.Sprintf("all %d manifest hashes match", len(manifest.Entries)))
	}

	// Every archive entry must be covered by the manifest, except the
	// disclosure receipt itself (referenced from the receipt chain).
	covered := map[string]bool{}
	for _, e := range manifest.Entries {
		covered[e.Path] = true
	}
	uncovered := []string{}
	for _, n := range zr.Names() {
		if n == protocol.FileDisclosureReceipt || n == protocol.FileManifest {
			continue
		}
		if !covered[n] {
			uncovered = append(uncovered, n)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		add("manifest-coverage", false, "entries not in manifest: "+strings.Join(uncovered, ", "))
	} else {
		add("manifest-coverage", true, "all entries covered by manifest")
	}

	if !receiptOK {
		return r, nil
	}

	// 4. Request hash (canonical JSON of request.json).
	reqBytes, err := zr.ReadEntry(protocol.FileRequest)
	if err != nil {
		add("request-hash", false, err.Error())
	} else {
		h, err := protocol.HashDocument(reqBytes)
		if err != nil || h != receipt.Request.Hash {
			add("request-hash", false, fmt.Sprintf("expected %s, computed %s", receipt.Request.Hash, h))
		} else {
			add("request-hash", true, "request hash matches receipt")
		}
	}

	// 5. Disclosure plan hash.
	planBytes, err := zr.ReadEntry(protocol.FileDisclosure)
	if err != nil {
		add("disclosure-plan-hash", false, err.Error())
	} else {
		h, err := protocol.HashDocument(planBytes)
		if err != nil || h != receipt.DisclosurePlanHash {
			add("disclosure-plan-hash", false, fmt.Sprintf("expected %s, computed %s", receipt.DisclosurePlanHash, h))
		} else {
			add("disclosure-plan-hash", true, "disclosure plan hash matches receipt")
		}
	}

	// 6. Manifest hash.
	manBytes, err := zr.ReadEntry(protocol.FileManifest)
	if err != nil {
		add("manifest-hash", false, err.Error())
	} else {
		h, err := protocol.HashDocument(manBytes)
		if err != nil || h != receipt.Artifact.ManifestHash {
			add("manifest-hash", false, fmt.Sprintf("expected %s, computed %s", receipt.Artifact.ManifestHash, h))
		} else {
			add("manifest-hash", true, "manifest hash matches receipt")
		}
	}

	// 7. Optional signatures: none exist in V0.1; report their absence
	// without failing.
	sig := false
	for _, n := range zr.Names() {
		if strings.HasPrefix(n, protocol.DirAttestations+"/") && n != protocol.FileDisclosureReceipt {
			sig = true
		}
	}
	if sig {
		add("signatures", true, "attestations present (see attestations/)")
	} else {
		add("signatures", true, "no signatures present (optional in V0.1; request authenticity NOT VERIFIED)")
	}

	return r, nil
}

// PrivacyDisclaimer is printed after every verify/inspect output. It is
// mandatory wording.
const PrivacyDisclaimer = `Integrity proves the package has not changed according to the
verification model. It does NOT prove that no sensitive information
remains inside. Review diagnostic content before sharing it.`
