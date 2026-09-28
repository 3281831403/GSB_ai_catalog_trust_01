// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

func TestTrustManifestMarshal_PreservesExplicitEmptyArrays(t *testing.T) {
	raw := `{
	  "identity": "did:web:example.com",
	  "trustSchema": {"identifier": "urn:trust:example", "version": "1.0",
	                  "verificationMethods": []},
	  "attestations": [],
	  "provenance": []
	}`

	var manifest catalog.TrustManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, member := range []string{`"attestations":[]`, `"provenance":[]`, `"verificationMethods":[]`} {
		if !strings.Contains(string(data), member) {
			t.Errorf("present empty array must survive marshal, missing %s: %s", member, data)
		}
	}

	// A second round trip must keep the members present.
	var reparsed catalog.TrustManifest
	if err := json.Unmarshal(data, &reparsed); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}

	if reparsed.Attestations == nil || reparsed.Provenance == nil {
		t.Errorf("empty arrays must remain non-nil after round trip: %+v", reparsed)
	}

	if reparsed.TrustSchema == nil || reparsed.TrustSchema.VerificationMethods == nil {
		t.Errorf("empty verificationMethods must remain non-nil after round trip: %+v", reparsed.TrustSchema)
	}
}

func TestTrustManifestMarshal_AbsentArraysStayOmitted(t *testing.T) {
	manifest := catalog.TrustManifest{Identity: "did:web:example.com"}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, member := range []string{"attestations", "provenance", "verificationMethods", "trustSchema"} {
		if strings.Contains(string(data), member) {
			t.Errorf("absent member %q must be omitted, got: %s", member, data)
		}
	}
}

func TestTrustManifestMarshal_PopulatedArraysUnchanged(t *testing.T) {
	raw := `{
	  "identity": "did:web:example.com",
	  "attestations": [{"type": "publisher-identity", "uri": "https://example.com/a.jwt"}],
	  "provenance": [{"relation": "publishedFrom", "sourceId": "https://example.com/repo"}]
	}`

	var manifest catalog.TrustManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !strings.Contains(string(data), `"attestations":[{`) ||
		!strings.Contains(string(data), `"provenance":[{`) {
		t.Errorf("populated arrays must serialize with their elements: %s", data)
	}
}
