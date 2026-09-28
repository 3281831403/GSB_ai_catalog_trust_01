// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

// A manifest with present-but-empty array members, exercising every array the
// trust manifest models.
const emptyArraysManifest = `{
  "identity": "did:web:example.com",
  "trustSchema": {"identifier": "urn:trust:example", "version": "1.0",
                  "verificationMethods": []},
  "attestations": [],
  "provenance": []
}`

const populatedArraysManifest = `{
  "identity": "did:web:example.com",
  "trustSchema": {"identifier": "urn:trust:example", "version": "1.0",
                  "verificationMethods": ["https://example.com/vm"]},
  "attestations": [{"type": "publisher-identity",
    "uri": "https://example.com/a.jwt"}],
  "provenance": [{"relation": "publishedFrom",
    "sourceId": "https://github.com/example/repo"}]
}`

const noArrayKeysManifest = `{
  "identity": "did:web:example.com",
  "privacyPolicyUrl": "https://example.com/privacy"
}`

func canonicalFromBytes(t *testing.T, raw string) string {
	t.Helper()

	canonical, err := trust.CanonicalizeForSignature([]byte(raw))
	if err != nil {
		t.Fatalf("CanonicalizeForSignature error: %v", err)
	}

	return string(canonical)
}

func canonicalFromStruct(t *testing.T, raw string) string {
	t.Helper()

	var manifest catalog.TrustManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	canonical, err := trust.CanonicalizeTrustManifest(&manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	return canonical
}

func TestCanonicalize_ExplicitEmptyArraysArePreserved(t *testing.T) {
	fromBytes := canonicalFromBytes(t, emptyArraysManifest)
	fromStruct := canonicalFromStruct(t, emptyArraysManifest)

	for _, member := range []string{`"attestations":[]`, `"provenance":[]`, `"verificationMethods":[]`} {
		if !strings.Contains(fromBytes, member) {
			t.Errorf("byte canonicalization lost %s: %s", member, fromBytes)
		}

		if !strings.Contains(fromStruct, member) {
			t.Errorf("struct canonicalization lost %s: %s", member, fromStruct)
		}
	}

	if fromBytes != fromStruct {
		t.Errorf("canonical payloads diverge:\n bytes:  %s\n struct: %s", fromBytes, fromStruct)
	}
}

func TestCanonicalize_PopulatedArraysAreUnchanged(t *testing.T) {
	fromBytes := canonicalFromBytes(t, populatedArraysManifest)
	fromStruct := canonicalFromStruct(t, populatedArraysManifest)

	if fromBytes != fromStruct {
		t.Errorf("canonical payloads diverge:\n bytes:  %s\n struct: %s", fromBytes, fromStruct)
	}

	if !strings.Contains(fromStruct, `"uri":"https://example.com/a.jwt"`) ||
		!strings.Contains(fromStruct, `"verificationMethods":["https://example.com/vm"]`) {
		t.Errorf("array elements lost during struct canonicalization: %s", fromStruct)
	}
}

func TestCanonicalize_AbsentArrayKeysStayAbsent(t *testing.T) {
	fromBytes := canonicalFromBytes(t, noArrayKeysManifest)
	fromStruct := canonicalFromStruct(t, noArrayKeysManifest)

	if fromBytes != fromStruct {
		t.Errorf("canonical payloads diverge for missing keys:\n bytes:  %s\n struct: %s",
			fromBytes, fromStruct)
	}

	for _, member := range []string{"attestations", "provenance", "verificationMethods"} {
		if strings.Contains(fromStruct, member) {
			t.Errorf("absent member %q must not be synthesized: %s", member, fromStruct)
		}
	}
}

// Constructing a struct directly with non-nil empty slices is equivalent to a
// present empty array in the JSON.
func TestCanonicalize_NonNilEmptySlicesMarshalAsArrays(t *testing.T) {
	manifest := catalog.TrustManifest{
		Identity:     "did:web:example.com",
		Attestations: []catalog.Attestation{},
		Provenance:   []catalog.ProvenanceLink{},
		TrustSchema: &catalog.TrustSchema{
			Identifier:          "urn:trust:example",
			Version:             "1.0",
			VerificationMethods: []string{},
		},
	}

	canonical, err := trust.CanonicalizeTrustManifest(&manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	for _, member := range []string{`"attestations":[]`, `"provenance":[]`, `"verificationMethods":[]`} {
		if !strings.Contains(canonical, member) {
			t.Errorf("expected %s in: %s", member, canonical)
		}
	}
}
