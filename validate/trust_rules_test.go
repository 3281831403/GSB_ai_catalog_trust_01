// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/validate"
)

// jwsWithAlg builds a detached JWS whose protected header declares alg.
func jwsWithAlg(alg string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"`+alg+`"}`)) + "..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
}

// signedEntryDoc builds an otherwise-valid document with one trust manifest,
// parameterized by signature algorithm and subject digest.
func signedEntryDoc(alg, digest string) string {
	return `{
  "specVersion": "1.0",
  "host": {"displayName": "Example Host"},
  "entries": [
    {"identifier": "urn:air:example.com:ns:agent", "type": "application/json",
     "url": "https://example.com/agent.json",
     "trustManifest": {
       "identity": "did:web:example.com",
       "subject": {
         "type": "application/json",
         "digest": "` + digest + `",
         "url": "https://example.com/agent.json"
       },
       "issuedAt": "2026-03-15T10:00:00Z",
       "signature": "` + jwsWithAlg(alg) + `"
     }}
  ]
}`
}

// hex40 is a syntactically valid 40-char hex value for sha1-shaped digests.
const hex40 = "0123456789abcdef0123456789abcdef01234567"

func TestValidate_RejectsForbiddenSignatureAlgorithms(t *testing.T) {
	cases := map[string]string{
		"none":              "none",
		"HS256 (symmetric)": "HS256",
		"HS512 (symmetric)": "HS512",
	}

	for name, alg := range cases {
		t.Run(name, func(t *testing.T) {
			result := validate.Validate(mustParse(t, signedEntryDoc(
				alg, "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")))

			if result.IsValid {
				t.Fatalf("alg %q should be rejected, result: %+v", alg, result.Errors)
			}

			if result.ConformanceLevel != validate.Minimal {
				t.Errorf("alg %q: level = %v, want minimal", alg, result.ConformanceLevel)
			}

			if !hasErrorAt(result,
				"catalog.entries[0].trustManifest.signature",
				"signature algorithm '"+alg+"' must be rejected") {
				t.Errorf("alg %q: missing signature error, got: %+v", alg, result.Errors)
			}
		})
	}
}

func TestValidate_RejectsWeakSubjectDigests(t *testing.T) {
	cases := map[string]string{
		"md5":  "md5:d41d8cd98f00b204e9800998ecf8427e",
		"sha1": "sha1:" + hex40,
	}

	for name, digest := range cases {
		t.Run(name, func(t *testing.T) {
			result := validate.Validate(mustParse(t, signedEntryDoc("ES256", digest)))

			if result.IsValid {
				t.Fatalf("digest %q should be rejected, result: %+v", digest, result.Errors)
			}

			if !hasErrorAt(result,
				"catalog.entries[0].trustManifest.subject.digest",
				"weaker than SHA-256") {
				t.Errorf("digest %q: missing weak-digest error, got: %+v", digest, result.Errors)
			}
		})
	}
}

func TestValidate_ForbiddenAlgorithmAndWeakDigestBothReported(t *testing.T) {
	result := validate.Validate(mustParse(t, signedEntryDoc(
		"none", "md5:d41d8cd98f00b204e9800998ecf8427e")))

	if result.IsValid || result.ConformanceLevel != validate.Minimal {
		t.Fatalf("expected invalid minimal document, got valid=%v level=%v",
			result.IsValid, result.ConformanceLevel)
	}

	if !hasErrorAt(result,
		"catalog.entries[0].trustManifest.signature", "must be rejected") {
		t.Errorf("missing signature-algorithm error: %+v", result.Errors)
	}

	if !hasErrorAt(result,
		"catalog.entries[0].trustManifest.subject.digest", "weaker than SHA-256") {
		t.Errorf("missing weak-digest error: %+v", result.Errors)
	}
}

func TestValidate_AcceptsAsymmetricAlgorithmWithStrongDigest(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "EdDSA", "PS256", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			result := validate.Validate(mustParse(t, signedEntryDoc(
				alg, "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")))

			if !result.IsValid {
				t.Fatalf("alg %q should be accepted, errors: %+v", alg, result.Errors)
			}

			if result.ConformanceLevel != validate.Trusted {
				t.Errorf("alg %q: level = %v, want trusted", alg, result.ConformanceLevel)
			}
		})
	}
}

func TestValidate_RejectsForbiddenAlgorithmOnHostManifest(t *testing.T) {
	const doc = `{
  "specVersion": "1.0",
  "host": {"displayName": "Example Host",
    "trustManifest": {
      "identity": "did:web:example.com",
      "subject": {"type": "application/ai-catalog+json",
        "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
      "issuedAt": "2026-03-15T10:00:00Z",
      "signature": "` + "eyJhbGciOiJub25lIn0..c2lnbmF0dXJlLXBsYWNlaG9sZGVy" + `"
    }},
  "entries": []
}`

	result := validate.Validate(mustParse(t, doc))

	if result.IsValid {
		t.Fatalf("host manifest with alg none should be rejected: %+v", result.Errors)
	}

	if !hasErrorAt(result, "catalog.host.trustManifest.signature", "must be rejected") {
		t.Errorf("missing host signature error: %+v", result.Errors)
	}
}

func TestValidate_RejectsForbiddenAlgorithmOnMultipleManifests(t *testing.T) {
	doc := fmt.Sprintf(`{
  "specVersion": "1.0",
  "host": {"displayName": "Example Host",
    "trustManifest": {
      "identity": "did:web:example.com",
      "subject": {"type": "application/ai-catalog+json",
        "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
      "issuedAt": "2026-03-15T10:00:00Z",
      "signature": "eyJhbGciOiJub25lIn0..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
    }},
  "entries": [
    {"identifier": "urn:air:example.com:ns:a", "type": "application/json",
     "url": "https://example.com/a.json",
     "trustManifest": {
       "identity": "did:web:example.com",
       "subject": {"type": "application/json",
         "digest": "sha1:%s",
         "url": "https://example.com/a.json"},
       "issuedAt": "2026-03-15T10:00:00Z",
       "signature": "eyJhbGciOiJIUzI1NiJ9..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
     }},
    {"identifier": "urn:air:example.com:ns:b", "type": "application/json",
     "url": "https://example.com/b.json",
     "trustManifest": {
       "identity": "did:web:example.com",
       "subject": {"type": "application/json",
         "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
         "url": "https://example.com/b.json"},
       "issuedAt": "2026-03-15T10:00:00Z",
       "signature": "eyJhbGciOiJFUzI1NiJ9..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
     }}
  ]
}`, hex40)

	result := validate.Validate(mustParse(t, doc))

	wantPaths := []string{
		"catalog.host.trustManifest.signature",
		"catalog.entries[0].trustManifest.signature",
		"catalog.entries[0].trustManifest.subject.digest",
	}

	for _, wantPath := range wantPaths {
		if !hasPath(result, wantPath) {
			t.Errorf("expected an error at %q, got: %+v", wantPath, result.Errors)
		}
	}

	if hasPath(result, "catalog.entries[1]") {
		t.Errorf("the valid second manifest must not be flagged: %+v", result.Errors)
	}
}

func TestValidate_RejectsForbiddenAlgorithmOnCatalogSignature(t *testing.T) {
	const doc = `{
  "specVersion": "1.0",
  "signature": "eyJhbGciOiJub25lIn0..c2lnbmF0dXJlLXBsYWNlaG9sZGVy",
  "host": {"displayName": "Example Host"},
  "entries": []
}`

	result := validate.Validate(mustParse(t, doc))

	if !hasErrorAt(result, "catalog.signature", "signature algorithm 'none' must be rejected") {
		t.Errorf("expected catalog.signature algorithm error, got: %+v", result.Errors)
	}
}

func hasErrorAt(result validate.Result, path, substr string) bool {
	for _, d := range result.Errors {
		if d.Path == path && strings.Contains(d.Message, substr) {
			return true
		}
	}

	return false
}

func hasPath(result validate.Result, pathPrefix string) bool {
	for _, d := range result.Errors {
		if strings.HasPrefix(d.Path, pathPrefix) {
			return true
		}
	}

	return false
}
