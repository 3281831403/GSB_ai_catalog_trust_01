// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"fmt"
)

// HostInfo identifies the operator of an AI Catalog.
type HostInfo struct {
	DisplayName string `json:"displayName"`

	// Identifier is a verifiable host identifier (e.g. a DID or domain name).
	Identifier string `json:"identifier,omitempty"`

	DocumentationURL string `json:"documentationUrl,omitempty"`

	// LogoURL may be a data URI (RFC 2397).
	LogoURL string `json:"logoUrl,omitempty"`

	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`
}

// Publisher is the canonical identity of the entity responsible for an artifact.
type Publisher struct {
	// Identifier is a verifiable identifier (e.g. a DID, domain name, or URI).
	Identifier string `json:"identifier"`

	DisplayName string `json:"displayName"`

	// IdentityType hints at Identifier's scheme (e.g. "did", "dns").
	IdentityType string `json:"identityType,omitempty"`
}

// TrustManifest provides verifiable identity, attestation, and provenance
// metadata for an artifact, sitting alongside it as a peer element.
type TrustManifest struct {
	// Identity is the subject identifier; within a CatalogEntry its trust
	// domain must align with the entry Identifier's publisher domain.
	Identity string `json:"identity"`

	IdentityType string           `json:"identityType,omitempty"`
	TrustSchema  *TrustSchema     `json:"trustSchema,omitempty"`
	Attestations []Attestation    `json:"attestations,omitempty"`
	Provenance   []ProvenanceLink `json:"provenance,omitempty"`

	PrivacyPolicyURL  string `json:"privacyPolicyUrl,omitempty"`
	TermsOfServiceURL string `json:"termsOfServiceUrl,omitempty"`

	// Subject binds the manifest to the exact artifact bytes it describes.
	// Required whenever Signature is present, otherwise the signature could be
	// replayed onto a different artifact.
	Subject *Subject `json:"subject,omitempty"`

	// IssuedAt is an RFC 3339 timestamp of when the manifest was issued.
	// Required whenever Signature is present.
	IssuedAt string `json:"issuedAt,omitempty"`

	// ExpiresAt is an RFC 3339 timestamp after which the manifest must no
	// longer be relied upon.
	ExpiresAt string `json:"expiresAt,omitempty"`

	// Signature is a detached JWS (RFC 7515) over the manifest, using JCS
	// (RFC 8785) canonicalization.
	Signature string `json:"signature,omitempty"`

	// Extensions holds custom or vendor-specific members. Keys must be a URL
	// or a reverse-DNS string to keep vendors from colliding.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// MarshalJSON preserves explicitly present empty array members.
//
// json.Unmarshal turns a present "attestations": [] into a non-nil slice of
// length zero, while a missing member leaves the field nil. encoding/json's
// "omitempty" treats both as absent, which drops a present-but-empty key. A
// producer signing the original bytes and a verifier canonicalizing this
// struct would then commit to different payloads. Marshaling through pointer
// slices lets omitempty distinguish nil (omit the member) from a non-nil empty
// slice (emit []).
func (m TrustManifest) MarshalJSON() ([]byte, error) {
	type proxy struct {
		Identity          string                     `json:"identity"`
		IdentityType      string                     `json:"identityType,omitempty"`
		TrustSchema       *TrustSchema               `json:"trustSchema,omitempty"`
		Attestations      *[]Attestation             `json:"attestations,omitempty"`
		Provenance        *[]ProvenanceLink          `json:"provenance,omitempty"`
		PrivacyPolicyURL  string                     `json:"privacyPolicyUrl,omitempty"`
		TermsOfServiceURL string                     `json:"termsOfServiceUrl,omitempty"`
		Subject           *Subject                   `json:"subject,omitempty"`
		IssuedAt          string                     `json:"issuedAt,omitempty"`
		ExpiresAt         string                     `json:"expiresAt,omitempty"`
		Signature         string                     `json:"signature,omitempty"`
		Extensions        map[string]json.RawMessage `json:"extensions,omitempty"`
	}

	out := proxy{
		Identity:          m.Identity,
		IdentityType:      m.IdentityType,
		TrustSchema:       m.TrustSchema,
		PrivacyPolicyURL:  m.PrivacyPolicyURL,
		TermsOfServiceURL: m.TermsOfServiceURL,
		Subject:           m.Subject,
		IssuedAt:          m.IssuedAt,
		ExpiresAt:         m.ExpiresAt,
		Signature:         m.Signature,
		Extensions:        m.Extensions,
	}

	if m.Attestations != nil {
		out.Attestations = &m.Attestations
	}

	if m.Provenance != nil {
		out.Provenance = &m.Provenance
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal trust manifest: %w", err)
	}

	return data, nil
}

// Subject binds a TrustManifest to the artifact it describes, so a signature
// cannot be replayed onto different content.
type Subject struct {
	// Type is the media type of the bound artifact; within a CatalogEntry it
	// must equal the entry's Type.
	Type string `json:"type"`

	// Digest is the artifact digest as "algorithm:hex" (SHA-256 or stronger).
	Digest string `json:"digest"`

	// URL locates the bound artifact; when set within a CatalogEntry it must
	// equal the entry's URL.
	URL string `json:"url,omitempty"`
}

// TrustSchema describes the trust framework applied to an artifact.
type TrustSchema struct {
	Identifier          string   `json:"identifier"`
	Version             string   `json:"version"`
	GovernanceURI       string   `json:"governanceUri,omitempty"`
	VerificationMethods []string `json:"verificationMethods,omitempty"`
}

// MarshalJSON preserves an explicitly present, empty "verificationMethods"
// member for the same signing-payload fidelity reasons as
// TrustManifest.MarshalJSON: nil omits the member, a non-nil empty slice
// serializes as [].
func (s TrustSchema) MarshalJSON() ([]byte, error) {
	type proxy struct {
		Identifier          string    `json:"identifier"`
		Version             string    `json:"version"`
		GovernanceURI       string    `json:"governanceUri,omitempty"`
		VerificationMethods *[]string `json:"verificationMethods,omitempty"`
	}

	out := proxy{
		Identifier:    s.Identifier,
		Version:       s.Version,
		GovernanceURI: s.GovernanceURI,
	}

	if s.VerificationMethods != nil {
		out.VerificationMethods = &s.VerificationMethods
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal trust schema: %w", err)
	}

	return data, nil
}

// Attestation is verifiable proof of a claim about an artifact (compliance
// certification, publisher identity binding, audit report, SBOM, etc.).
type Attestation struct {
	// Type is the attestation type (e.g. "SOC2-Type2", "publisher-identity").
	Type string `json:"type"`

	// URI is an HTTPS URL or Data URI locating the attestation document.
	URI string `json:"uri"`

	// Digest is an integrity digest as "algorithm:hex" (SHA-256 or stronger).
	Digest string `json:"digest,omitempty"`

	Size        *uint64 `json:"size,omitempty"`
	Description string  `json:"description,omitempty"`
}

// ProvenanceLink records lineage for an artifact.
type ProvenanceLink struct {
	// Relation to the source (e.g. "derivedFrom", "publishedFrom").
	Relation string `json:"relation"`

	// SourceID is the source artifact (e.g. a Git repo URL, OCI ref, dataset).
	SourceID string `json:"sourceId"`

	// SourceDigest is an integrity digest as "algorithm:hex".
	SourceDigest string `json:"sourceDigest,omitempty"`

	RegistryURI string `json:"registryUri,omitempty"`

	// StatementURI locates a provenance statement (e.g. in-toto / SLSA).
	StatementURI string `json:"statementUri,omitempty"`

	SignatureRef string `json:"signatureRef,omitempty"`
}
