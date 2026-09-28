package main

import (
	"fmt"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/trust"
	"github.com/Agent-Card/ai-catalog-go/validate"
)

const weakDoc = `{
  "specVersion": "1.0",
  "host": {"displayName": "Example Host"},
  "entries": [
    {"identifier": "urn:air:example.com:ns:agent", "type": "application/json",
     "url": "https://example.com/agent.json",
     "trustManifest": {
       "identity": "did:web:example.com",
       "subject": {"type": "application/json",
         "digest": "md5:d41d8cd98f00b204e9800998ecf8427e",
         "url": "https://example.com/agent.json"},
       "issuedAt": "2026-03-15T10:00:00Z",
       "signature": "eyJhbGciOiJub25lIn0..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
     }}
  ]
}`

const legalDoc = `{
  "specVersion": "1.0",
  "host": {"displayName": "Example Host"},
  "entries": [
    {"identifier": "urn:air:example.com:ns:agent", "type": "application/json",
     "url": "https://example.com/agent.json",
     "trustManifest": {
       "identity": "did:web:example.com",
       "subject": {"type": "application/json",
         "digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
         "url": "https://example.com/agent.json"},
       "issuedAt": "2026-03-15T10:00:00Z",
       "signature": "eyJhbGciOiJFUzI1NiJ9..c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
     }}
  ]
}`

func show(name, doc string) {
	c, err := catalog.ParseString(doc)
	if err != nil {
		panic(err)
	}

	r := validate.Validate(c)
	analysisErrors := 0
	for _, f := range trust.AnalyzeCatalog(c).Findings {
		if f.Severity == trust.SeverityError {
			analysisErrors++
		}
	}

	fmt.Printf("%-12s validate(valid=%v level=%s errors=%d) analysisErrors=%d\n",
		name, r.IsValid, r.ConformanceLevel, len(r.Errors), analysisErrors)
}

func main() {
	show("weak:", weakDoc)
	show("legal:", legalDoc)
}
