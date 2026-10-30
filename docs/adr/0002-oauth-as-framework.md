# ADR-002: OAuth AS framework

## Status

Accepted (provisional for M6)

## Decision

Use an embedded authorization server implementing OAuth 2.1 with PKCE (S256), RFC 8707 resource indicators, RFC 9207 `iss`, and DPoP (RFC 9449) / mTLS sender constraints.

For v2.0 M6 scaffolding, OpenTPRM ships Protected Resource Metadata and AS metadata endpoints plus opaque hashed token storage. Full `ory/fosite` integration is the preferred library when its license (Apache-2.0) and DPoP support are confirmed in-tree; until then the custom minimal AS in `internal/authn` handles development flows.

## Consequences

Dynamic Client Registration remains disabled. Clients are pre-registered by a Security Administrator.
