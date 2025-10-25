# Roadmap — OAuth for MCP in Julia

This package aims to provide a modern, secure OAuth 2.x toolkit oriented around the Model Context Protocol (MCP), while also being a general-purpose OAuth client/server library for Julia.

We target **OAuth 2.1 (draft)** behavior and **RFC 9700** security best practices by default.

## Principles

- **Secure by default**: Authorization Code + PKCE only for public clients; no implicit; strict redirect URI matching; state/nonce; refresh token rotation; least privilege via scopes/authorization_details.
- **Interoperable**: Support RFC 8414 (AS metadata) and RFC 9728 (Protected Resource Metadata) so clients and servers auto-discover each other.
- **MCP-first UX**: Smooth 401 ➜ PRM ➜ AS metadata ➜ browser consent flow.

## Phase 1 — MCP-ready core

### Client (OAuth Client + MCP Client helpers)
- [ ] Fetch Resource Server **PRM** (`.well-known/oauth-protected-resource`) and extract `authorization_servers` (RFC 9728).
- [ ] Load **AS Metadata** (RFC 8414) for endpoints, JWKS URI, supported grants/algorithms.
- [ ] **Authorization Code + PKCE (S256)**: build auth URL, open browser, receive redirect (local callback helper), exchange code.
- [ ] Token handling: access + refresh, rotation, expiry skew handling, storage abstraction.
- [ ] **JWT AT (RFC 9068)** validation: fetch JWKS, verify `alg`, `kid`, `iss`, `aud`, `exp/nbf`, `client_id`, `scope` / `authorization_details`.
- [ ] HTTP auth middleware: attach bearer, parse `WWW-Authenticate` (401) and, if needed, re-bootstrap via PRM.
- [ ] **Revocation (RFC 7009)** helper.
- [ ] Minimal **RAR (RFC 9396)**: request/parse `authorization_details` objects for fine-grained permissions.

### Server (Authorization/Resource server surfaces for MCP servers)
- [ ] **Protected Resource Metadata (RFC 9728)** endpoint.
- [ ] **WWW-Authenticate** 401 with pointer to PRM when unauthenticated.
- [ ] RS token validation for **JWT AT (RFC 9068)**; audience/resource checks; scope/authorization_details enforcement.
- [ ] Basic **Introspection (RFC 7662)** and **Revocation (RFC 7009)** endpoints (JSON responses).

### Tooling & DX
- [ ] Config conventions (issuer, client_id/secret (confidential), redirect URIs, algorithms).
- [ ] Logging & structured errors aligning with OAuth error names.
- [ ] Examples: “MCP client ↔ demo MCP server” end-to-end.

## Phase 2 — Hardening & breadth

### Client
- [ ] **PAR (RFC 9126)** + **JAR (RFC 9101)** for signed/back-channel auth requests.
- [ ] **Device Authorization (RFC 8628)** for headless clients.
- [ ] **Sender-constrained tokens**: **DPoP (RFC 9449)** first; **mTLS (RFC 8705)** optional.
- [ ] **Resource Indicators (RFC 8707)** support.
- [ ] **Token Exchange (RFC 8693)** helpers for service-to-service hops.
- [ ] Introspection w/**JWT response (RFC 9701)** parsing.
- [ ] **Dynamic Client Registration (RFC 7591)** (+ **Mgmt 7592** where appropriate).

### Server
- [ ] **AS Metadata (RFC 8414)** endpoint (if the package offers an AS).
- [ ] **PAR** endpoint; **JAR** verification.
- [ ] **Issue JWT Access Tokens (RFC 9068)** with configurable signing algs; **JWKS** publishing.
- [ ] **Introspection with JWT responses (RFC 9701)**.
- [ ] **DPoP** acceptance and replay cache; optional **mTLS**.
- [ ] **RAR** policy engine & templates.
- [ ] **Step-Up Challenge (RFC 9470)** for sensitive tool actions.

## Security Defaults (RFC 9700)
- PKCE for all public clients; disable implicit.
- Enforce exact redirect URIs; state/nonce required.
- Refresh token rotation; revoke on suspected compromise.
- Prefer sender-constrained tokens (DPoP or mTLS) where feasible.
- Strict algorithm allow-lists; reject `none`/weak algs.

## Julia Dependencies

**Core**: HTTP.jl, JSON.jl, URIs.jl, Dates  
**Crypto/JWT**: JWTs.jl (JWS/JWT & JWKS), LibAwsX libraries for crypto primitives

## Compatibility

- MCP: follows the spec’s requirement to expose PRM and guide clients to the AS. Works with agents that implement the 401 ➜ PRM ➜ AS flow.

## Non-Goals (for now)

- Legacy OAuth (implicit, password grant).  
- Broad JWE coverage (may be added for JAR encryption later).
