# OAuth.jl

OAuth.jl is a reference implementation of modern OAuth 2.x client/server flows in Julia. It now includes:

- PAR/JAR support with automatic HTTPS validation and request-object signing via `RequestObjectSigner`.
- Resource Indicator (RFC 8707) and Rich Authorization Request (RFC 9396) propagation for PKCE, refresh tokens, device authorization, and client credentials.
- Dynamic Client Registration helpers for RFC 7591/7592 compliant authorization servers.

## Quick Links

```@docs
PublicClientConfig
RequestObjectSigner
register_dynamic_client
register_dynamic_client_from_issuer
update_dynamic_client
delete_dynamic_client
```
