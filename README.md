# OAuth.jl

[![CI](https://github.com/JuliaServices/OAuth.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/OAuth.jl/actions?query=workflow%3ACI)
[![Stable Docs](https://img.shields.io/badge/docs-stable-blue.svg)](https://juliaservices.github.io/OAuth.jl/stable)
[![Dev Docs](https://img.shields.io/badge/docs-dev-purple.svg)](https://juliaservices.github.io/OAuth.jl/dev)
[![Coverage](https://codecov.io/gh/JuliaServices/OAuth.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/JuliaServices/OAuth.jl)

OAuth.jl is a pure Julia toolkit for building OAuth 2.x clients and servers. It includes helpers for PKCE, DPoP, device authorization, pushed authorization requests (PAR), JWT authorization requests (JAR), resource indicators, dynamic client registration, protected-resource middleware, token introspection, and more.

- Works with real-world metadata: discover protected resources, authorization servers, and token endpoints directly from `/.well-known` documents.
- First-class support for sender-constrained tokens (DPoP), resource indicators, and `authorization_details` objects so access tokens stay bound to audiences and actions.
- Batteries-included server primitives: metadata endpoints, JWT access token issuance, in-memory token stores, authorization/token endpoint builders, and middleware that validates bearer/DPoP tokens for you.
- Pure Julia API surface that plays nicely with `HTTP.jl`, async tasks, and REPL-friendly workflows.

## Installation

```julia
julia> ] add OAuth
```

OAuth.jl is tested against Julia `1.10` and newer.

## Contents

- [Client](#client)
  - [Discovery & Configuration](#discovery--configuration)
  - [Authorization Code + PKCE](#authorization-code--pkce)
  - [Device Authorization Flow](#device-authorization-flow)
  - [Client Credentials Grant](#client-credentials-grant)
  - [Token Refresh, Resource Indicators & Authenticated Calls](#token-refresh-resource-indicators--authenticated-calls)
  - [Dynamic Client Registration](#dynamic-client-registration)
- [Server](#server)
  - [Publishing OAuth Metadata](#publishing-oauth-metadata)
  - [JWT Access Token Issuance & Storage](#jwt-access-token-issuance--storage)
  - [Protected Resource Middleware](#protected-resource-middleware)
  - [Authorization Endpoint Helpers](#authorization-endpoint-helpers)
  - [Token Endpoint Helpers](#token-endpoint-helpers)
  - [Introspection & Revocation](#introspection--revocation)
- [Contributing](#contributing)
- [License](#license)

## Client

OAuth.jl exposes a high-level client API that balances ergonomics (loopback listeners, browser launch helpers, refresh token persistence) with access to raw OAuth features when you need them.

### Discovery & Configuration

Use discovery helpers to bootstrap configurations from protected resource metadata or directly from an issuer. Both `PublicClientConfig` and `ConfidentialClientConfig` understand scopes, resource indicators, authorization details, additional query parameters, DPoP, and persistent refresh tokens.

```julia
using OAuth, JSON

# Resolve both the protected resource and authorization server metadata.
discovery = discover_oauth_metadata(
    "https://api.example/.well-known/oauth-protected-resource";
    issuer = "https://id.example",
)

# Optional DPoP and request-object signers.
dpop = DPoPAuth(
    private_key = read("keys/dpop-private.pem", String),
    public_jwk = JSON.parse(read("keys/dpop-public.jwk", String)),
)
request_signer = RequestObjectSigner(
    private_key = read("keys/request-object.pem", String),
    alg = :RS256,
    kid = "request-key",
)

client = PublicClientConfig(
    client_id = "desktop-app",
    redirect_uri = "http://127.0.0.1:8765/callback",
    scopes = ["openid", "profile", "payments.read"],
    resources = ["https://api.example"],
    authorization_details = [Dict("type" => "payment", "actions" => ["read"], "locations" => ["https://api.example"])],
    additional_parameters = Dict("prompt" => "consent"),
    dpop = dpop,
    refresh_token_store = InMemoryRefreshTokenStore(),
    use_par = true,
    request_object_signer = request_signer,
)
```

Confidential clients are configured the same way but add token-endpoint credentials:

```julia
service_app = ConfidentialClientConfig(
    client_id = "microservice",
    credential = PrivateKeyJWTAuth(
        private_key = read("keys/private-jwt.pem", String),
        alg = :RS256,
        audience = "https://id.example/token",
        kid = "svc-key",
    ),
    scopes = ["jobs.write"],
    resources = ["https://api.example"],
    authorization_details = nothing,
)
```

### Authorization Code + PKCE

`start_pkce_authorization` bootstraps an interactive authorization session. OAuth.jl can manage a loopback HTTP listener automatically, generate a PKCE verifier/challenge, push authorization requests (PAR) when required, and optionally launch the user’s browser.

```julia
session = start_pkce_authorization(
    "https://api.example/.well-known/oauth-protected-resource",
    client;
    open_browser = false,
    wait = false,
    listener_port = 8765,
)
println("Open this URL in your browser: \n$(session.authorization_url)")
callback = wait_for_authorization_code(session; timeout = 180)

token = exchange_code_for_token(
    session.authorization_server,
    session.client_config,
    callback.code,
    session.verifier,
)
```

The convenience wrapper `complete_pkce_authorization` combines the start/wait/exchange phases if you’re happy letting OAuth.jl open a browser window:

```julia
result = complete_pkce_authorization(
    "https://api.example/.well-known/oauth-protected-resource",
    client;
    open_browser = true,
    wait = true,
)
access_token = result.token
```

Refresh tokens are persisted via the configured `RefreshTokenStore`, and the helpers automatically carry over `resource` and `authorization_details` to refresh requests:

```julia
refreshed = refresh_pkce_token(result.session.authorization_server, result.session.client_config)
```

### Device Authorization Flow

Device/limited-input scenarios use the same configuration object. OAuth.jl posts to the authorization server’s `device_authorization_endpoint`, prints the verification URI/user code, and keeps polling until the user finishes consent.

```julia
device_flow = start_device_authorization(
    "https://api.example/.well-known/oauth-protected-resource",
    client,
)
println("Visit $(device_flow.device.verification_uri) and enter code $(device_flow.device.user_code)")

token = poll_device_authorization_token(
    device_flow.authorization_server,
    client,
    device_flow.device;
    sleep_function = sleep,
)
```

### Client Credentials Grant

Confidential clients can request service-to-service tokens with any supported token-endpoint auth method (`client_secret_basic`, `client_secret_jwt`, `private_key_jwt`, or mTLS via `TLSClientAuth`).

```julia
discovery = discover_oauth_metadata_from_issuer("https://id.example")
token = request_client_credentials_token(
    discovery.authorization_server,
    service_app;
    extra_token_params = Dict("resource" => "https://api.example/processor"),
)
```

### Token Refresh, Resource Indicators & Authenticated Calls

Tokens capture resource indicators, authorization details, DPoP thumbprints, and expiration data via `TokenResponse`. Use `oauth_request` to send authenticated HTTP requests; it automatically injects the `Authorization` header, adds DPoP proofs when needed, and retries when the server asks for a nonce.

```julia
resp = oauth_request(
    HTTP,
    "GET",
    "https://api.example/v1/payments";
    token = token,
    config = client, # supplies the DPoP key if token_type == "DPoP"
    headers = HTTP.Headers(["Accept" => "application/json"]),
)
```

### Dynamic Client Registration

Registration helpers enforce HTTPS, serialize metadata once, and return the raw JSON provided by the authorization server so you can persist registration and management endpoints.

```julia
metadata = fetch_authorization_server_metadata("https://id.example")
client_record = register_dynamic_client(
    metadata,
    Dict(
        "redirect_uris" => ["http://127.0.0.1:8765/callback"],
        "grant_types" => ["authorization_code"],
        "token_endpoint_auth_method" => "client_secret_basic",
    );
    initial_access_token = "seed-token",
)

update_dynamic_client(
    client_record["client_configuration_endpoint"],
    Dict("client_name" => "Updated Demo App");
    registration_access_token = client_record["registration_access_token"],
)

delete_dynamic_client(
    client_record["client_configuration_endpoint"]; 
    registration_access_token = client_record["registration_access_token"],
)
```

## Server

Server-side helpers cover metadata exposure, authorization and token endpoints, JWT access token issuance, DPoP validation, introspection/revocation, and middleware that gates `HTTP.jl` handlers behind OAuth scopes.

### Publishing OAuth Metadata

Expose protected-resource and authorization-server metadata straight from a router. The helpers validate HTTPS URLs, normalize string vectors, and keep documents on the canonical `/.well-known` paths.

```julia
using HTTP, OAuth, JSON

router = HTTP.Router()

resource_cfg = ProtectedResourceConfig(
    resource = "https://api.example",
    authorization_servers = ["https://id.example"],
    scopes_supported = ["payments.read", "payments.write"],
)
register_protected_resource_metadata!(router, resource_cfg)

token_issuer = JWTAccessTokenIssuer(
    issuer = "https://id.example",
    audience = ["https://api.example"],
    private_key = read("keys/token-signing.pem", String),
    alg = :RS256,
    kid = "token-key-1",
)

auth_server_cfg = AuthorizationServerConfig(
    issuer = "https://id.example",
    authorization_endpoint = "https://id.example/authorize",
    token_endpoint = "https://id.example/token",
    device_authorization_endpoint = "https://id.example/device_authorization",
    jwks_uri = "https://id.example/.well-known/jwks.json",
    scopes_supported = ["payments.read", "payments.write"],
    code_challenge_methods_supported = ["S256"],
    token_endpoint_auth_methods_supported = ["client_secret_basic", "private_key_jwt"],
    request_object_signing_alg_values_supported = ["RS256", "ES256"],
)
register_authorization_server_metadata!(router, auth_server_cfg)
register_jwks_endpoint!(router, [public_jwk(token_issuer)])
```

### JWT Access Token Issuance & Storage

`JWTAccessTokenIssuer` signs tokens, and the optional `AccessTokenStore` captures issued tokens for introspection and revocation. Tokens inherit scopes, authorization details, audiences, confirmation (`cnf`) claims, and extra custom claims in a single call.

```julia
token_store = InMemoryTokenStore()
issued = issue_access_token(
    token_issuer;
    subject = "user-123",
    client_id = "desktop-app",
    scope = ["payments.read"],
    authorization_details = [Dict("type" => "payment", "actions" => ["read"])],
    extra_claims = Dict("username" => "alice"),
    store = token_store,
)

validator = TokenValidationConfig(
    issuer = "https://id.example",
    audience = ["https://api.example"],
    jwks = Dict("keys" => [public_jwk(token_issuer)]),
)
claims = validate_jwt_access_token(issued.token, validator; required_scopes = ["payments.read"])
```

`AccessTokenClaims` includes the parsed scope list, audience, confirmation thumbprint, client ID, and raw claims you can use for authorization decisions.

### Protected Resource Middleware

Wrap any `HTTP.jl` handler so it automatically validates the `Authorization` header, enforces scopes, checks DPoP proofs, and places the decoded token on the request context.

```julia
function payments_handler(req)
    claims = req.context[:oauth_token]
    body = JSON.json(Dict("subject" => claims.subject, "scope" => claims.scope))
    return HTTP.Response(200, ["Content-Type" => "application/json"], body)
end

secured_handler = protected_resource_middleware(
    payments_handler,
    validator;
    resource_metadata_url = "https://api.example/.well-known/oauth-protected-resource",
    required_scopes = ["payments.read"],
    sender_constrained_only = false,
    dpop_nonce_validator = (_nonce, _req) -> true,
)
HTTP.register!(router, "GET", "/payments", secured_handler)
```

When the incoming token is sender constrained, OAuth.jl verifies the accompanying DPoP proof (htu/htm/ath), enforces nonce policies, and rejects replayed JTIs via `DPoPReplayCache`.

### Authorization Endpoint Helpers

`build_authorization_endpoint` wires together redirect validation, consent collection, PKCE enforcement, and authorization-code issuance. You implement two small callbacks: a redirect resolver and a consent handler that returns `AuthorizationGrantDecision`.

```julia
code_store = InMemoryAuthorizationCodeStore()
auth_endpoint = build_authorization_endpoint(
    AuthorizationEndpointConfig(
        code_store = code_store,
        redirect_uri_resolver = (_req, client_id, requested) -> begin
            whitelist = Dict("desktop-app" => "http://127.0.0.1:8765/callback")
            requested === nothing ? whitelist[client_id] : requested
        end,
        consent_handler = (_req, ctx) -> begin
            println("User granted scopes: $(ctx.scope)")
            return grant_authorization("user-123"; scope = ctx.scope, authorization_details = ctx.authorization_details)
        end,
    ),
)
HTTP.register!(router, "GET", "/authorize", auth_endpoint)
```

`AuthorizationRequestContext` contains the normalized request (client ID, redirect URI, scope/resource arrays, PKCE code challenge/method, and arbitrary params), so your consent handler can add custom claims or deny requests with helpful messages via `deny_authorization`.

### Token Endpoint Helpers

The token endpoint builder consumes the authorization codes created above, issues JWTs, saves them to your store, and optionally returns refresh tokens. Bring your client-store map as an authenticator.

```julia
client_auth = client_credentials_authenticator(Dict("desktop-app" => "secret"))

token_endpoint = build_token_endpoint(
    TokenEndpointConfig(
        code_store = code_store,
        token_issuer = token_issuer,
        client_authenticator = client_auth,
        token_store = token_store,
        refresh_token_generator = (record, _client) -> random_state(),
        extra_token_claims = (record, _client) -> Dict("auth_time" => OAuth.datetime_to_unix(record.issued_at)),
        allowed_grant_types = ["authorization_code"],
    ),
)
HTTP.register!(router, "POST", "/token", token_endpoint)
```

You receive a `TokenEndpointClient` describing the authenticated client, and the helper automatically enforces PKCE (plain vs `S256`), validates redirect URIs, and copies authorization details/resource indicators into the response.

### Introspection & Revocation

OAuth.jl exposes ready-to-mount handlers for RFC 7662 introspection and RFC 7009 revocation. Protect them with either the default `AllowAllAuthenticator` or HTTP Basic credentials.

```julia
introspect_auth = BasicCredentialsAuthenticator(
    credentials = Dict("resource" => "topsecret"),
    realm = "token",
)
HTTP.register!(router, "POST", "/introspect", build_introspection_handler(token_store; authenticator = introspect_auth))
HTTP.register!(router, "POST", "/revoke", build_revocation_handler(token_store; authenticator = introspect_auth))
```

### Running the server

Once routes are registered, start serving with `HTTP.serve(router, ip"0.0.0.0", 8080)` or your favorite HTTP stack. All helpers return plain functions, so you can plug them into Genie.jl, Oxygen.jl, or any other framework that understands `HTTP.Request`.

## Contributing

1. Install Julia 1.10 or newer.
2. Run the test suite with `julia --project -e 'using Pkg; Pkg.test()'`.
3. Open a pull request that explains the motivation and behavior changes.

Bug reports and feature requests are welcome via GitHub issues.

## License

This package is available under the terms of the [MIT "Expat" License](LICENSE.md).
