# Server-side helpers for Protected Resource Metadata, Authorization Server metadata,
# middleware, token validation, and JWT access token issuance.

const DEFAULT_PRM_PATH = "/.well-known/oauth-protected-resource"
const DEFAULT_AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
"""
    DEFAULT_JWKS_PATH

Default URL path used when exposing a JWKS via [`register_jwks_endpoint!`](@ref)
or [`public_jwk`](@ref).
"""
const DEFAULT_JWKS_PATH = "/.well-known/jwks.json"
const DEFAULT_REALM = "protected"

normalize_string_vector(values::Nothing) = String[]
function normalize_string_vector(values)
    if values isa AbstractString
        return [String(values)]
    elseif values isa AbstractVector
        return [String(v) for v in values]
    else
        throw(ArgumentError("Expected string or array of strings"))
    end
end

function normalize_metadata_dict(data)
    dict = Dict{String,Any}()
    data === nothing && return dict
    for (k, v) in data
        dict[String(k)] = v
    end
    return dict
end

json_response(body; status::Integer=200) = HTTP.Response(status, HTTP.Headers(["Content-Type" => "application/json"]), JSON.json(body))

function json_no_store_response(body; status::Integer=200)
    headers = HTTP.Headers([
        "Content-Type" => "application/json",
        "Cache-Control" => "no-store",
        "Pragma" => "no-cache",
    ])
    return HTTP.Response(status, headers, JSON.json(body))
end

struct AuthorizationCredentials
    scheme::String
    token::String
end

function authorization_credentials(req::HTTP.Request)
    auth = HTTP.header(req.headers, "Authorization", "")
    isempty(auth) && return nothing
    parts = split(auth, ' ')
    length(parts) == 2 || return nothing
    return AuthorizationCredentials(String(parts[1]), String(parts[2]))
end

function bearer_token(req::HTTP.Request)
    creds = authorization_credentials(req)
    if creds !== nothing && ascii_lc_isequal(creds.scheme, "bearer")
        return creds.token
    end
    return ""
end

function parse_form_urlencoded(body_bytes)
    text = String(body_bytes)
    params = Dict{String,String}()
    for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?" * text))
        params[String(k)] = String(v)
    end
    return params
end

function request_body_bytes(req::HTTP.Request)
    if req.body isa Vector{UInt8}
        return req.body
    elseif req.body === nothing
        return UInt8[]
    else
        return Vector{UInt8}(codeunits(String(req.body)))
    end
end

function decode_form_component(component::AbstractString, field::AbstractString)
    normalized = replace(String(component), '+' => ' ')
    try
        return HTTP.unescapeuri(normalized)
    catch err
        throw(OAuthError(:invalid_request, "Invalid percent-encoding in $(field): $(err)"))
    end
end

function parse_parameter_pairs(text::AbstractString)
    pairs = Pair{String,String}[]
    isempty(text) && return pairs
    for segment in split(text, '&')
        isempty(segment) && continue
        key = segment
        value = ""
        idx = findfirst(==('='), segment)
        if idx !== nothing
            key = idx == 1 ? "" : segment[1:idx-1]
            value = idx == lastindex(segment) ? "" : segment[idx+1:end]
        end
        decoded_key = decode_form_component(key, "parameter key")
        decoded_value = decode_form_component(value, decoded_key)
        push!(pairs, decoded_key => decoded_value)
    end
    return pairs
end

function request_param_pairs(req::HTTP.Request)
    pairs = Pair{String,String}[]
    target = String(req.target)
    uri = try
        HTTP.URI(target)
    catch
        HTTP.URI("/" * target)
    end
    query = String(uri.query)
    if !isempty(query)
        append!(pairs, parse_parameter_pairs(query))
    end
    if HTTP.method(req) == "POST"
        content_type = lowercase(String(HTTP.header(req.headers, "Content-Type", "")))
        if startswith(content_type, "application/x-www-form-urlencoded")
            body = request_body_bytes(req)
            append!(pairs, parse_parameter_pairs(String(body)))
        end
    end
    return pairs
end

function last_value_dict(pairs::Vector{Pair{String,String}})
    dict = Dict{String,String}()
    for (k, v) in pairs
        dict[k] = v
    end
    return dict
end

function multi_value_dict(pairs::Vector{Pair{String,String}})
    dict = Dict{String,Vector{String}}()
    for (k, v) in pairs
        values = get!(dict, k, String[])
        push!(values, v)
    end
    return dict
end

function encode_query_pairs(pairs::Vector{Pair{String,String}})
    isempty(pairs) && return ""
    parts = String[]
    for (k, v) in pairs
        push!(parts, escape_pair(String(k) => String(v)))
    end
    return join(parts, '&')
end

function append_query_params(url::AbstractString, params::Vector{Pair{String,String}})
    isempty(params) && return String(url)
    query = encode_query_pairs(params)
    base = String(url)
    fragment_idx = findfirst('#', base)
    prefix = fragment_idx === nothing ? base : base[1:fragment_idx-1]
    fragment = fragment_idx === nothing ? "" : base[fragment_idx:end]
    separator = if occursin('?', prefix)
        endswith(prefix, '?') || endswith(prefix, '&') ? "" : "&"
    else
        "?"
    end
    return string(prefix, separator, query, fragment)
end

const UNIX_EPOCH = DateTime(1970, 1, 1, 0, 0, 0)

datetime_to_unix(dt::DateTime) = Dates.value(dt - UNIX_EPOCH) ÷ 1000

"""
    ProtectedResourceConfig

Declarative description of a protected resource that you expose from your
own server.  You can register it with [`register_protected_resource_metadata!`](@ref)
to serve RFC 8414 metadata without manually building JSON.
"""
struct ProtectedResourceConfig
    resource::Union{String,Nothing}
    authorization_servers::Vector{String}
    scopes_supported::Vector{String}
    metadata::Dict{String,Any}
    path::String
end

function ensure_metadata_url(value, field::AbstractString)
    ensure_https_url(String(value), field; allow_loopback=true)
    return String(value)
end

"""
    ProtectedResourceConfig(; resource=nothing, authorization_servers, scopes_supported=[], resource_documentation=nothing, resource_registration_endpoint=nothing, extra=nothing, path=DEFAULT_PRM_PATH)

Validates URLs, normalizes string inputs, and builds a metadata document
ready to publish.
"""
function ProtectedResourceConfig(; resource=nothing, authorization_servers, scopes_supported=String[], resource_documentation=nothing, resource_registration_endpoint=nothing, extra=nothing, path::AbstractString=DEFAULT_PRM_PATH)
    authz = normalize_string_vector(authorization_servers)
    isempty(authz) && throw(ArgumentError("authorization_servers must not be empty"))
    authz = [ensure_metadata_url(url, "ProtectedResourceConfig.authorization_servers") for url in authz]
    scopes = normalize_string_vector(scopes_supported)
    metadata = normalize_metadata_dict(extra)
    if resource !== nothing
        resource = ensure_metadata_url(resource, "ProtectedResourceConfig.resource")
        metadata["resource"] = resource
    end
    metadata["authorization_servers"] = authz
    !isempty(scopes) && (metadata["scopes_supported"] = scopes)
    resource_documentation !== nothing && (metadata["resource_documentation"] = ensure_metadata_url(resource_documentation, "ProtectedResourceConfig.resource_documentation"))
    resource_registration_endpoint !== nothing && (metadata["resource_registration_endpoint"] = ensure_metadata_url(resource_registration_endpoint, "ProtectedResourceConfig.resource_registration_endpoint"))
    return ProtectedResourceConfig(resource === nothing ? nothing : resource, authz, scopes, metadata, ensure_slash(path))
end

protected_resource_document(config::ProtectedResourceConfig) = copy(config.metadata)

"""
    register_protected_resource_metadata!(router, config; path=config.path) -> Function

Registers an HTTP GET handler on the provided `router` that serves the JSON
representation of `config`.  Returns the handler function so you can
deregister it later if needed.
"""
function register_protected_resource_metadata!(router::HTTP.Router, config::ProtectedResourceConfig; path::AbstractString=config.path)
    handler = _ -> json_response(protected_resource_document(config))
    HTTP.register!(router, "GET", ensure_slash(path), handler)
    return handler
end

"""
    AuthorizationServerConfig

Server-side counterpart to [`AuthorizationServerMetadata`](@ref).  Populate
the fields your authorization server supports and serve them through
[`register_authorization_server_metadata!`](@ref).
"""
struct AuthorizationServerConfig
    issuer::String
    authorization_endpoint::Union{String,Nothing}
    token_endpoint::Union{String,Nothing}
    jwks_uri::Union{String,Nothing}
    device_authorization_endpoint::Union{String,Nothing}
    introspection_endpoint::Union{String,Nothing}
    revocation_endpoint::Union{String,Nothing}
    pushed_authorization_request_endpoint::Union{String,Nothing}
    backchannel_authentication_endpoint::Union{String,Nothing}
    end_session_endpoint::Union{String,Nothing}
    registration_endpoint::Union{String,Nothing}
    response_types_supported::Vector{String}
    grant_types_supported::Vector{String}
    code_challenge_methods_supported::Vector{String}
    token_endpoint_auth_methods_supported::Vector{String}
    token_endpoint_auth_signing_alg_values_supported::Vector{String}
    scopes_supported::Vector{String}
    request_object_signing_alg_values_supported::Vector{String}
    request_parameter_supported::Union{Bool,Nothing}
    request_uri_parameter_supported::Union{Bool,Nothing}
    require_pushed_authorization_requests::Union{Bool,Nothing}
    mtls_endpoint_aliases::Dict{String,String}
    authorization_response_iss_parameter_supported::Union{Bool,Nothing}
    metadata::Dict{String,Any}
    path::String
end

"""
    AuthorizationServerConfig(; issuer, authorization_endpoint=nothing, token_endpoint=nothing, ... , path=DEFAULT_AS_METADATA_PATH)

Keyword constructor that enforces HTTPS on every endpoint URL and allows
you to attach arbitrary extra metadata via `extra`.
"""
function AuthorizationServerConfig(; issuer, authorization_endpoint=nothing, token_endpoint=nothing, jwks_uri=nothing, device_authorization_endpoint=nothing, introspection_endpoint=nothing, revocation_endpoint=nothing, pushed_authorization_request_endpoint=nothing, backchannel_authentication_endpoint=nothing, end_session_endpoint=nothing, registration_endpoint=nothing, response_types_supported=String[], grant_types_supported=String[], code_challenge_methods_supported=String[], token_endpoint_auth_methods_supported=String[], token_endpoint_auth_signing_alg_values_supported=String[], scopes_supported=String[], request_object_signing_alg_values_supported=String[], request_parameter_supported=nothing, request_uri_parameter_supported=nothing, require_pushed_authorization_requests=nothing, mtls_endpoint_aliases=nothing, authorization_response_iss_parameter_supported=nothing, extra=nothing, path::AbstractString=DEFAULT_AS_METADATA_PATH)
    metadata = normalize_metadata_dict(extra)
    issuer_string = ensure_metadata_url(issuer, "AuthorizationServerConfig.issuer")
    metadata["issuer"] = issuer_string
    authorization_endpoint = authorization_endpoint === nothing ? nothing : ensure_metadata_url(authorization_endpoint, "AuthorizationServerConfig.authorization_endpoint")
    token_endpoint = token_endpoint === nothing ? nothing : ensure_metadata_url(token_endpoint, "AuthorizationServerConfig.token_endpoint")
    jwks_uri = jwks_uri === nothing ? nothing : ensure_metadata_url(jwks_uri, "AuthorizationServerConfig.jwks_uri")
    device_authorization_endpoint = device_authorization_endpoint === nothing ? nothing : ensure_metadata_url(device_authorization_endpoint, "AuthorizationServerConfig.device_authorization_endpoint")
    introspection_endpoint = introspection_endpoint === nothing ? nothing : ensure_metadata_url(introspection_endpoint, "AuthorizationServerConfig.introspection_endpoint")
    revocation_endpoint = revocation_endpoint === nothing ? nothing : ensure_metadata_url(revocation_endpoint, "AuthorizationServerConfig.revocation_endpoint")
    pushed_authorization_request_endpoint = pushed_authorization_request_endpoint === nothing ? nothing : ensure_metadata_url(pushed_authorization_request_endpoint, "AuthorizationServerConfig.pushed_authorization_request_endpoint")
    backchannel_authentication_endpoint = backchannel_authentication_endpoint === nothing ? nothing : ensure_metadata_url(backchannel_authentication_endpoint, "AuthorizationServerConfig.backchannel_authentication_endpoint")
    end_session_endpoint = end_session_endpoint === nothing ? nothing : ensure_metadata_url(end_session_endpoint, "AuthorizationServerConfig.end_session_endpoint")
    registration_endpoint = registration_endpoint === nothing ? nothing : ensure_metadata_url(registration_endpoint, "AuthorizationServerConfig.registration_endpoint")
    for (key, value) in (
        ("authorization_endpoint", authorization_endpoint),
        ("token_endpoint", token_endpoint),
        ("jwks_uri", jwks_uri),
        ("device_authorization_endpoint", device_authorization_endpoint),
        ("introspection_endpoint", introspection_endpoint),
        ("revocation_endpoint", revocation_endpoint),
        ("pushed_authorization_request_endpoint", pushed_authorization_request_endpoint),
        ("backchannel_authentication_endpoint", backchannel_authentication_endpoint),
        ("end_session_endpoint", end_session_endpoint),
        ("registration_endpoint", registration_endpoint),
    )
        value === nothing || (metadata[key] = value)
    end
    !isempty(response_types_supported) && (metadata["response_types_supported"] = normalize_string_vector(response_types_supported))
    !isempty(grant_types_supported) && (metadata["grant_types_supported"] = normalize_string_vector(grant_types_supported))
    !isempty(code_challenge_methods_supported) && (metadata["code_challenge_methods_supported"] = normalize_string_vector(code_challenge_methods_supported))
    !isempty(token_endpoint_auth_methods_supported) && (metadata["token_endpoint_auth_methods_supported"] = normalize_string_vector(token_endpoint_auth_methods_supported))
    !isempty(token_endpoint_auth_signing_alg_values_supported) && (metadata["token_endpoint_auth_signing_alg_values_supported"] = normalize_string_vector(token_endpoint_auth_signing_alg_values_supported))
    !isempty(scopes_supported) && (metadata["scopes_supported"] = normalize_string_vector(scopes_supported))
    !isempty(request_object_signing_alg_values_supported) && (metadata["request_object_signing_alg_values_supported"] = normalize_string_vector(request_object_signing_alg_values_supported))
    request_parameter_supported !== nothing && (metadata["request_parameter_supported"] = Bool(request_parameter_supported))
    request_uri_parameter_supported !== nothing && (metadata["request_uri_parameter_supported"] = Bool(request_uri_parameter_supported))
    require_pushed_authorization_requests !== nothing && (metadata["require_pushed_authorization_requests"] = Bool(require_pushed_authorization_requests))
    alias_dict = Dict{String,String}()
    if mtls_endpoint_aliases !== nothing
        for (k, v) in mtls_endpoint_aliases
            k isa AbstractString || continue
            v isa AbstractString || continue
            alias_dict[String(k)] = ensure_metadata_url(v, "AuthorizationServerConfig.mtls_endpoint_aliases.$k")
        end
        !isempty(alias_dict) && (metadata["mtls_endpoint_aliases"] = alias_dict)
    end
    if authorization_response_iss_parameter_supported !== nothing
        metadata["authorization_response_iss_parameter_supported"] = Bool(authorization_response_iss_parameter_supported)
    end
    return AuthorizationServerConfig(
        issuer_string,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        device_authorization_endpoint,
        introspection_endpoint,
        revocation_endpoint,
        pushed_authorization_request_endpoint,
        backchannel_authentication_endpoint,
        end_session_endpoint,
        registration_endpoint,
        normalize_string_vector(response_types_supported),
        normalize_string_vector(grant_types_supported),
        normalize_string_vector(code_challenge_methods_supported),
        normalize_string_vector(token_endpoint_auth_methods_supported),
        normalize_string_vector(token_endpoint_auth_signing_alg_values_supported),
        normalize_string_vector(scopes_supported),
        normalize_string_vector(request_object_signing_alg_values_supported),
        request_parameter_supported === nothing ? nothing : Bool(request_parameter_supported),
        request_uri_parameter_supported === nothing ? nothing : Bool(request_uri_parameter_supported),
        require_pushed_authorization_requests === nothing ? nothing : Bool(require_pushed_authorization_requests),
        alias_dict,
        authorization_response_iss_parameter_supported === nothing ? nothing : Bool(authorization_response_iss_parameter_supported),
        metadata,
        ensure_slash(path),
    )
end

"""
    register_authorization_server_metadata!(router, config; path=config.path) -> Function

Adds a GET endpoint to `router` that returns the authorization server
metadata JSON derived from `config`.
"""
function register_authorization_server_metadata!(router::HTTP.Router, config::AuthorizationServerConfig; path::AbstractString=config.path)
    handler = _ -> json_response(config.metadata)
    HTTP.register!(router, "GET", ensure_slash(path), handler)
    return handler
end

"""
    register_jwks_endpoint!(router, keys; path=DEFAULT_JWKS_PATH) -> Function

Publishes a JSON Web Key Set generated from the objects in `keys`.  Each
element can already be a dictionary or a struct with stringifiable fields.
"""
function register_jwks_endpoint!(router::HTTP.Router, keys; path::AbstractString=DEFAULT_JWKS_PATH)
    key_docs = Vector{Dict{String,Any}}()
    for key in keys
        doc = Dict{String,Any}()
        for (k, v) in key
            doc[String(k)] = v
        end
        push!(key_docs, doc)
    end
    handler = _ -> json_response(Dict("keys" => key_docs))
    HTTP.register!(router, "GET", ensure_slash(path), handler)
    return handler
end

"""
    JWTAccessTokenIssuer

Holds the signing material and metadata required to mint JWT access tokens
for your resource server.  Combine with [`issue_access_token`](@ref) and
[`public_jwk`](@ref) to build your own auth server in a few lines.
"""
mutable struct JWTAccessTokenIssuer
    issuer::String
    audience::Vector{String}
    signer::JWTSigner
    alg::Symbol
    kid::Union{String,Nothing}
    expires_in::Int
    public_jwk::Union{Dict{String,Any},Nothing}
end

"""
    JWTAccessTokenIssuer(; issuer, audience, private_key, alg=:RS256, kid=nothing, expires_in=3600, public_jwk=nothing)

Loads the provided private key, deduces the right signer type, derives the
public JWK (unless you supply one), and stores other helpful metadata.
"""
function JWTAccessTokenIssuer(; issuer, audience, private_key, alg::Union{Symbol,AbstractString}=:RS256, kid=nothing, expires_in::Integer=3600, public_jwk=nothing)
    alg_symbol = Symbol(uppercase(String(alg)))
    signer = if alg_symbol in SUPPORTED_RSA_ALGS
        rsa_signer_from_bytes(private_key)
    elseif alg_symbol in SUPPORTED_EC_ALGS
        curve = alg_symbol == :ES256 ? :P256 : :P384
        ecc_signer_from_bytes(private_key, curve)
    elseif alg_symbol in SUPPORTED_OKP_ALGS
        eddsa_signer_from_bytes(private_key)
    else
        throw(ArgumentError("Unsupported signing alg $(alg_symbol)"))
    end
    aud = normalize_string_vector(audience)
    kid_value = maybe_string(kid)
    jwk_dict = public_jwk === nothing ? derive_signing_jwk(private_key, signer, alg_symbol, kid_value) : normalize_metadata_dict(public_jwk)
    return JWTAccessTokenIssuer(String(issuer), aud, signer, alg_symbol, kid_value, Int(expires_in), jwk_dict)
end

"""
    AccessTokenStore

Abstract storage backend for bearer tokens that you issue via the server
helpers.  Implementors persist/retrieve arbitrary dictionaries keyed by a
token string.
"""
abstract type AccessTokenStore end

"""
    IssuedAccessToken

Internal record returned by [`issue_access_token`](@ref) that includes the
serialized token plus the claims used to create it.
"""
struct IssuedAccessToken
    token::String
    claims::Dict{String,Any}
    scope::Vector{String}
    issued_at::DateTime
    expires_at::DateTime
    client_id::Union{String,Nothing}
    subject::Union{String,Nothing}
    confirmation_jkt::Union{String,Nothing}
end

function token_audience(issuer::JWTAccessTokenIssuer, audience)
    aud = audience === nothing ? issuer.audience : normalize_string_vector(audience)
    return length(aud) == 1 ? aud[1] : aud
end

"""
    issue_access_token(issuer; subject=nothing, client_id=nothing, scope=[], authorization_details=nothing, extra_claims=Dict(), audience=nothing, now=Dates.now(UTC), store=nothing, confirmation=nothing, confirmation_jkt=nothing) -> IssuedAccessToken

Signs a JWT access token using the supplied [`JWTAccessTokenIssuer`](@ref)
and optionally records it in an [`AccessTokenStore`](@ref) for later
introspection or revocation checks.  Set `confirmation` / `confirmation_jkt`
to embed DPoP confirmation claims.
"""
function issue_access_token(issuer::JWTAccessTokenIssuer; subject=nothing, client_id=nothing, scope=String[], authorization_details=nothing, extra_claims=Dict{String,Any}(), audience=nothing, now::DateTime=Dates.now(UTC), store::Union{Nothing,AccessTokenStore}=nothing, confirmation=nothing, confirmation_jkt=nothing)
    expires_at = now + Dates.Second(issuer.expires_in)
    claims = Dict{String,Any}(
        "iss" => issuer.issuer,
        "aud" => token_audience(issuer, audience),
        "exp" => datetime_to_unix(expires_at),
        "iat" => datetime_to_unix(now),
    )
    subject !== nothing && (claims["sub"] = String(subject))
    client_id !== nothing && (claims["client_id"] = String(client_id))
    !isempty(scope) && (claims["scope"] = join(String.(scope), ' '))
    authorization_details !== nothing && (claims["authorization_details"] = authorization_details)
    for (k, v) in extra_claims
        claims[String(k)] = v
    end
    claims["jti"] = random_state()
    cnf_claim = nothing
    if confirmation !== nothing
        cnf_claim = Dict{String,Any}()
        for (k, v) in confirmation
            cnf_claim[String(k)] = v
        end
    end
    if confirmation_jkt !== nothing
        cnf_claim = cnf_claim === nothing ? Dict{String,Any}() : cnf_claim
        cnf_claim["jkt"] = String(confirmation_jkt)
    end
    cnf_thumbprint = nothing
    if cnf_claim !== nothing
        claims["cnf"] = cnf_claim
        value = get(cnf_claim, "jkt", nothing)
        cnf_thumbprint = value isa AbstractString ? String(value) : nothing
    end
    header = Dict{String,Any}("typ" => "JWT")
    issuer.kid !== nothing && (header["kid"] = issuer.kid)
    token = build_jws_compact(header, claims, issuer.signer, issuer.alg)
    issued = IssuedAccessToken(token, claims, normalize_string_vector(scope), now, expires_at, client_id === nothing ? nothing : String(client_id), subject === nothing ? nothing : String(subject), cnf_thumbprint)
    store === nothing || store_access_token!(store, issued)
    return issued
end

function ensure_public_jwk!(issuer::JWTAccessTokenIssuer)
    issuer.public_jwk === nothing && error("JWT access token issuer is missing a public JWK")
    return issuer.public_jwk
end

"""
    public_jwk(issuer::JWTAccessTokenIssuer) -> Dict{String,Any}

Returns (and memoizes) the public JWK derived from the issuer’s private key
so you can publish it via [`register_jwks_endpoint!`](@ref).
"""
public_jwk(issuer::JWTAccessTokenIssuer) = ensure_public_jwk!(issuer)

token_alg_string(alg::Symbol) = alg == :EDDSA ? "EdDSA" : String(alg)

function derive_signing_jwk(private_key, signer::RSASigner, alg::Symbol, kid::Union{String,Nothing})
    modulus, exponent = rsa_public_components_from_private_bytes(private_key)
    jwk = Dict(
        "kty" => "RSA",
        "n" => base64urlencode(modulus),
        "e" => base64urlencode(exponent),
        "alg" => token_alg_string(alg),
        "use" => "sig",
    )
    kid !== nothing && (jwk["kid"] = kid)
    return jwk
end

function derive_signing_jwk(_private_key, signer::ECSigner, alg::Symbol, kid::Union{String,Nothing})
    x, y = ecc_public_coordinates(signer)
    jwk = Dict(
        "kty" => "EC",
        "crv" => signer.curve == :P256 ? "P-256" : "P-384",
        "x" => base64urlencode(x),
        "y" => base64urlencode(y),
        "alg" => token_alg_string(alg),
        "use" => "sig",
    )
    kid !== nothing && (jwk["kid"] = kid)
    return jwk
end

function derive_signing_jwk(_private_key, signer::EdDSASigner, alg::Symbol, kid::Union{String,Nothing})
    jwk = Dict(
        "kty" => "OKP",
        "crv" => "Ed25519",
        "x" => base64urlencode(signer.public),
        "alg" => token_alg_string(alg),
        "use" => "sig",
    )
    kid !== nothing && (jwk["kid"] = kid)
    return jwk
end

mutable struct AccessTokenRecord
    token::String
    scope::Vector{String}
    issued_at::DateTime
    expires_at::DateTime
    client_id::Union{String,Nothing}
    subject::Union{String,Nothing}
    claims::Dict{String,Any}
    revoked::Bool
    confirmation_jkt::Union{String,Nothing}
end

"""
    DPoPReplayCache

Tracks recently seen DPoP JWT IDs so you can reject replays at the token
endpoint or protected resource.  Thread-safe via a `ReentrantLock`.
"""
mutable struct DPoPReplayCache
    lock::ReentrantLock
    entries::Dict{String,DateTime}
    window::Dates.Second
end

"""
    DPoPReplayCache(; window_seconds=300)

Creates a replay cache that expires entries after `window_seconds`.
"""
function DPoPReplayCache(; window_seconds::Integer=300)
    window_seconds > 0 || throw(ArgumentError("window_seconds must be positive"))
    return DPoPReplayCache(ReentrantLock(), Dict{String,DateTime}(), Dates.Second(window_seconds))
end

function cleanup_replay_cache!(cache::DPoPReplayCache, now::DateTime)
    threshold = now - cache.window
    expired = String[]
    for (jti, timestamp) in cache.entries
        timestamp < threshold && push!(expired, jti)
    end
    for jti in expired
        delete!(cache.entries, jti)
    end
end

function record_dpop_proof!(cache::DPoPReplayCache, jti::AbstractString, now::DateTime)
    lock(cache.lock) do
        cleanup_replay_cache!(cache, now)
        key = String(jti)
        if haskey(cache.entries, key)
            return false
        end
        cache.entries[key] = now
        return true
    end
end

"""
    InMemoryTokenStore()

Simple dictionary-backed implementation of [`AccessTokenStore`](@ref).  Best
suited for tests or single-process resource servers.
"""
mutable struct InMemoryTokenStore <: AccessTokenStore
    lock::ReentrantLock
    records::Dict{String,AccessTokenRecord}
end

InMemoryTokenStore() = InMemoryTokenStore(ReentrantLock(), Dict{String,AccessTokenRecord}())

"""
    store_access_token!(store::AccessTokenStore, issued::IssuedAccessToken)

Persists an issued token into the backing store so later introspection or
revocation checks can find it.
"""
function store_access_token!(store::InMemoryTokenStore, issued::IssuedAccessToken)
    record = AccessTokenRecord(
        issued.token,
        copy(issued.scope),
        issued.issued_at,
        issued.expires_at,
        issued.client_id,
        issued.subject,
        Dict{String,Any}(issued.claims),
        false,
        issued.confirmation_jkt,
    )
    lock(store.lock) do
        store.records[issued.token] = record
    end
    return record
end

"""
    lookup_access_token(store::AccessTokenStore, token::AbstractString) -> Union{IssuedAccessToken,Nothing}

Fetches a previously stored token record or returns `nothing` if the token
is unknown (or revoked).
"""
function lookup_access_token(store::InMemoryTokenStore, token::AbstractString)
    lock(store.lock) do
        return get(store.records, String(token), nothing)
    end
end

"""
    revoke_access_token!(store::AccessTokenStore, token::AbstractString)

Removes a token from the store so future introspection attempts consider it
invalid.
"""
function revoke_access_token!(store::InMemoryTokenStore, token::AbstractString)
    lock(store.lock) do
        record = get(store.records, String(token), nothing)
        record === nothing && return false
        record.revoked = true
        return true
    end
end

"""
    AuthorizationCodeStore

Storage interface for authorization codes generated by the embedded AS.
"""
abstract type AuthorizationCodeStore end

"""
    AuthorizationCodeRecord

Internal struct that captures everything needed to validate an
authorization code (scope, PKCE challenge, expiration, etc.).
"""
struct AuthorizationCodeRecord
    code::String
    client_id::String
    redirect_uri::String
    scope::Vector{String}
    subject::Union{String,Nothing}
    code_challenge::Union{String,Nothing}
    code_challenge_method::Union{String,Nothing}
    issued_at::DateTime
    expires_at::DateTime
    authorization_details::Union{Nothing,Any}
    resource::Vector{String}
    extra_claims::Dict{String,Any}
end

"""In-memory implementation of [`AuthorizationCodeStore`](@ref)."""
mutable struct InMemoryAuthorizationCodeStore <: AuthorizationCodeStore
    lock::ReentrantLock
    records::Dict{String,AuthorizationCodeRecord}
end

InMemoryAuthorizationCodeStore() = InMemoryAuthorizationCodeStore(ReentrantLock(), Dict{String,AuthorizationCodeRecord}())

"""
    store_authorization_code!(store::AuthorizationCodeStore, record)

Persists an authorization code until it is redeemed or expires.
"""
function store_authorization_code!(store::InMemoryAuthorizationCodeStore, record::AuthorizationCodeRecord)
    lock(store.lock) do
        store.records[record.code] = record
    end
    return record
end

"""
    consume_authorization_code!(store::AuthorizationCodeStore, code) -> Union{AuthorizationCodeRecord,Nothing}

Atomically removes the specified code and returns its record so grant
handlers can mint tokens.
"""
function consume_authorization_code!(store::InMemoryAuthorizationCodeStore, code::AbstractString)
    lock(store.lock) do
        return pop!(store.records, String(code), nothing)
    end
end

"""
    AuthorizationRequestContext

Data passed to your `consent_handler` inside `build_authorization_endpoint`.
Contains the client’s requested redirect URI, scope, PKCE challenge, and
raw request params.
"""
Base.@kwdef struct AuthorizationRequestContext
    client_id::String
    redirect_uri::String
    scope::Vector{String}
    state::Union{String,Nothing}
    code_challenge::Union{String,Nothing}
    code_challenge_method::Union{String,Nothing}
    resource::Vector{String}
    authorization_details::Union{Nothing,Any}
    response_type::String
    params::Dict{String,String}
end

"""
    AuthorizationGrantDecision

Return value from your consent handler that indicates whether the user
granted the request and which scopes/resources were approved.
"""
Base.@kwdef struct AuthorizationGrantDecision
    approved::Bool = true
    subject::Union{String,Nothing} = nothing
    scope::Vector{String} = String[]
    resource::Vector{String} = String[]
    authorization_details::Union{Nothing,Any} = nothing
    extra_params::Dict{String,String} = Dict{String,String}()
    extra_claims::Dict{String,Any} = Dict{String,Any}()
    error::Union{String,Nothing} = nothing
    error_description::Union{String,Nothing} = nothing
end

"""
    grant_authorization(subject; scope=String[], resource=String[], authorization_details=nothing, extra_params=Dict(), extra_claims=Dict()) -> AuthorizationGrantDecision

Helper to build the affirmative variant of [`AuthorizationGrantDecision`](@ref).
"""
function grant_authorization(subject::Union{String,Nothing}; scope=String[], resource=String[], authorization_details=nothing, extra_params=Dict{String,String}(), extra_claims=Dict{String,Any}())
    return AuthorizationGrantDecision(
        approved = true,
        subject = subject === nothing ? nothing : String(subject),
        scope = [String(s) for s in scope],
        resource = [String(r) for r in resource],
        authorization_details = authorization_details,
        extra_params = Dict{String,String}(extra_params),
        extra_claims = Dict{String,Any}(extra_claims),
    )
end

"""
    deny_authorization(; error=\"access_denied\", description=nothing) -> AuthorizationGrantDecision

Convenience constructor for negative decisions with an OAuth error payload.
"""
function deny_authorization(; error::AbstractString="access_denied", description=nothing)
    return AuthorizationGrantDecision(
        approved = false,
        error = String(error),
        error_description = description === nothing ? nothing : String(description),
    )
end

"""
    AuthorizationEndpointConfig

Aggregates everything the built-in authorization endpoint needs: a store,
redirect URI resolver, consent handler, and code TTL.
"""
struct AuthorizationEndpointConfig{S<:AuthorizationCodeStore,R<:Function,C<:Function}
    code_store::S
    redirect_uri_resolver::R
    consent_handler::C
    code_ttl::Dates.Second
end

"""
    AuthorizationEndpointConfig(; code_store, redirect_uri_resolver, consent_handler, code_ttl_seconds=600)

Validates inputs and returns a ready-to-use configuration for
[`build_authorization_endpoint`](@ref).
"""
function AuthorizationEndpointConfig(; code_store, redirect_uri_resolver, consent_handler, code_ttl_seconds::Integer=600)
    code_store isa AuthorizationCodeStore || throw(ArgumentError("code_store must implement AuthorizationCodeStore"))
    redirect_uri_resolver isa Function || throw(ArgumentError("redirect_uri_resolver must be callable"))
    consent_handler isa Function || throw(ArgumentError("consent_handler must be callable"))
    code_ttl_seconds > 0 || throw(ArgumentError("code_ttl_seconds must be positive"))
    return AuthorizationEndpointConfig(code_store, redirect_uri_resolver, consent_handler, Dates.Second(code_ttl_seconds))
end

"""
    TokenEndpointClient

Represents the authenticated client hitting your token endpoint.  Contains
its `client_id` and whether it’s a public client.
"""
struct TokenEndpointClient
    client_id::String
    public::Bool
end

"""Normalizes inputs before building a `TokenEndpointClient`."""
TokenEndpointClient(client_id::AbstractString; public::Bool=false) = TokenEndpointClient(String(client_id), Bool(public))

"""
    TokenEndpointConfig

Holds everything the built-in token endpoint needs: the authorization code
store, token issuer, client authenticator, refresh token generator, extra
claims callback, optional persistent token store, and allowed grant types.
"""
struct TokenEndpointConfig{S<:AuthorizationCodeStore,C<:Function,R<:Function,E<:Function}
    code_store::S
    token_issuer::JWTAccessTokenIssuer
    client_authenticator::C
    refresh_token_generator::R
    extra_token_claims::E
    token_store::Union{AccessTokenStore,Nothing}
    allowed_grant_types::Set{String}
end

"""
    TokenEndpointConfig(; code_store, token_issuer, client_authenticator, token_store=nothing, refresh_token_generator=nothing, extra_token_claims=nothing, allowed_grant_types=[\"authorization_code\"])

Validates and normalizes the callbacks before handing the struct to
[`build_token_endpoint`](@ref).
"""
function TokenEndpointConfig(; code_store, token_issuer, client_authenticator, token_store::Union{AccessTokenStore,Nothing}=nothing, refresh_token_generator=nothing, extra_token_claims=nothing, allowed_grant_types=["authorization_code"])
    code_store isa AuthorizationCodeStore || throw(ArgumentError("code_store must implement AuthorizationCodeStore"))
    token_issuer isa JWTAccessTokenIssuer || throw(ArgumentError("token_issuer must be a JWTAccessTokenIssuer"))
    client_authenticator isa Function || throw(ArgumentError("client_authenticator must be callable"))
    refresh_fn = refresh_token_generator === nothing ? (_record, _client) -> nothing : refresh_token_generator
    extra_fn = extra_token_claims === nothing ? (_record, _client) -> Dict{String,Any}() : extra_token_claims
    allowed = Set(lowercase.(String.(allowed_grant_types)))
    isempty(allowed) && throw(ArgumentError("allowed_grant_types must not be empty"))
    return TokenEndpointConfig(code_store, token_issuer, client_authenticator, refresh_fn, extra_fn, token_store, allowed)
end

"""
    client_credentials_authenticator(credentials; allow_public=false) -> Function

Builds a helper that authenticates token endpoint requests using a lookup
table of `client_id => client_secret`.  When `allow_public=true` the
authenticator accepts clients that omit credentials, which is useful when
you support both public and confidential apps on the same endpoint.
"""
function client_credentials_authenticator(credentials; allow_public::Bool=false)
    normalized = Dict{String,String}()
    for (k, v) in credentials
        normalized[String(k)] = String(v)
    end
    function authenticate(req::HTTP.Request, params::Dict{String,String})
        header = HTTP.header(req.headers, "Authorization", "")
        if startswith(header, "Basic ")
            encoded = header[7:end]
            decoded = try
                String(Base64.base64decode(encoded))
            catch err
                throw(OAuthError(:invalid_client, "Invalid Authorization header: $(err)"))
            end
            idx = findfirst(==(':'), decoded)
            idx === nothing && throw(OAuthError(:invalid_client, "Invalid Authorization credentials"))
            username = decoded[1:idx-1]
            password = decoded[idx+1:end]
            expected = get(normalized, username, nothing)
            expected === nothing && throw(OAuthError(:invalid_client, "Unknown client"))
            password == expected || throw(OAuthError(:invalid_client, "Invalid client secret"))
            return TokenEndpointClient(username; public=false)
        end
        client_id = get(params, "client_id", nothing)
        client_id === nothing && throw(OAuthError(:invalid_client, "client_id is required"))
        secret = get(params, "client_secret", nothing)
        if secret === nothing
            allow_public || throw(OAuthError(:invalid_client, "client_secret is required"))
            return TokenEndpointClient(client_id; public=true)
        end
        expected = get(normalized, client_id, nothing)
        expected === nothing && throw(OAuthError(:invalid_client, "Unknown client"))
        secret == expected || throw(OAuthError(:invalid_client, "Invalid client secret"))
        return TokenEndpointClient(client_id; public=false)
    end
    return authenticate
end

function authorization_error_response(message::AbstractString)
    return json_response(Dict("error" => "invalid_request", "error_description" => String(message)); status=400)
end

function authorization_redirect_response(redirect_uri::AbstractString, state::Union{String,Nothing}, params::Vector{Pair{String,String}})
    state === nothing || push!(params, "state" => String(state))
    location = append_query_params(redirect_uri, params)
    headers = HTTP.Headers([
        "Location" => location,
        "Cache-Control" => "no-store",
        "Pragma" => "no-cache",
    ])
    return HTTP.Response(302, headers, "")
end

function parse_scope_list(scope_value)
    scope_value === nothing && return String[]
    scopes = String[]
    for part in split(String(scope_value))
        isempty(part) && continue
        push!(scopes, String(part))
    end
    return scopes
end

function parse_authorization_details(raw_value, redirect_uri, state)
    raw_value === nothing && return nothing
    return try
        JSON.parse(String(raw_value))
    catch err
        authorization_redirect_response(redirect_uri, state, [ "error" => "invalid_request", "error_description" => "authorization_details must be valid JSON" ])
    end
end

"""
    build_authorization_endpoint(config::AuthorizationEndpointConfig) -> Function

Returns an HTTP handler that implements the OAuth 2.0 authorization
endpoint.  The handler enforces PKCE, calls your consent callback, and
stores issued codes in the configured store.
"""
function build_authorization_endpoint(config::AuthorizationEndpointConfig)
    function handler(req::HTTP.Request)
        method = HTTP.method(req)
        if !(method == "GET" || method == "POST")
            return HTTP.Response(405, HTTP.Headers(["Allow" => "GET, POST"]), "")
        end
        pairs = request_param_pairs(req)
        params = last_value_dict(pairs)
        multi = multi_value_dict(pairs)
        client_id = get(params, "client_id", nothing)
        client_id === nothing && return authorization_error_response("client_id is required")
        requested_redirect = get(params, "redirect_uri", nothing)
        redirect_uri = try
            config.redirect_uri_resolver(req, String(client_id), requested_redirect)
        catch err
            if err isa OAuthError
                return authorization_error_response(err.message)
            else
                rethrow()
            end
        end
        redirect_uri === nothing && return authorization_error_response("redirect_uri resolver returned nothing")
        redirect_uri = String(redirect_uri)
        state_value = get(params, "state", nothing)
        response_type = get(params, "response_type", nothing)
        response_type === nothing && return authorization_redirect_response(redirect_uri, state_value, ["error" => "invalid_request", "error_description" => "response_type is required"])
        lowercase(String(response_type)) == "code" || return authorization_redirect_response(redirect_uri, state_value, ["error" => "unsupported_response_type", "error_description" => "Only authorization_code flow is supported"])
        authz_details = parse_authorization_details(get(params, "authorization_details", nothing), redirect_uri, state_value)
        authz_details isa HTTP.Response && return authz_details
        code_challenge = get(params, "code_challenge", nothing)
        method_value = get(params, "code_challenge_method", nothing)
        code_challenge_method = if code_challenge === nothing
            nothing
        elseif method_value === nothing
            "PLAIN"
        else
            uppercase(String(method_value))
        end
        resources = get(multi, "resource", nothing)
        resource_values = resources === nothing ? String[] : [String(r) for r in resources if !isempty(r)]
        scope_values = parse_scope_list(get(params, "scope", nothing))
        ctx = AuthorizationRequestContext(
            client_id = String(client_id),
            redirect_uri = redirect_uri,
            scope = scope_values,
            state = state_value === nothing ? nothing : String(state_value),
            code_challenge = code_challenge === nothing ? nothing : String(code_challenge),
            code_challenge_method = code_challenge_method,
            resource = resource_values,
            authorization_details = authz_details,
            response_type = String(response_type),
            params = params,
        )
        decision = config.consent_handler(req, ctx)
        decision isa AuthorizationGrantDecision || throw(ArgumentError("consent_handler must return AuthorizationGrantDecision"))
        issued_at = Dates.now(UTC)
        if !decision.approved
            error_code = decision.error === nothing ? "access_denied" : String(decision.error)
            description = decision.error_description
            extra = ["error" => error_code]
            description === nothing || push!(extra, "error_description" => String(description))
            return authorization_redirect_response(ctx.redirect_uri, ctx.state, extra)
        end
        granted_scope = isempty(decision.scope) ? copy(ctx.scope) : [String(s) for s in decision.scope]
        granted_resource = isempty(decision.resource) ? copy(ctx.resource) : [String(r) for r in decision.resource]
        granted_details = decision.authorization_details === nothing ? ctx.authorization_details : decision.authorization_details
        extra_params = Dict{String,String}()
        for (k, v) in decision.extra_params
            extra_params[String(k)] = String(v)
        end
        extra_claims = Dict{String,Any}()
        extra_claims["auth_time"] = datetime_to_unix(issued_at)
        for (k, v) in decision.extra_claims
            extra_claims[String(k)] = v
        end
        code = random_state(bytes=32)
        record = AuthorizationCodeRecord(
            code,
            ctx.client_id,
            ctx.redirect_uri,
            granted_scope,
            decision.subject === nothing ? nothing : String(decision.subject),
            ctx.code_challenge,
            ctx.code_challenge_method,
            issued_at,
            issued_at + config.code_ttl,
            granted_details,
            granted_resource,
            extra_claims,
        )
        store_authorization_code!(config.code_store, record)
        redirect_params = Pair{String,String}["code" => code]
        if ctx.state !== nothing
            push!(redirect_params, "state" => ctx.state)
        end
        for (k, v) in extra_params
            push!(redirect_params, k => v)
        end
        return authorization_redirect_response(ctx.redirect_uri, nothing, redirect_params)
    end
    return handler
end

function token_error_response(code::AbstractString, description::Union{String,Nothing}; status::Integer=400, headers=HTTP.Headers())
    body = Dict{String,Any}("error" => String(code))
    description !== nothing && (body["error_description"] = String(description))
    response_headers = HTTP.Headers(headers)
    set_request_header!(response_headers, "Content-Type", "application/json")
    set_request_header!(response_headers, "Cache-Control", "no-store")
    set_request_header!(response_headers, "Pragma", "no-cache")
    return HTTP.Response(status, response_headers, JSON.json(body))
end

function verify_pkce(record::AuthorizationCodeRecord, verifier::AbstractString)
    method = record.code_challenge_method === nothing ? "PLAIN" : uppercase(String(record.code_challenge_method))
    method == "PLAIN" && return String(verifier) == record.code_challenge
    method == "S256" || throw(OAuthError(:invalid_grant, "Unsupported code_challenge_method $(method)"))
    challenge = try
        pkce_challenge(String(verifier))
    catch err
        throw(OAuthError(:invalid_grant, "Invalid code_verifier: $(err)"))
    end
    return challenge == record.code_challenge
end

function handle_authorization_code_grant(config::TokenEndpointConfig, req::HTTP.Request, params::Dict{String,String})
    code_value = get(params, "code", nothing)
    code_value === nothing && return token_error_response("invalid_request", "code is required")
    redirect_uri = get(params, "redirect_uri", nothing)
    redirect_uri === nothing && return token_error_response("invalid_request", "redirect_uri is required")
    client = try
        config.client_authenticator(req, params)
    catch err
        if err isa OAuthError
            if err.code == :invalid_client
                headers = HTTP.Headers(["WWW-Authenticate" => "Basic realm=\"token\""])
                return token_error_response("invalid_client", err.message; status=401, headers=headers)
            else
                return token_error_response(String(err.code), err.message)
            end
        else
            rethrow()
        end
    end
    client isa TokenEndpointClient || throw(ArgumentError("client_authenticator must return TokenEndpointClient"))
    record = consume_authorization_code!(config.code_store, code_value)
    record === nothing && return token_error_response("invalid_grant", "authorization code is invalid or has already been used")
    now_time = Dates.now(UTC)
    now_time > record.expires_at && return token_error_response("invalid_grant", "authorization code expired")
    record.client_id == client.client_id || return token_error_response("invalid_grant", "authorization code was issued to a different client")
    record.redirect_uri == String(redirect_uri) || return token_error_response("invalid_grant", "redirect_uri mismatch")
    if record.code_challenge !== nothing
        verifier = get(params, "code_verifier", nothing)
        verifier === nothing && return token_error_response("invalid_grant", "code_verifier is required")
        verify_pkce(record, verifier) || return token_error_response("invalid_grant", "code_verifier mismatch")
    end
    extra_claims = Dict{String,Any}()
    for (k, v) in record.extra_claims
        extra_claims[String(k)] = v
    end
    custom_claims = config.extra_token_claims(record, client)
    for (k, v) in custom_claims
        extra_claims[String(k)] = v
    end
    issued = issue_access_token(
        config.token_issuer;
        subject = record.subject,
        client_id = record.client_id,
        scope = record.scope,
        authorization_details = record.authorization_details,
        extra_claims = extra_claims,
        store = config.token_store,
    )
    response = Dict{String,Any}(
        "access_token" => issued.token,
        "token_type" => "Bearer",
        "expires_in" => config.token_issuer.expires_in,
    )
    !isempty(record.scope) && (response["scope"] = join(record.scope, ' '))
    record.authorization_details !== nothing && (response["authorization_details"] = record.authorization_details)
    !isempty(record.resource) && (response["resource"] = record.resource)
    refresh_token = config.refresh_token_generator(record, client)
    refresh_token === nothing || (response["refresh_token"] = String(refresh_token))
    headers = HTTP.Headers([
        "Content-Type" => "application/json",
        "Cache-Control" => "no-store",
        "Pragma" => "no-cache",
    ])
    return HTTP.Response(200, headers, JSON.json(response))
end

"""
    build_token_endpoint(config::TokenEndpointConfig) -> Function

Creates a handler that implements the OAuth 2.0 token endpoint for the
authorization_code grant.  It verifies client credentials, enforces PKCE,
issues JWT access tokens, and optionally persists refresh tokens.
"""
function build_token_endpoint(config::TokenEndpointConfig)
    function handler(req::HTTP.Request)
        HTTP.method(req) == "POST" || return HTTP.Response(405, HTTP.Headers(["Allow" => "POST"]), "")
        content_type = lowercase(String(HTTP.header(req.headers, "Content-Type", "")))
        startswith(content_type, "application/x-www-form-urlencoded") || return token_error_response("invalid_request", "Content-Type must be application/x-www-form-urlencoded")
        pairs = request_param_pairs(req)
        params = last_value_dict(pairs)
        grant_type = get(params, "grant_type", nothing)
        grant_type === nothing && return token_error_response("invalid_request", "grant_type is required")
        normalized_grant = lowercase(String(grant_type))
        normalized_grant in config.allowed_grant_types || return token_error_response("unsupported_grant_type", "Grant type $(grant_type) is not supported")
        if normalized_grant == "authorization_code"
            return handle_authorization_code_grant(config, req, params)
        else
            return token_error_response("unsupported_grant_type", "Grant type $(grant_type) is not supported")
        end
    end
    return handler
end

"""
    EndpointAuthenticator

Abstract interface for authenticating callers of management endpoints
(`introspection`, `revocation`, etc.).
"""
abstract type EndpointAuthenticator end

"""
    AllowAllAuthenticator()

Sentinel authenticator that accepts every request.
"""
struct AllowAllAuthenticator <: EndpointAuthenticator end

"""
    BasicCredentialsAuthenticator(; credentials, realm=\"oauth2\")

Validates HTTP Basic credentials for management endpoints.  Pass a
`Dict(\"client\" => \"secret\")` style table for quick setups.
"""
struct BasicCredentialsAuthenticator <: EndpointAuthenticator
    realm::String
    credentials::Dict{String,String}
end

"""
    BasicCredentialsAuthenticator(; credentials, realm=\"oauth2\")

Normalizes the provided credential table into strings and returns a
`BasicCredentialsAuthenticator`.
"""
function BasicCredentialsAuthenticator(; credentials, realm::AbstractString="oauth2")
    isempty(credentials) && throw(ArgumentError("credentials must not be empty"))
    dict = Dict{String,String}()
    for (k, v) in credentials
        dict[String(k)] = String(v)
    end
    return BasicCredentialsAuthenticator(String(realm), dict)
end

authenticate_request(::AllowAllAuthenticator, _req::HTTP.Request) = true
function authenticate_request(auth::BasicCredentialsAuthenticator, req::HTTP.Request)
    header = HTTP.header(req.headers, "Authorization", "")
    startswith(header, "Basic ") || return false
    encoded = header[7:end]
    decoded = try
        String(Base64.base64decode(encoded))
    catch
        return false
    end
    idx = findfirst(==(':'), decoded)
    idx === nothing && return false
    username = decoded[1:idx-1]
    password = decoded[idx+1:end]
    expected = get(auth.credentials, username, nothing)
    return expected !== nothing && expected == password
end

auth_challenge_headers(::AllowAllAuthenticator) = HTTP.Headers()
function auth_challenge_headers(auth::BasicCredentialsAuthenticator)
    header = "Basic realm=\"$(auth.realm)\", charset=\"UTF-8\""
    return HTTP.Headers(["WWW-Authenticate" => header])
end

function unauthorized_endpoint_response(authenticator::EndpointAuthenticator)
    headers = auth_challenge_headers(authenticator)
    return HTTP.Response(401, headers, "")
end

struct VerificationKey
    kid::Union{String,Nothing}
    alg::Union{Symbol,Nothing}
    use::Union{String,Nothing}
    kty::String
    verifier::JWTVerifier
end

function VerificationKey(; kid=nothing, alg=nothing, use=nothing, kty, verifier)
    kid_val = kid === nothing ? nothing : String(kid)
    alg_val = alg === nothing ? nothing : Symbol(alg)
    use_val = use === nothing ? nothing : String(use)
    return VerificationKey(kid_val, alg_val, use_val, String(kty), verifier)
end

"""
    TokenValidationConfig

Holds the knobs for JWT access token validation: a set of trusted issuers,
expected audience, acceptable algorithms, leeway, DPoP replay cache, etc.
Feed it to [`validate_jwt_access_token`](@ref).
"""
struct TokenValidationConfig
    issuer::String
    audience::Vector{String}
    allowed_algs::Set{Symbol}
    leeway::Dates.Second
    keys::Vector{VerificationKey}
end

"""
    AccessTokenClaims

Result of [`validate_jwt_access_token`](@ref).  Exposes common claims such
as `sub`, `aud`, `scope`, and DPoP confirmation digest.
"""
struct AccessTokenClaims
    token::String
    subject::Union{String,Nothing}
    client_id::Union{String,Nothing}
    scope::Vector{String}
    audience::Vector{String}
    expires_at::DateTime
    issued_at::Union{DateTime,Nothing}
    claims::Dict{String,Any}
    confirmation_jkt::Union{String,Nothing}
end

function AccessTokenClaims(; token, subject, client_id, scope, audience, expires_at, issued_at, claims, confirmation_jkt=nothing)
    return AccessTokenClaims(
        String(token),
        subject,
        client_id,
        scope,
        audience,
        expires_at,
        issued_at,
        claims,
        confirmation_jkt === nothing ? nothing : String(confirmation_jkt),
    )
end

function TokenValidationConfig(; issuer, audience, jwks, allowed_algs=(:RS256, :PS256, :ES256, :ES384, :EDDSA), leeway_seconds::Integer=60)
    aud = normalize_string_vector(audience)
    allowed = Set(Symbol.(allowed_algs))
    keys = build_verification_keys(jwks)
    isempty(keys) && throw(ArgumentError("jwks must contain at least one key"))
    return TokenValidationConfig(String(issuer), aud, allowed, Dates.Second(leeway_seconds), keys)
end

function build_verification_keys(jwks)
    key_entries = jwks isa AbstractDict ? (haskey(jwks, "keys") ? jwks["keys"] : jwks) : jwks
    key_entries isa AbstractVector || throw(ArgumentError("jwks must be a AbstractDict or AbstractVector"))
    keys = VerificationKey[]
    for item in key_entries
        kty = uppercase(String(item["kty"]))
        kid = haskey(item, "kid") ? String(item["kid"]) : nothing
        alg = haskey(item, "alg") ? Symbol(uppercase(String(item["alg"]))) : nothing
        use = haskey(item, "use") ? String(item["use"]) : nothing
        key_ops = get(item, "key_ops", nothing)
        enforce_signature_key_intent(use, key_ops, kid)
        verifier = if kty == "RSA"
            n = haskey(item, "n") ? base64urldecode(String(item["n"])) : error("RSA JWK missing modulus")
            e = haskey(item, "e") ? base64urldecode(String(item["e"])) : error("RSA JWK missing exponent")
            rsa_verifier_from_components(Vector{UInt8}(n), Vector{UInt8}(e))
        elseif kty == "EC"
            crv = haskey(item, "crv") ? String(item["crv"]) : error("EC JWK missing curve")
            curve = crv == "P-256" ? :P256 : crv == "P-384" ? :P384 : error("Unsupported EC curve $(crv)")
            x = haskey(item, "x") ? base64urldecode(String(item["x"])) : error("EC JWK missing x coordinate")
            y = haskey(item, "y") ? base64urldecode(String(item["y"])) : error("EC JWK missing y coordinate")
            ecc_verifier_from_coordinates(Vector{UInt8}(x), Vector{UInt8}(y), curve)
        elseif kty == "OKP"
            crv = haskey(item, "crv") ? String(item["crv"]) : error("OKP JWK missing curve")
            crv == "Ed25519" || error("Unsupported OKP curve $(crv)")
            x = haskey(item, "x") ? base64urldecode(String(item["x"])) : error("OKP JWK missing x coordinate")
            eddsa_verifier_from_bytes(Vector{UInt8}(x))
        else
            error("Unsupported JWK kty $(kty)")
        end
        push!(keys, VerificationKey(kid=kid, alg=alg, use=use, kty=kty, verifier=verifier))
    end
    return keys
end

function enforce_signature_key_intent(use::Union{String,Nothing}, key_ops, kid::Union{String,Nothing})
    label = kid === nothing ? "<unnamed>" : kid
    if use !== nothing && lowercase(String(use)) != "sig"
        throw(ArgumentError("JWK $(label) declares use=$(use) and cannot be used for signature verification"))
    end
    key_ops === nothing && return
    key_ops isa AbstractVector || throw(ArgumentError("JWK $(label) key_ops must be an array of strings"))
    ops = String[]
    for op in key_ops
        op isa AbstractString || continue
        push!(ops, lowercase(String(op)))
    end
    isempty(ops) && throw(ArgumentError("JWK $(label) key_ops must include verify"))
    "verify" in ops || throw(ArgumentError("JWK $(label) key_ops does not include verify"))
end

function select_verification_key(config::TokenValidationConfig, alg::Symbol, kid::Union{String,Nothing})
    for key in config.keys
        if kid !== nothing && key.kid !== nothing && key.kid != kid
            continue
        end
        if key.alg !== nothing && key.alg != alg
            continue
        end
        if (key.verifier isa RSAVerifier && alg in SUPPORTED_RSA_ALGS) ||
           (key.verifier isa ECVerifier && alg in SUPPORTED_EC_ALGS) ||
           (key.verifier isa EdDSAVerifier && alg in SUPPORTED_OKP_ALGS)
            return key
        end
    end
    throw(OAuthError(:invalid_token, "No matching verification key for alg $(alg)"))
end

function parse_audience(value)
    if value isa AbstractVector
        return [String(v) for v in value]
    elseif value isa AbstractString
        return [String(value)]
    else
        return String[]
    end
end

function parse_scope_claim(payload)
    if haskey(payload, "scope")
        value = payload["scope"]
        if value isa AbstractString
            return split(String(value))
        elseif value isa AbstractVector
            return [String(v) for v in value]
        end
    elseif haskey(payload, "scp")
        value = payload["scp"]
        value isa AbstractVector && return [String(v) for v in value]
    end
    return String[]
end

function extract_confirmation_thumbprint(payload)
    haskey(payload, "cnf") || return nothing
    cnf = payload["cnf"]
    if cnf isa AbstractDict
        value = get(cnf, "jkt", nothing)
        return value isa AbstractString ? String(value) : nothing
    end
    return nothing
end

function parse_numeric_claim(value)
    if value isa Integer
        return Dates.unix2datetime(value)
    elseif value isa Real
        return Dates.unix2datetime(floor(Int, value))
    elseif value isa AbstractString
        parsed = tryparse(Int, value)
        parsed === nothing && return nothing
        return Dates.unix2datetime(parsed)
    else
        return nothing
    end
end

"""
    validate_jwt_access_token(token, config; now=Dates.now(UTC), required_scopes=String[]) -> AccessTokenClaims

Checks signature, issuer, audience, expiration, scope, DPoP confirmation,
and optional replay cache entries for a JWT access token that your server
received.  Throws `OAuthError` if validation fails.
"""
function validate_jwt_access_token(token::AbstractString, config::TokenValidationConfig; now::DateTime=Dates.now(UTC), required_scopes=String[])
    header, payload, signature, signing_input = decode_compact_jwt(token)
    alg_value = haskey(header, "alg") ? uppercase(String(header["alg"])) : error(OAuthError(:invalid_token, "Missing alg"))
    alg = Symbol(alg_value)
    alg in config.allowed_algs || throw(OAuthError(:invalid_token, "Disallowed alg $(alg)"))
    kid = haskey(header, "kid") ? String(header["kid"]) : nothing
    key = select_verification_key(config, alg, kid)
    verify_jws(key.verifier, alg, signing_input, signature) || throw(OAuthError(:invalid_token, "JWT signature invalid"))
    iss = haskey(payload, "iss") ? String(payload["iss"]) : nothing
    iss == config.issuer || throw(OAuthError(:invalid_token, "Issuer mismatch"))
    expires_at = parse_numeric_claim(get(payload, "exp", nothing))
    expires_at === nothing && throw(OAuthError(:invalid_token, "Missing exp"))
    now > expires_at + config.leeway && throw(OAuthError(:invalid_token, "Token expired"))
    nbf = haskey(payload, "nbf") ? parse_numeric_claim(payload["nbf"]) : nothing
    nbf !== nothing && now + config.leeway < nbf && throw(OAuthError(:invalid_token, "Token not yet valid"))
    issued_at = haskey(payload, "iat") ? parse_numeric_claim(payload["iat"]) : nothing
    issued_at !== nothing && issued_at - config.leeway > now && throw(OAuthError(:invalid_token, "Token issued in the future"))
    aud_claim = parse_audience(get(payload, "aud", String[]))
    if !isempty(config.audience)
        any(in(config.audience), aud_claim) || throw(OAuthError(:invalid_token, "Audience mismatch"))
    end
    scope_claims = parse_scope_claim(payload)
    confirmation_jkt = extract_confirmation_thumbprint(payload)
    if !isempty(required_scopes)
        missing = [scope for scope in required_scopes if !(scope in scope_claims)]
        !isempty(missing) && throw(OAuthError(:insufficient_scope, "Missing required scopes: $(join(missing, ", "))"))
    end
    claims = Dict{String,Any}()
    for (k, v) in payload
        claims[String(k)] = v
    end
    return AccessTokenClaims(
        token = String(token),
        subject = haskey(payload, "sub") ? String(payload["sub"]) : nothing,
        client_id = haskey(payload, "client_id") ? String(payload["client_id"]) : (haskey(payload, "azp") ? String(payload["azp"]) : nothing),
        scope = scope_claims,
        audience = aud_claim,
        expires_at = expires_at,
        issued_at = issued_at,
        claims = claims,
        confirmation_jkt = confirmation_jkt,
    )
end

function quote_auth_value(value)
    escaped = replace(String(value), "\"" => "\\\"")
    return "\"$(escaped)\""
end

struct ResourceOrigin
    scheme::String
    host::String
    port::Union{Int,Nothing}
end

function ResourceOrigin(url::AbstractString)
    uri = parse_uri_or_throw(String(url), "resource_metadata_url")
    scheme = lowercase(String(uri.scheme))
    host = uri.host === nothing ? "" : lowercase(String(uri.host))
    port_value = uri.port
    port = if port_value === nothing
        scheme == "https" ? 443 :
        scheme == "http" ? 80 : nothing
    elseif port_value isa Integer
        port_value
    else
        tryparse(Int, port_value)
    end
    return ResourceOrigin(scheme, host, port)
end

function normalized_request_url(req::HTTP.Request, origin::ResourceOrigin)
    target = String(req.target)
    uri = try
        HTTP.URI(target)
    catch
        HTTP.URI("/" * target)
    end
    req_scheme = String(uri.scheme)
    scheme = isempty(req_scheme) ? origin.scheme : lowercase(req_scheme)
    req_host = uri.host === nothing ? "" : String(uri.host)
    host = isempty(req_host) ? origin.host : lowercase(req_host)
    port_value = uri.port
    port = if port_value === nothing
        origin.port
    elseif port_value isa Integer
        port_value
    else
        tryparse(Int, port_value)
    end
    path = String(uri.path)
    isempty(path) && (path = "/")
    query = String(uri.query)
    base = string(scheme, "://", host)
    if port !== nothing && !is_default_port(scheme, port)
        base = string(base, ":", port)
    end
    absolute = isempty(query) ? base * path : base * path * "?" * query
    return normalize_dpop_url(absolute)
end

function build_dpop_verifier_from_jwk(jwk::Dict{String,Any}, alg::Symbol)
    kty = uppercase(String(get(jwk, "kty", "")))
    if kty == "EC"
        crv = get(jwk, "crv", nothing)
        crv isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing EC curve"))
        curve_symbol = crv == "P-256" ? :P256 : crv == "P-384" ? :P384 : throw(OAuthError(:invalid_token, "Unsupported EC curve $(crv) for DPoP"))
        alg in SUPPORTED_EC_ALGS || throw(OAuthError(:invalid_token, "Unsupported DPoP alg $(alg) for EC key"))
        x_val = get(jwk, "x", nothing)
        y_val = get(jwk, "y", nothing)
        x_val isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing EC x coordinate"))
        y_val isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing EC y coordinate"))
        x_bytes = Vector{UInt8}(base64urldecode(String(x_val)))
        y_bytes = Vector{UInt8}(base64urldecode(String(y_val)))
        return ecc_verifier_from_coordinates(x_bytes, y_bytes, curve_symbol)
    elseif kty == "RSA"
        alg in SUPPORTED_RSA_ALGS || throw(OAuthError(:invalid_token, "Unsupported DPoP alg $(alg) for RSA key"))
        n_val = get(jwk, "n", nothing)
        e_val = get(jwk, "e", nothing)
        n_val isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing RSA modulus"))
        e_val isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing RSA exponent"))
        n_bytes = Vector{UInt8}(base64urldecode(String(n_val)))
        e_bytes = Vector{UInt8}(base64urldecode(String(e_val)))
        return rsa_verifier_from_components(n_bytes, e_bytes)
    else
        throw(OAuthError(:invalid_token, "Unsupported DPoP key type $(kty)"))
    end
end

function verify_dpop_proof(
    proof::AbstractString,
    req::HTTP.Request,
    claims::AccessTokenClaims,
    origin::ResourceOrigin,
    replay_cache::DPoPReplayCache,
    now::DateTime,
    max_age::Dates.Second,
    iat_skew::Dates.Second,
    nonce_validator,
)
    header, payload, signature, signing_input = decode_compact_jwt(proof)
    typ = lowercase(String(get(header, "typ", "")))
    typ == "dpop+jwt" || throw(OAuthError(:invalid_token, "Invalid DPoP proof typ"))
    jwk_value = get(header, "jwk", nothing)
    jwk_value isa AbstractDict || throw(OAuthError(:invalid_token, "DPoP proof missing jwk"))
    jwk = Dict{String,Any}()
    for (k, v) in jwk_value
        jwk[String(k)] = v
    end
    alg_value = Symbol(uppercase(String(get(header, "alg", ""))))
    verifier = build_dpop_verifier_from_jwk(jwk, alg_value)
    verify_jws(verifier, alg_value, signing_input, signature) || throw(OAuthError(:invalid_token, "Invalid DPoP proof signature"))
    thumbprint = jwk_thumbprint(jwk)
    claims.confirmation_jkt === nothing && throw(OAuthError(:invalid_token, "Token is not sender constrained"))
    thumbprint == claims.confirmation_jkt || throw(OAuthError(:invalid_token, "DPoP key thumbprint mismatch"))
    expected_htu = normalized_request_url(req, origin)
    htu = get(payload, "htu", nothing)
    htu isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing htu"))
    normalize_dpop_url(String(htu)) == expected_htu || throw(OAuthError(:invalid_token, "DPoP htu mismatch"))
    htm = get(payload, "htm", nothing)
    htm isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing htm"))
    request_method = uppercase(String(HTTP.method(req)))
    uppercase(String(htm)) == request_method || throw(OAuthError(:invalid_token, "DPoP htm mismatch"))
    ath = get(payload, "ath", nothing)
    ath isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing ath"))
    token_hash = base64url(SHA.sha256(codeunits(claims.token)))
    String(ath) == token_hash || throw(OAuthError(:invalid_token, "DPoP ath mismatch"))
    iat = parse_numeric_claim(get(payload, "iat", nothing))
    iat === nothing && throw(OAuthError(:invalid_token, "DPoP proof missing iat"))
    iat < now - max_age && throw(OAuthError(:invalid_token, "DPoP proof expired"))
    iat > now + iat_skew && throw(OAuthError(:invalid_token, "DPoP proof issued in the future"))
    nonce_value = get(payload, "nonce", nothing)
    if nonce_validator !== nothing
        valid_nonce = nonce_value isa AbstractString ? nonce_validator(String(nonce_value), req) : false
        valid_nonce || throw(OAuthError(:invalid_token, "DPoP proof nonce invalid"))
    end
    jti = get(payload, "jti", nothing)
    jti isa AbstractString || throw(OAuthError(:invalid_token, "DPoP proof missing jti"))
    record_dpop_proof!(replay_cache, String(jti), now) || throw(OAuthError(:invalid_token, "DPoP proof replay detected"))
end

"""
    build_www_authenticate_header(resource_metadata_url; realm=nothing, required_scopes=String[], error_code=nothing, error_description=nothing) -> String

Constructs a standards-compliant `WWW-Authenticate` header for Protected
Resource Metadata-based deployments.  Useful when returning 401s from your
resource server.
"""
function build_www_authenticate_header(resource_metadata_url; realm::Union{String,Nothing}=nothing, required_scopes=String[], error_code::Union{String,Nothing}=nothing, error_description::Union{String,Nothing}=nothing)
    parts = ["Bearer"]
    realm_value = quote_auth_value(realm === nothing ? DEFAULT_REALM : realm)
    push!(parts, "realm=$(realm_value)")
    push!(parts, "resource_metadata=$(quote_auth_value(String(resource_metadata_url)))")
    !isempty(required_scopes) && push!(parts, "scope=$(quote_auth_value(join(required_scopes, ' ')))")
    error_code !== nothing && push!(parts, "error=$(quote_auth_value(error_code))")
    error_description !== nothing && push!(parts, "error_description=$(quote_auth_value(error_description))")
    return join(parts, ' ')
end

function unauthorized_response(resource_metadata_url; realm=nothing, required_scopes=String[], error_code=nothing, error_description=nothing, status::Integer=401)
    header = build_www_authenticate_header(resource_metadata_url; realm=realm, required_scopes=required_scopes, error_code=error_code, error_description=error_description)
    return HTTP.Response(status, HTTP.Headers(["WWW-Authenticate" => header]), "")
end

"""
    protected_resource_middleware(; token_store=nothing, token_validator=nothing, realm=DEFAULT_REALM, extra_challenges=String[])

Builds an HTTP middleware function that validates incoming `Authorization`
headers, enforces scope requirements, and passes the resulting
[`AccessTokenClaims`](@ref) to your handler via the request context.
"""
function protected_resource_middleware(
    handler::Function,
    validator::TokenValidationConfig;
    resource_metadata_url::AbstractString,
    realm=nothing,
    required_scopes=String[],
    context_key::Symbol=:oauth_token,
    verbose::Bool=false,
    sender_constrained_only::Bool=false,
    dpop_replay_cache::Union{DPoPReplayCache,Nothing}=nothing,
    dpop_max_age_seconds::Integer=300,
    dpop_iat_skew_seconds::Integer=60,
    dpop_nonce_validator=nothing,
)
    scopes = [String(s) for s in required_scopes]
    origin = ResourceOrigin(resource_metadata_url)
    replay_cache = dpop_replay_cache === nothing ? DPoPReplayCache(window_seconds=dpop_max_age_seconds) : dpop_replay_cache
    max_age = Dates.Second(dpop_max_age_seconds)
    iat_skew = Dates.Second(dpop_iat_skew_seconds)
    function middleware(req::HTTP.Request)
        creds = authorization_credentials(req)
        creds === nothing && return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description="Missing access token")
        claims = try
            validate_jwt_access_token(creds.token, validator; required_scopes=scopes)
        catch err
            if err isa OAuthError && err.code == :insufficient_scope
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="insufficient_scope", error_description=err.message, status=403)
            elseif err isa OAuthError
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description=err.message)
            else
                rethrow()
            end
        end
        confirmation = claims.confirmation_jkt
        scheme_lc = lowercase(creds.scheme)
        if confirmation !== nothing
            if scheme_lc != "dpop"
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description="DPoP tokens must use the DPoP Authorization scheme")
            end
            proof_header = HTTP.header(req.headers, "DPoP", "")
            if isempty(proof_header)
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description="Missing DPoP proof")
            end
            now_time = Dates.now(UTC)
            try
                verify_dpop_proof(
                    proof_header,
                    req,
                    claims,
                    origin,
                    replay_cache,
                    now_time,
                    max_age,
                    iat_skew,
                    dpop_nonce_validator,
                )
            catch err
                if err isa OAuthError
                    return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description=err.message)
                else
                    rethrow()
                end
            end
        else
            if sender_constrained_only
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description="Sender-constrained tokens required")
            end
            if scheme_lc == "dpop"
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description="Bearer tokens cannot use the DPoP scheme")
            end
        end
        req.context[context_key] = claims
        return handler(req)
    end
    return middleware
end

"""
    build_introspection_handler(store; authenticator=AllowAllAuthenticator()) -> Function

Produces an HTTP handler that implements RFC 7662 token introspection by
looking up tokens in the provided `store`.  Requests are authenticated via
the supplied `EndpointAuthenticator`.
"""
function build_introspection_handler(store::InMemoryTokenStore; authenticator::EndpointAuthenticator=AllowAllAuthenticator())
    function handler(req::HTTP.Request)
        authenticate_request(authenticator, req) || return unauthorized_endpoint_response(authenticator)
        HTTP.method(req) == "POST" || return HTTP.Response(405, HTTP.Headers(["Allow" => "POST"]), "")
        body_bytes = request_body_bytes(req)
        params = parse_form_urlencoded(body_bytes)
        token = get(params, "token", nothing)
        token === nothing && return json_no_store_response(Dict("error" => "invalid_request", "error_description" => "token parameter is required"); status=400)
        hint = get(params, "token_type_hint", nothing)
        if hint !== nothing
            hint_lc = lowercase(String(hint))
            hint_lc == "access_token" || return json_no_store_response(Dict("error" => "unsupported_token_type"); status=400)
        end
        record = lookup_access_token(store, token)
        if record === nothing || record.revoked || Dates.now(UTC) > record.expires_at
            return json_no_store_response(Dict("active" => false))
        end
        response = Dict{String,Any}(
            "active" => true,
            "iss" => get(record.claims, "iss", nothing),
            "client_id" => record.client_id,
            "sub" => record.subject,
            "exp" => datetime_to_unix(record.expires_at),
            "iat" => datetime_to_unix(record.issued_at),
            "scope" => join(record.scope, ' '),
            "token_type" => "access_token",
        )
        haskey(record.claims, "aud") && (response["aud"] = record.claims["aud"])
        haskey(record.claims, "nbf") && (response["nbf"] = record.claims["nbf"])
        haskey(record.claims, "authorization_details") && (response["authorization_details"] = record.claims["authorization_details"])
        haskey(record.claims, "auth_time") && (response["auth_time"] = record.claims["auth_time"])
        haskey(record.claims, "azp") && (response["azp"] = record.claims["azp"])
        haskey(record.claims, "username") && (response["username"] = record.claims["username"])
        return json_no_store_response(response)
    end
    return handler
end

"""
    build_revocation_handler(store; authenticator=AllowAllAuthenticator()) -> Function

Builds an RFC 7009 token revocation endpoint backed by the supplied token
store.  Deletes matching access tokens and returns the appropriate HTTP
response envelope.
"""
function build_revocation_handler(store::InMemoryTokenStore; authenticator::EndpointAuthenticator=AllowAllAuthenticator())
    function handler(req::HTTP.Request)
        authenticate_request(authenticator, req) || return unauthorized_endpoint_response(authenticator)
        HTTP.method(req) == "POST" || return HTTP.Response(405, HTTP.Headers(["Allow" => "POST"]), "")
        body_bytes = request_body_bytes(req)
        params = parse_form_urlencoded(body_bytes)
        token = get(params, "token", nothing)
        token === nothing && return json_no_store_response(Dict("error" => "invalid_request", "error_description" => "token parameter is required"); status=400)
        hint = get(params, "token_type_hint", nothing)
        if hint !== nothing
            hint_lc = lowercase(String(hint))
            hint_lc == "access_token" || return json_no_store_response(Dict("error" => "unsupported_token_type"); status=400)
        end
        revoke_access_token!(store, token)
        headers = HTTP.Headers([
            "Cache-Control" => "no-store",
            "Pragma" => "no-cache",
        ])
        return HTTP.Response(200, headers, "")
    end
    return handler
end
