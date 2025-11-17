const JSONObject = JSON.Object{String,Any}

abstract type RefreshTokenStore end

struct InMemoryRefreshTokenStore <: RefreshTokenStore
    token::Base.RefValue{Union{Nothing,String}}
end

InMemoryRefreshTokenStore() = InMemoryRefreshTokenStore(Base.RefValue{Union{Nothing,String}}(nothing))

struct CallbackRefreshTokenStore{L,S,C} <: RefreshTokenStore
    load_callback::L
    save_callback::S
    clear_callback::C
end

function CallbackRefreshTokenStore(; load, save, clear=nothing)
    clear_fn = clear === nothing ? (_config) -> nothing : clear
    return CallbackRefreshTokenStore(load, save, clear_fn)
end

Base.@kwdef struct WWWAuthenticateChallenge
    scheme::String
    token::Union{String,Nothing}
    params::Dict{String,String}
end

WWWAuthenticateChallenge(scheme::AbstractString; token=nothing, params=Dict{String,String}()) =
    WWWAuthenticateChallenge(String(scheme), token === nothing ? nothing : String(token), Dict{String,String}(params))

realm(ch::WWWAuthenticateChallenge) = get(ch.params, "realm", nothing)

Base.@kwdef struct ProtectedResourceMetadata
    resource::Union{String,Nothing}
    authorization_servers::Vector{String}
    scopes_supported::Vector{String}
    resource_documentation::Union{String,Nothing}
    resource_registration_endpoint::Union{String,Nothing}
    raw::JSONObject
end

function ProtectedResourceMetadata(data::JSONObject)
    authz = String[]
    if haskey(data, "authorization_servers")
        for item in data["authorization_servers"]
            item isa AbstractString && push!(authz, String(item))
        end
    end
    scopes = String[]
    if haskey(data, "scopes_supported")
        for item in data["scopes_supported"]
            item isa AbstractString && push!(scopes, String(item))
        end
    end
    documentation = get(data, "resource_documentation", nothing)
    registration_endpoint = get(data, "resource_registration_endpoint", nothing)
    return ProtectedResourceMetadata(
        resource = haskey(data, "resource") ? String(data["resource"]) : nothing,
        authorization_servers = authz,
        scopes_supported = scopes,
        resource_documentation = maybe_string(documentation),
        resource_registration_endpoint = maybe_string(registration_endpoint),
        raw = data,
    )
end

Base.@kwdef struct AuthorizationServerMetadata
    issuer::Union{String,Nothing}
    authorization_endpoint::Union{String,Nothing}
    token_endpoint::Union{String,Nothing}
    device_authorization_endpoint::Union{String,Nothing}
    jwks_uri::Union{String,Nothing}
    scopes_supported::Vector{String}
    response_types_supported::Vector{String}
    grant_types_supported::Vector{String}
    code_challenge_methods_supported::Vector{String}
    token_endpoint_auth_methods_supported::Vector{String}
    token_endpoint_auth_signing_alg_values_supported::Vector{String}
    introspection_endpoint::Union{String,Nothing}
    revocation_endpoint::Union{String,Nothing}
    pushed_authorization_request_endpoint::Union{String,Nothing}
    backchannel_authentication_endpoint::Union{String,Nothing}
    end_session_endpoint::Union{String,Nothing}
    registration_endpoint::Union{String,Nothing}
    mtls_endpoint_aliases::Dict{String,String}
    authorization_response_iss_parameter_supported::Bool
    request_object_signing_alg_values_supported::Vector{String}
    request_parameter_supported::Bool
    request_uri_parameter_supported::Bool
    require_pushed_authorization_requests::Bool
    raw::JSONObject
end

function AuthorizationServerMetadata(data::JSONObject)
    return AuthorizationServerMetadata(
        issuer = get(data, "issuer", nothing) |> maybe_string,
        authorization_endpoint = get(data, "authorization_endpoint", nothing) |> maybe_string,
        token_endpoint = get(data, "token_endpoint", nothing) |> maybe_string,
        device_authorization_endpoint = get(data, "device_authorization_endpoint", nothing) |> maybe_string,
        jwks_uri = get(data, "jwks_uri", nothing) |> maybe_string,
        scopes_supported = collect_strings(get(data, "scopes_supported", Any[])),
        response_types_supported = collect_strings(get(data, "response_types_supported", Any[])),
        grant_types_supported = collect_strings(get(data, "grant_types_supported", Any[])),
        code_challenge_methods_supported = collect_strings(get(data, "code_challenge_methods_supported", Any[])),
        token_endpoint_auth_methods_supported = collect_strings(get(data, "token_endpoint_auth_methods_supported", Any[])),
        token_endpoint_auth_signing_alg_values_supported = collect_strings(get(data, "token_endpoint_auth_signing_alg_values_supported", Any[])),
        introspection_endpoint = get(data, "introspection_endpoint", nothing) |> maybe_string,
        revocation_endpoint = get(data, "revocation_endpoint", nothing) |> maybe_string,
        pushed_authorization_request_endpoint = get(data, "pushed_authorization_request_endpoint", nothing) |> maybe_string,
        backchannel_authentication_endpoint = get(data, "backchannel_authentication_endpoint", nothing) |> maybe_string,
        end_session_endpoint = get(data, "end_session_endpoint", nothing) |> maybe_string,
        registration_endpoint = get(data, "registration_endpoint", nothing) |> maybe_string,
        mtls_endpoint_aliases = collect_string_dict(get(data, "mtls_endpoint_aliases", Dict{String,Any}())),
        authorization_response_iss_parameter_supported = get_bool(data, "authorization_response_iss_parameter_supported"),
        request_object_signing_alg_values_supported = collect_strings(get(data, "request_object_signing_alg_values_supported", Any[])),
        request_parameter_supported = get_bool(data, "request_parameter_supported"; default=true),
        request_uri_parameter_supported = get_bool(data, "request_uri_parameter_supported"; default=true),
        require_pushed_authorization_requests = get_bool(data, "require_pushed_authorization_requests"),
        raw = data,
    )
end

function metadata_scopes(resource::Union{ProtectedResourceMetadata,Nothing}, metadata::AuthorizationServerMetadata)
    if resource !== nothing && !isempty(resource.scopes_supported)
        return copy(resource.scopes_supported)
    elseif !isempty(metadata.scopes_supported)
        return copy(metadata.scopes_supported)
    end
    return String[]
end

function effective_scope_list(scopes::Vector{String}, resource::Union{ProtectedResourceMetadata,Nothing}, metadata::AuthorizationServerMetadata)
    if !isempty(scopes)
        return copy(scopes)
    end
    return metadata_scopes(resource, metadata)
end

Base.@kwdef struct OAuthDiscoveryContext
    authorization_server::AuthorizationServerMetadata
    resource::Union{ProtectedResourceMetadata,Nothing}
    scopes_supported::Vector{String}
    jwks_uri::Union{String,Nothing}
    introspection_endpoint::Union{String,Nothing}
    revocation_endpoint::Union{String,Nothing}
end

function OAuthDiscoveryContext(auth::AuthorizationServerMetadata, resource::Union{ProtectedResourceMetadata,Nothing}=nothing)
    return OAuthDiscoveryContext(
        authorization_server = auth,
        resource = resource,
        scopes_supported = metadata_scopes(resource, auth),
        jwks_uri = auth.jwks_uri,
        introspection_endpoint = auth.introspection_endpoint,
        revocation_endpoint = auth.revocation_endpoint,
    )
end

abstract type TokenEndpointAuth end

struct ClientSecretAuth <: TokenEndpointAuth
    method::Symbol
    secret::String
end

struct ClientSecretJWTAuth <: TokenEndpointAuth
    secret::Vector{UInt8}
    alg::Symbol
    expires_in::Int
    clock_skew::Int
    extra_claims::Dict{String,Any}
end

struct PrivateKeyJWTAuth <: TokenEndpointAuth
    signer::JWTSigner
    alg::Symbol
    kid::Union{String,Nothing}
    audience::Union{String,Nothing}
    expires_in::Int
    clock_skew::Int
    extra_claims::Dict{String,Any}
end

struct TLSClientAuth{C} <: TokenEndpointAuth
    method::Symbol
    sslconfig::C
end

function TLSClientAuth(sslconfig; method::Union{Symbol,AbstractString}=:tls_client_auth)
    method_symbol = method isa Symbol ? method : Symbol(method)
    method_symbol in (:tls_client_auth, :self_signed_tls_client_auth) || throw(ArgumentError("Unsupported TLS client auth method: $(method_symbol)"))
    sslconfig === nothing && throw(ArgumentError("sslconfig must be provided for TLS client authentication"))
    return TLSClientAuth{typeof(sslconfig)}(method_symbol, sslconfig)
end

mutable struct DPoPNonceCache
    lock::Base.ReentrantLock
    entries::Dict{String,Tuple{String,DateTime}}
    ttl::Dates.Second
end

function DPoPNonceCache(; ttl_seconds::Integer=300)
    ttl_seconds > 0 || throw(ArgumentError("ttl_seconds must be positive"))
    return DPoPNonceCache(Base.ReentrantLock(), Dict{String,Tuple{String,DateTime}}(), Dates.Second(ttl_seconds))
end

struct DPoPAuth
    signer::ECSigner
    alg::Symbol
    public_jwk::Dict{String,Any}
    kid::Union{String,Nothing}
    thumbprint::String
    iat_skew::Int
    nonce_cache::DPoPNonceCache
end

struct RequestObjectSigner
    signer::JWTSigner
    alg::Symbol
    kid::Union{String,Nothing}
    audience::Union{String,Nothing}
    expires_in::Int
    clock_skew::Int
    extra_claims::Dict{String,Any}
end

function RequestObjectSigner(; private_key, alg::Union{Symbol,AbstractString}=:RS256, kid=nothing, audience=nothing, expires_in::Integer=300, clock_skew::Integer=60, extra_claims=Dict{String,Any}())
    alg_symbol = Symbol(uppercase(String(alg)))
    signer = if alg_symbol in SUPPORTED_RSA_ALGS
        rsa_signer_from_bytes(private_key)
    elseif alg_symbol in SUPPORTED_EC_ALGS
        curve = alg_symbol == :ES256 ? :P256 : :P384
        ecc_signer_from_bytes(private_key, curve)
    elseif alg_symbol in SUPPORTED_OKP_ALGS
        eddsa_signer_from_bytes(private_key)
    else
        throw(ArgumentError("Unsupported request object signing alg $(alg_symbol)"))
    end
    claims = Dict{String,Any}()
    for (k, v) in extra_claims
        claims[String(k)] = v
    end
    return RequestObjectSigner(
        signer,
        alg_symbol,
        maybe_string(kid),
        maybe_string(audience),
        Int(expires_in),
        Int(clock_skew),
        claims,
    )
end

struct ConfidentialClientConfig{T<:TokenEndpointAuth}
    client_id::String
    credential::T
    scopes::Vector{String}
    resources::Vector{String}
    authorization_details::Union{Nothing,Any}
    additional_parameters::StringParams
    dpop::Union{DPoPAuth,Nothing}
    verbose::Bool
end

struct PublicClientConfig
    client_id::String
    redirect_uri::Union{String,Nothing}
    scopes::Vector{String}
    resources::Vector{String}
    authorization_details::Union{Nothing,Any}
    additional_parameters::StringParams
    dpop::Union{DPoPAuth,Nothing}
    refresh_token_store::Union{RefreshTokenStore,Nothing}
    allow_plain_pkce::Bool
    use_par::Bool
    request_object_signer::Union{RequestObjectSigner,Nothing}
    verbose::Bool
end

function ClientSecretAuth(secret::AbstractString; method::Union{Symbol,AbstractString}=:client_secret_basic)
    method_symbol = method isa Symbol ? method : Symbol(method)
    method_symbol in (:client_secret_basic, :client_secret_post) || throw(ArgumentError("Unsupported client secret auth method: $(method_symbol)"))
    return ClientSecretAuth(method_symbol, String(secret))
end

const SUPPORTED_CLIENT_SECRET_JWT_ALGS = Set([:HS256, :HS384, :HS512])

function ClientSecretJWTAuth(secret::AbstractString; alg::Union{Symbol,AbstractString}=:HS256, expires_in::Integer=300, clock_skew::Integer=60, extra_claims=Dict{String,Any}())
    alg_symbol = Symbol(uppercase(String(alg)))
    alg_symbol in SUPPORTED_CLIENT_SECRET_JWT_ALGS || throw(ArgumentError("Unsupported client_secret_jwt alg $(alg_symbol)"))
    claims = Dict{String,Any}()
    for (k, v) in extra_claims
        claims[String(k)] = v
    end
    return ClientSecretJWTAuth(Vector{UInt8}(codeunits(String(secret))), alg_symbol, Int(expires_in), Int(clock_skew), claims)
end

function PrivateKeyJWTAuth(; private_key, alg::Union{Symbol,AbstractString}=:RS256, kid=nothing, audience=nothing, expires_in::Integer=300, clock_skew::Integer=60, extra_claims=Dict{String,Any}())
    alg_symbol = Symbol(uppercase(String(alg)))
    signer = if alg_symbol in SUPPORTED_RSA_ALGS
        rsa_signer_from_bytes(private_key)
    elseif alg_symbol in SUPPORTED_EC_ALGS
        curve = alg_symbol == :ES256 ? :P256 : :P384
        ecc_signer_from_bytes(private_key, curve)
    elseif alg_symbol in SUPPORTED_OKP_ALGS
        eddsa_signer_from_bytes(private_key)
    else
        throw(ArgumentError("Unsupported private_key_jwt alg $(alg_symbol)"))
    end
    claims = Dict{String,Any}()
    for (k, v) in extra_claims
        claims[String(k)] = v
    end
    return PrivateKeyJWTAuth(
        signer,
        alg_symbol,
        maybe_string(kid),
        maybe_string(audience),
        Int(expires_in),
        Int(clock_skew),
        claims,
    )
end

function DPoPAuth(; private_key, public_jwk, alg::Union{Symbol,AbstractString}=:ES256, kid=nothing, iat_skew::Integer=60, nonce_cache::Union{DPoPNonceCache,Nothing}=nothing)
    alg_symbol = alg isa Symbol ? alg : Symbol(alg)
    alg_symbol in SUPPORTED_EC_ALGS || throw(ArgumentError("DPoP requires ECDSA-based alg, got $(alg_symbol)"))
    curve = alg_symbol == :ES256 ? :P256 : :P384
    signer = ecc_signer_from_bytes(private_key, curve)
    jwk = Dict{String,Any}()
    for (k, v) in public_jwk
        jwk[String(k)] = v isa AbstractString ? String(v) : v
    end
    thumbprint = jwk_thumbprint(jwk)
    cache = nonce_cache === nothing ? DPoPNonceCache() : nonce_cache
    return DPoPAuth(signer, alg_symbol, jwk, maybe_string(kid), thumbprint, Int(iat_skew), cache)
end


function ConfidentialClientConfig(; client_id, client_secret=nothing, credential::Union{TokenEndpointAuth,Nothing}=nothing, scopes=String[], resources=String[], authorization_details=nothing, additional_parameters=nothing, token_endpoint_auth_method=:client_secret_basic, dpop::Union{DPoPAuth,Nothing}=nothing, verbose::Bool=false)
    scope_list = String[String(s) for s in scopes]
    resource_list = String[String(r) for r in resources]
    auth_details_value = normalize_authorization_details_value(authorization_details)
    params = normalize_string_params(additional_parameters)
    effective_credential = credential
    if effective_credential === nothing
        client_secret === nothing && throw(ArgumentError("client_secret must be provided when credential is not supplied"))
        effective_credential = ClientSecretAuth(String(client_secret); method=token_endpoint_auth_method)
    elseif client_secret !== nothing
        throw(ArgumentError("Provide either credential or client_secret, not both"))
    end
    return ConfidentialClientConfig(
        String(client_id),
        effective_credential::TokenEndpointAuth,
        scope_list,
        resource_list,
        auth_details_value,
        params,
        dpop,
        verbose,
    )
end

function PublicClientConfig(; client_id, redirect_uri=nothing, scopes=String[], resources=String[], authorization_details=nothing, additional_parameters=nothing, dpop::Union{DPoPAuth,Nothing}=nothing, refresh_token_store::Union{RefreshTokenStore,Nothing}=nothing, allow_plain_pkce::Bool=false, use_par::Bool=false, request_object_signer::Union{RequestObjectSigner,Nothing}=nothing, verbose::Bool=false)
    scope_list = String[String(s) for s in scopes]
    resource_list = String[String(r) for r in resources]
    auth_details_value = normalize_authorization_details_value(authorization_details)
    params = normalize_string_params(additional_parameters)
    redirect_value = redirect_uri === nothing ? nothing : String(redirect_uri)
    return PublicClientConfig(
        String(client_id),
        redirect_value,
        scope_list,
        resource_list,
        auth_details_value,
        params,
        dpop,
        refresh_token_store,
        allow_plain_pkce,
        Bool(use_par),
        request_object_signer,
        verbose,
    )
end

load_refresh_token(::RefreshTokenStore, ::PublicClientConfig) = nothing
save_refresh_token!(::RefreshTokenStore, ::PublicClientConfig, ::String) = nothing
clear_refresh_token!(::RefreshTokenStore, ::PublicClientConfig) = nothing
load_refresh_token(::Nothing, ::PublicClientConfig) = nothing
save_refresh_token!(::Nothing, ::PublicClientConfig, ::String) = nothing
clear_refresh_token!(::Nothing, ::PublicClientConfig) = nothing

function load_refresh_token(store::InMemoryRefreshTokenStore, ::PublicClientConfig)
    return store.token[]
end

function save_refresh_token!(store::InMemoryRefreshTokenStore, ::PublicClientConfig, token::String)
    store.token[] = token
end

function clear_refresh_token!(store::InMemoryRefreshTokenStore, ::PublicClientConfig)
    store.token[] = nothing
end

function load_refresh_token(store::CallbackRefreshTokenStore, config::PublicClientConfig)
    return store.load_callback(config)
end

function save_refresh_token!(store::CallbackRefreshTokenStore, config::PublicClientConfig, token::String)
    store.save_callback(config, token)
end

function clear_refresh_token!(store::CallbackRefreshTokenStore, config::PublicClientConfig)
    store.clear_callback(config)
end

function load_refresh_token(config::PublicClientConfig)
    return load_refresh_token(config.refresh_token_store, config)
end

function save_refresh_token!(config::PublicClientConfig, token::Union{String,Nothing})
    token === nothing && return
    save_refresh_token!(config.refresh_token_store, config, token)
end

function clear_refresh_token!(config::PublicClientConfig)
    clear_refresh_token!(config.refresh_token_store, config)
end

config_verbose(::Any) = false

config_verbose(config::ConfidentialClientConfig) = config.verbose
config_verbose(config::PublicClientConfig) = config.verbose

effective_verbose(source, verbose::Union{Bool,Nothing}) = verbose === nothing ? config_verbose(source) : verbose

Base.@kwdef struct AuthorizationRequest
    authorization_endpoint::String
    response_type::String
    client_id::String
    redirect_uri::String
    scope::Union{String,Nothing}
    state::String
    code_challenge::Union{String,Nothing}
    code_challenge_method::Union{String,Nothing}
    resources::Vector{String}
    authorization_details::Union{Nothing,Any}
    request::Union{String,Nothing}
    request_uri::Union{String,Nothing}
    extra::Dict{String,String}
end

struct PKCEVerifier
    verifier::String
end

Base.@kwdef struct TokenResponse
    access_token::String
    token_type::String
    expires_at::Union{DateTime,Nothing}
    refresh_token::Union{String,Nothing}
    scope::Union{String,Nothing}
    id_token::Union{String,Nothing}
    dpop_jkt::Union{String,Nothing}
    dpop_nonce::Union{String,Nothing}
    authorization_details::Union{Nothing,Any}
    resource::Vector{String}
    issued_token_type::Union{String,Nothing}
    extra::Dict{String,Any}
    raw::JSONObject
end

Base.@kwdef struct DeviceAuthorizationResponse
    device_code::String
    user_code::String
    verification_uri::String
    verification_uri_complete::Union{String,Nothing}
    expires_at::DateTime
    interval::Dates.Second
    raw::JSONObject
end

const TOKEN_RESPONSE_KNOWN_KEYS = Set([
    "access_token",
    "token_type",
    "expires_in",
    "expires_at",
    "refresh_token",
    "scope",
    "id_token",
    "cnf",
    "dpop_nonce",
    "authorization_details",
    "resource",
    "issued_token_type",
])

function TokenResponse(data::JSONObject; issued_at::DateTime = now(UTC), dpop_nonce::Union{String,Nothing}=nothing)
    expires_at = nothing
    expires_in = parse_expires_in_seconds(get(data, "expires_in", nothing))
    if expires_in !== nothing
        expires_at = issued_at + Dates.Second(expires_in)
    elseif haskey(data, "expires_at")
        expires_at = try_parse_time(data["expires_at"])
    end
    dpop_jkt = extract_cnf_jkt(data)
    response_nonce = get_str(data, "dpop_nonce")
    response_nonce = response_nonce === nothing ? dpop_nonce : response_nonce
    authz_details = haskey(data, "authorization_details") ? data["authorization_details"] : nothing
    resource_value = collect_resource_values(get(data, "resource", nothing))
    issued_type = get_str(data, "issued_token_type")
    extra = build_token_response_extra(data)
    return TokenResponse(
        access_token = String(data["access_token"]),
        token_type = String(get(data, "token_type", "Bearer")),
        expires_at = expires_at,
        refresh_token = get_str(data, "refresh_token"),
        scope = get_str(data, "scope"),
        id_token = get_str(data, "id_token"),
        dpop_jkt = dpop_jkt,
        dpop_nonce = response_nonce,
        authorization_details = authz_details,
        resource = resource_value,
        issued_token_type = issued_type,
        extra = extra,
        raw = data,
    )
end

function DeviceAuthorizationResponse(data::JSONObject; issued_at::DateTime=now(UTC))
    haskey(data, "device_code") || throw(OAuthError(:metadata_error, "device_authorization response missing device_code"))
    haskey(data, "user_code") || throw(OAuthError(:metadata_error, "device_authorization response missing user_code"))
    haskey(data, "verification_uri") || throw(OAuthError(:metadata_error, "device_authorization response missing verification_uri"))
    expires_in = parse_expires_in_seconds(get(data, "expires_in", nothing))
    expires_in === nothing && throw(OAuthError(:metadata_error, "device_authorization response must include expires_in"))
    interval_seconds = parse_interval_seconds(get(data, "interval", nothing))
    return DeviceAuthorizationResponse(
        device_code = String(data["device_code"]),
        user_code = String(data["user_code"]),
        verification_uri = String(data["verification_uri"]),
        verification_uri_complete = get_str(data, "verification_uri_complete"),
        expires_at = issued_at + Dates.Second(expires_in),
        interval = Dates.Second(interval_seconds),
        raw = data,
    )
end

# ---------- helpers ----------

function parse_expires_in_seconds(value)
    value === nothing && return nothing
    seconds = if value isa Integer
        Int(value)
    elseif value isa Real
        isfinite(value) ? floor(Int, value) : nothing
    elseif value isa AbstractString
        parsed = tryparse(Float64, value)
        parsed === nothing && return nothing
        isfinite(parsed) ? floor(Int, parsed) : nothing
    else
        nothing
    end
    seconds === nothing && return nothing
    return seconds < 0 ? nothing : seconds
end

function parse_interval_seconds(value)
    value === nothing && return 5
    seconds = parse_expires_in_seconds(value)
    seconds === nothing && return 5
    return max(seconds, 1)
end

maybe_string(value) = value === nothing ? nothing : String(value)

function collect_strings(xs)
    strings = String[]
    if xs isa AbstractVector
        for item in xs
            item isa AbstractString && push!(strings, String(item))
        end
    end
    return strings
end

function collect_string_dict(xs)
    dict = Dict{String,String}()
    if xs isa AbstractDict
        for (k, v) in xs
            k isa AbstractString || continue
            v isa AbstractString || continue
            dict[String(k)] = String(v)
        end
    end
    return dict
end

function normalize_authorization_details_value(value)
    value === nothing && return nothing
    if value isa AbstractString
        try
            return JSON.parse(String(value))
        catch err
            throw(ArgumentError("authorization_details must be valid JSON: $(err)"))
        end
    else
        return value
    end
end

function collect_resource_values(value)
    if value isa AbstractVector
        strings = String[]
        for item in value
            item isa AbstractString && push!(strings, String(item))
        end
        return strings
    elseif value isa AbstractString
        return [String(value)]
    else
        return String[]
    end
end

function build_token_response_extra(data::JSONObject)
    extra = Dict{String,Any}()
    for (k, v) in data
        key = String(k)
        key in TOKEN_RESPONSE_KNOWN_KEYS && continue
        extra[key] = v
    end
    return extra
end

function get_str(data::JSONObject, key::String)
    haskey(data, key) || return nothing
    value = data[key]
    return value isa AbstractString ? String(value) : nothing
end

function get_bool(data::JSONObject, key::String; default::Bool=false)
    haskey(data, key) || return default
    value = data[key]
    return value isa Bool ? value : default
end

function extract_cnf_jkt(data::JSONObject)
    haskey(data, "cnf") || return nothing
    cnf = data["cnf"]
    if cnf isa JSONObject
        return get_str(cnf, "jkt")
    elseif cnf isa AbstractDict
        value = get(cnf, "jkt", nothing)
        return value isa AbstractString ? String(value) : nothing
    end
    return nothing
end

function persist_refresh_token!(config::PublicClientConfig, response::TokenResponse)
    save_refresh_token!(config, response.refresh_token)
end

function try_parse_time(value)
    value isa AbstractString || return nothing
    try
        return DateTime(String(value))
    catch
        return nothing
    end
end

function build_client_assertion(
    auth::PrivateKeyJWTAuth,
    client_id::AbstractString,
    audience::AbstractString,
    now::DateTime,
)
    header = Dict{String,Any}("typ" => "JWT")
    auth.kid !== nothing && (header["kid"] = auth.kid)
    issued_at = Int(floor(Dates.datetime2unix(now))) - max(auth.clock_skew, 0)
    expires_at = issued_at + max(auth.expires_in, 0)
    payload = Dict{String,Any}(
        "iss" => String(client_id),
        "sub" => String(client_id),
        "aud" => String(audience),
        "iat" => issued_at,
        "exp" => expires_at,
        "jti" => random_state(),
    )
    for (k, v) in auth.extra_claims
        payload[String(k)] = v
    end
    return build_jws_compact(header, payload, auth.signer, auth.alg)
end

function sign_hmac_jws(alg::Symbol, key::Vector{UInt8}, data::Vector{UInt8})
    if alg == :HS256
        return SHA.hmac_sha256(key, data)
    elseif alg == :HS384
        return SHA.hmac_sha384(key, data)
    elseif alg == :HS512
        return SHA.hmac_sha512(key, data)
    else
        throw(ArgumentError("Unsupported HMAC alg $(alg)"))
    end
end

function build_hmac_jws_compact(header::Dict{String,Any}, payload::Dict{String,Any}, key::Vector{UInt8}, alg::Symbol)
    header["alg"] = String(alg)
    header_json = JSON.json(header)
    payload_json = JSON.json(payload)
    encoded_header = base64urlencode(header_json)
    encoded_payload = base64urlencode(payload_json)
    signing_input = Vector{UInt8}(codeunits(string(encoded_header, ".", encoded_payload)))
    signature = sign_hmac_jws(alg, key, signing_input)
    encoded_signature = base64urlencode(signature)
    return string(encoded_header, ".", encoded_payload, ".", encoded_signature)
end

function build_client_assertion(
    auth::ClientSecretJWTAuth,
    client_id::AbstractString,
    audience::AbstractString,
    now::DateTime,
)
    header = Dict{String,Any}("typ" => "JWT")
    issued_at = Int(floor(Dates.datetime2unix(now))) - max(auth.clock_skew, 0)
    expires_at = issued_at + max(auth.expires_in, 0)
    payload = Dict{String,Any}(
        "iss" => String(client_id),
        "sub" => String(client_id),
        "aud" => String(audience),
        "iat" => issued_at,
        "exp" => expires_at,
        "jti" => random_state(),
    )
    for (k, v) in auth.extra_claims
        payload[String(k)] = v
    end
    return build_hmac_jws_compact(header, payload, auth.secret, auth.alg)
end

normalize_dpop_url(url::AbstractString) = begin
    uri = HTTP.URI(String(url))
    scheme = lowercase(String(uri.scheme))
    host = uri.host === nothing ? "" : String(uri.host)
    path = String(uri.path)
    query = String(uri.query)
    if isempty(path)
        path = "/"
    end
    base = string(scheme, "://", host)
    port_value = uri.port
    if port_value isa AbstractString
        if isempty(port_value)
            port_value = nothing
        else
            parsed = tryparse(Int, port_value)
            port_value = parsed === nothing ? port_value : parsed
        end
    end
    if port_value !== nothing && !is_default_port(scheme, port_value)
        base = string(base, ":", port_value)
    end
    if isempty(query)
        return base * path
    else
        return base * path * "?" * query
    end
end

is_default_port(scheme::AbstractString, port) = begin
    if scheme == "https"
        return port == 443
    elseif scheme == "http"
        return port == 80
    else
        return false
    end
end

function create_dpop_proof(
    auth::DPoPAuth,
    method::AbstractString,
    url::AbstractString,
    now::DateTime;
    nonce=nothing,
    access_token=nothing,
)
    header = Dict{String,Any}(
        "typ" => "dpop+jwt",
        "jwk" => auth.public_jwk,
    )
    auth.kid !== nothing && (header["kid"] = auth.kid)
    iat = Int(floor(Dates.datetime2unix(now))) - max(auth.iat_skew, 0)
    payload = Dict{String,Any}(
        "htu" => normalize_dpop_url(url),
        "htm" => uppercase(String(method)),
        "iat" => iat,
        "jti" => random_state(),
    )
    nonce !== nothing && (payload["nonce"] = String(nonce))
    if access_token !== nothing
        digest = SHA.sha256(codeunits(String(access_token)))
        payload["ath"] = base64url(digest)
    end
    return build_jws_compact(header, payload, auth.signer, auth.alg)
end

dpop_thumbprint(auth::DPoPAuth) = auth.thumbprint

function dpop_origin_key(url::AbstractString)
    uri = try
        HTTP.URI(String(url))
    catch
        return lowercase(String(url))
    end
    scheme = String(uri.scheme)
    host = uri.host === nothing ? "" : String(uri.host)
    isempty(scheme) && isempty(host) && return lowercase(String(url))
    normalized_scheme = lowercase(scheme)
    normalized_host = lowercase(host)
    port_value = uri.port
    port = if port_value isa Integer
        port_value
    elseif port_value isa AbstractString
        tryparse(Int, port_value)
    else
        nothing
    end
    default_port = normalized_scheme == "https" ? 443 : (normalized_scheme == "http" ? 80 : nothing)
    port_part = (port === nothing || port == default_port) ? "" : string(":", port)
    return string(normalized_scheme, "://", normalized_host, port_part)
end

function cleanup_dpop_nonce_cache!(cache::DPoPNonceCache, now::DateTime)
    expired = String[]
    for (key, (_nonce, stored_at)) in cache.entries
        if stored_at + cache.ttl < now
            push!(expired, key)
        end
    end
    for key in expired
        delete!(cache.entries, key)
    end
end

function cache_dpop_nonce!(cache::DPoPNonceCache, url::AbstractString, nonce::AbstractString; now::DateTime=now(UTC))
    lock(cache.lock) do
        cleanup_dpop_nonce_cache!(cache, now)
        cache.entries[dpop_origin_key(url)] = (String(nonce), now)
    end
end

function cached_dpop_nonce(cache::DPoPNonceCache, url::AbstractString; now::DateTime=now(UTC))
    lock(cache.lock) do
        cleanup_dpop_nonce_cache!(cache, now)
        entry = get(cache.entries, dpop_origin_key(url), nothing)
        entry === nothing && return nothing
        nonce, _stored_at = entry
        return nonce
    end
end

cache_dpop_nonce!(auth::DPoPAuth, url::AbstractString, nonce::AbstractString; now::DateTime=now(UTC)) =
    cache_dpop_nonce!(auth.nonce_cache, url, nonce; now=now)

cached_dpop_nonce(auth::DPoPAuth, url::AbstractString; now::DateTime=now(UTC)) =
    cached_dpop_nonce(auth.nonce_cache, url; now=now)

Base.@kwdef struct AuthorizationSession
    authorization_url::String
    redirect_uri::String
    verifier::PKCEVerifier
    state::String
    authorization_server::AuthorizationServerMetadata
    resource::Union{ProtectedResourceMetadata,Nothing}
    client_config::PublicClientConfig
    listener::Union{LoopbackListener,Nothing}
    discovery::Union{OAuthDiscoveryContext,Nothing} = nothing
end

config_verbose(session::AuthorizationSession) = config_verbose(session.client_config)

function session_discovery(session::AuthorizationSession)
    if session.discovery === nothing
        return OAuthDiscoveryContext(session.authorization_server, session.resource)
    end
    return session.discovery
end
