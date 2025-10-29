const JSONObject = JSON.Object{String,Any}

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
    return ProtectedResourceMetadata(
        resource = haskey(data, "resource") ? String(data["resource"]) : nothing,
        authorization_servers = authz,
        scopes_supported = scopes,
        raw = data,
    )
end

Base.@kwdef struct AuthorizationServerMetadata
    issuer::Union{String,Nothing}
    authorization_endpoint::Union{String,Nothing}
    token_endpoint::Union{String,Nothing}
    device_authorization_endpoint::Union{String,Nothing}
    jwks_uri::Union{String,Nothing}
    response_types_supported::Vector{String}
    grant_types_supported::Vector{String}
    code_challenge_methods_supported::Vector{String}
    token_endpoint_auth_methods_supported::Vector{String}
    token_endpoint_auth_signing_alg_values_supported::Vector{String}
    raw::JSONObject
end

function AuthorizationServerMetadata(data::JSONObject)
    return AuthorizationServerMetadata(
        issuer = get(data, "issuer", nothing) |> maybe_string,
        authorization_endpoint = get(data, "authorization_endpoint", nothing) |> maybe_string,
        token_endpoint = get(data, "token_endpoint", nothing) |> maybe_string,
        device_authorization_endpoint = get(data, "device_authorization_endpoint", nothing) |> maybe_string,
        jwks_uri = get(data, "jwks_uri", nothing) |> maybe_string,
        response_types_supported = collect_strings(get(data, "response_types_supported", Any[])),
        grant_types_supported = collect_strings(get(data, "grant_types_supported", Any[])),
        code_challenge_methods_supported = collect_strings(get(data, "code_challenge_methods_supported", Any[])),
        token_endpoint_auth_methods_supported = collect_strings(get(data, "token_endpoint_auth_methods_supported", Any[])),
        token_endpoint_auth_signing_alg_values_supported = collect_strings(get(data, "token_endpoint_auth_signing_alg_values_supported", Any[])),
        raw = data,
    )
end

abstract type TokenEndpointAuth end

struct ClientSecretAuth <: TokenEndpointAuth
    method::Symbol
    secret::String
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

struct DPoPAuth
    signer::ECSigner
    alg::Symbol
    public_jwk::Dict{String,Any}
    kid::Union{String,Nothing}
    thumbprint::String
    iat_skew::Int
end

struct ConfidentialClientConfig{T<:TokenEndpointAuth}
    client_id::String
    credential::T
    scopes::Vector{String}
    additional_parameters::StringParams
    dpop::Union{DPoPAuth,Nothing}
    verbose::Bool
end

struct PublicClientConfig
    client_id::String
    redirect_uri::Union{String,Nothing}
    scopes::Vector{String}
    additional_parameters::StringParams
    dpop::Union{DPoPAuth,Nothing}
    verbose::Bool
end

function ClientSecretAuth(secret::AbstractString; method::Union{Symbol,AbstractString}=:client_secret_basic)
    method_symbol = method isa Symbol ? method : Symbol(method)
    method_symbol in (:client_secret_basic, :client_secret_post) || throw(ArgumentError("Unsupported client secret auth method: $(method_symbol)"))
    return ClientSecretAuth(method_symbol, String(secret))
end

function PrivateKeyJWTAuth(; private_key, alg::Union{Symbol,AbstractString}=:RS256, kid=nothing, audience=nothing, expires_in::Integer=300, clock_skew::Integer=60, extra_claims=Dict{String,Any}())
    alg_symbol = alg isa Symbol ? alg : Symbol(alg)
    signer = if alg_symbol in SUPPORTED_RSA_ALGS
        rsa_signer_from_bytes(private_key)
    elseif alg_symbol in SUPPORTED_EC_ALGS
        curve = alg_symbol == :ES256 ? :P256 : :P384
        ecc_signer_from_bytes(private_key, curve)
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

function DPoPAuth(; private_key, public_jwk, alg::Union{Symbol,AbstractString}=:ES256, kid=nothing, iat_skew::Integer=60)
    alg_symbol = alg isa Symbol ? alg : Symbol(alg)
    alg_symbol in SUPPORTED_EC_ALGS || throw(ArgumentError("DPoP requires ECDSA-based alg, got $(alg_symbol)"))
    curve = alg_symbol == :ES256 ? :P256 : :P384
    signer = ecc_signer_from_bytes(private_key, curve)
    jwk = Dict{String,Any}()
    for (k, v) in public_jwk
        jwk[String(k)] = v isa AbstractString ? String(v) : v
    end
    thumbprint = jwk_thumbprint(jwk)
    return DPoPAuth(signer, alg_symbol, jwk, maybe_string(kid), thumbprint, Int(iat_skew))
end

function ConfidentialClientConfig(; client_id, client_secret=nothing, credential::Union{TokenEndpointAuth,Nothing}=nothing, scopes=String[], additional_parameters=nothing, token_endpoint_auth_method=:client_secret_basic, dpop::Union{DPoPAuth,Nothing}=nothing, verbose::Bool=false)
    scope_list = String[String(s) for s in scopes]
    params = StringParams()
    if additional_parameters !== nothing
        for (k, v) in additional_parameters
            params[String(k)] = String(v)
        end
    end
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
        params,
        dpop,
        verbose,
    )
end

function PublicClientConfig(; client_id, redirect_uri=nothing, scopes=String[], additional_parameters=nothing, dpop::Union{DPoPAuth,Nothing}=nothing, verbose::Bool=false)
    scope_list = String[String(s) for s in scopes]
    params = StringParams()
    if additional_parameters !== nothing
        for (k, v) in additional_parameters
            params[String(k)] = String(v)
        end
    end
    redirect_value = redirect_uri === nothing ? nothing : String(redirect_uri)
    return PublicClientConfig(String(client_id), redirect_value, scope_list, params, dpop, verbose)
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
    raw::JSONObject
end

function TokenResponse(data::JSONObject; issued_at::DateTime = now(UTC), dpop_nonce::Union{String,Nothing}=nothing)
    expires_at = nothing
    if haskey(data, "expires_in")
        expires = try
            parse(Int, string(data["expires_in"]))
        catch
            nothing
        end
        expires !== nothing && (expires_at = issued_at + Dates.Second(expires))
    elseif haskey(data, "expires_at")
        expires_at = try_parse_time(data["expires_at"])
    end
    dpop_jkt = extract_cnf_jkt(data)
    response_nonce = get_str(data, "dpop_nonce")
    response_nonce = response_nonce === nothing ? dpop_nonce : response_nonce
    return TokenResponse(
        access_token = String(data["access_token"]),
        token_type = String(get(data, "token_type", "Bearer")),
        expires_at = expires_at,
        refresh_token = get_str(data, "refresh_token"),
        scope = get_str(data, "scope"),
        id_token = get_str(data, "id_token"),
        dpop_jkt = dpop_jkt,
        dpop_nonce = response_nonce,
        raw = data,
    )
end

# ---------- helpers ----------

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

function get_str(data::JSONObject, key::String)
    haskey(data, key) || return nothing
    value = data[key]
    return value isa AbstractString ? String(value) : nothing
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
    return build_jws_compact(header, payload, auth.signer, auth.alg)
end

dpop_thumbprint(auth::DPoPAuth) = auth.thumbprint

Base.@kwdef struct AuthorizationSession
    authorization_url::String
    redirect_uri::String
    verifier::PKCEVerifier
    state::String
    authorization_server::AuthorizationServerMetadata
    resource::Union{ProtectedResourceMetadata,Nothing}
    client_config::PublicClientConfig
    listener::Union{LoopbackListener,Nothing}
end

config_verbose(session::AuthorizationSession) = config_verbose(session.client_config)
