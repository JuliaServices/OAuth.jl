# Server-side helpers for Protected Resource Metadata, Authorization Server metadata,
# middleware, token validation, and JWT access token issuance.

const DEFAULT_PRM_PATH = "/.well-known/oauth-protected-resource"
const DEFAULT_AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
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

function bearer_token(req::HTTP.Request)
    auth = HTTP.header(req.headers, "Authorization", "")
    isempty(auth) && return ""
    parts = split(auth, ' ')
    if length(parts) == 2 && HTTP.ascii_lc_isequal(parts[1], "bearer")
        return String(parts[2])
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

const UNIX_EPOCH = DateTime(1970, 1, 1, 0, 0, 0)

datetime_to_unix(dt::DateTime) = Dates.value(dt - UNIX_EPOCH) ÷ 1000

struct ProtectedResourceConfig
    resource::Union{String,Nothing}
    authorization_servers::Vector{String}
    scopes_supported::Vector{String}
    metadata::Dict{String,Any}
    path::String
end

function ProtectedResourceConfig(; resource=nothing, authorization_servers, scopes_supported=String[], extra=nothing, path::AbstractString=DEFAULT_PRM_PATH)
    authz = normalize_string_vector(authorization_servers)
    isempty(authz) && throw(ArgumentError("authorization_servers must not be empty"))
    scopes = normalize_string_vector(scopes_supported)
    metadata = normalize_metadata_dict(extra)
    if resource !== nothing
        metadata["resource"] = String(resource)
    end
    metadata["authorization_servers"] = authz
    !isempty(scopes) && (metadata["scopes_supported"] = scopes)
    return ProtectedResourceConfig(resource === nothing ? nothing : String(resource), authz, scopes, metadata, ensure_slash(path))
end

protected_resource_document(config::ProtectedResourceConfig) = copy(config.metadata)

function register_protected_resource_metadata!(router::HTTP.Router, config::ProtectedResourceConfig; path::AbstractString=config.path)
    handler = _ -> json_response(protected_resource_document(config))
    HTTP.register!(router, "GET", ensure_slash(path), handler)
    return handler
end

struct AuthorizationServerConfig
    issuer::String
    authorization_endpoint::Union{String,Nothing}
    token_endpoint::Union{String,Nothing}
    jwks_uri::Union{String,Nothing}
    device_authorization_endpoint::Union{String,Nothing}
    introspection_endpoint::Union{String,Nothing}
    revocation_endpoint::Union{String,Nothing}
    response_types_supported::Vector{String}
    grant_types_supported::Vector{String}
    code_challenge_methods_supported::Vector{String}
    token_endpoint_auth_methods_supported::Vector{String}
    token_endpoint_auth_signing_alg_values_supported::Vector{String}
    scopes_supported::Vector{String}
    metadata::Dict{String,Any}
    path::String
end

function AuthorizationServerConfig(; issuer, authorization_endpoint=nothing, token_endpoint=nothing, jwks_uri=nothing, device_authorization_endpoint=nothing, introspection_endpoint=nothing, revocation_endpoint=nothing, response_types_supported=String[], grant_types_supported=String[], code_challenge_methods_supported=String[], token_endpoint_auth_methods_supported=String[], token_endpoint_auth_signing_alg_values_supported=String[], scopes_supported=String[], extra=nothing, path::AbstractString=DEFAULT_AS_METADATA_PATH)
    metadata = normalize_metadata_dict(extra)
    metadata["issuer"] = String(issuer)
    for (key, value) in (
        ("authorization_endpoint", authorization_endpoint),
        ("token_endpoint", token_endpoint),
        ("jwks_uri", jwks_uri),
        ("device_authorization_endpoint", device_authorization_endpoint),
        ("introspection_endpoint", introspection_endpoint),
        ("revocation_endpoint", revocation_endpoint),
    )
        value === nothing || (metadata[key] = String(value))
    end
    !isempty(response_types_supported) && (metadata["response_types_supported"] = normalize_string_vector(response_types_supported))
    !isempty(grant_types_supported) && (metadata["grant_types_supported"] = normalize_string_vector(grant_types_supported))
    !isempty(code_challenge_methods_supported) && (metadata["code_challenge_methods_supported"] = normalize_string_vector(code_challenge_methods_supported))
    !isempty(token_endpoint_auth_methods_supported) && (metadata["token_endpoint_auth_methods_supported"] = normalize_string_vector(token_endpoint_auth_methods_supported))
    !isempty(token_endpoint_auth_signing_alg_values_supported) && (metadata["token_endpoint_auth_signing_alg_values_supported"] = normalize_string_vector(token_endpoint_auth_signing_alg_values_supported))
    !isempty(scopes_supported) && (metadata["scopes_supported"] = normalize_string_vector(scopes_supported))
    return AuthorizationServerConfig(
        String(issuer),
        authorization_endpoint === nothing ? nothing : String(authorization_endpoint),
        token_endpoint === nothing ? nothing : String(token_endpoint),
        jwks_uri === nothing ? nothing : String(jwks_uri),
        device_authorization_endpoint === nothing ? nothing : String(device_authorization_endpoint),
        introspection_endpoint === nothing ? nothing : String(introspection_endpoint),
        revocation_endpoint === nothing ? nothing : String(revocation_endpoint),
        normalize_string_vector(response_types_supported),
        normalize_string_vector(grant_types_supported),
        normalize_string_vector(code_challenge_methods_supported),
        normalize_string_vector(token_endpoint_auth_methods_supported),
        normalize_string_vector(token_endpoint_auth_signing_alg_values_supported),
        normalize_string_vector(scopes_supported),
        metadata,
        ensure_slash(path),
    )
end

function register_authorization_server_metadata!(router::HTTP.Router, config::AuthorizationServerConfig; path::AbstractString=config.path)
    handler = _ -> json_response(config.metadata)
    HTTP.register!(router, "GET", ensure_slash(path), handler)
    return handler
end

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

mutable struct JWTAccessTokenIssuer
    issuer::String
    audience::Vector{String}
    signer::JWTSigner
    alg::Symbol
    kid::Union{String,Nothing}
    expires_in::Int
    public_jwk::Union{Dict{String,Any},Nothing}
end

function JWTAccessTokenIssuer(; issuer, audience, private_key, alg::Union{Symbol,AbstractString}=:RS256, kid=nothing, expires_in::Integer=3600, public_jwk=nothing)
    alg_symbol = alg isa Symbol ? alg : Symbol(alg)
    signer = if alg_symbol in SUPPORTED_RSA_ALGS
        rsa_signer_from_bytes(private_key)
    elseif alg_symbol in SUPPORTED_EC_ALGS
        curve = alg_symbol == :ES256 ? :P256 : :P384
        ecc_signer_from_bytes(private_key, curve)
    else
        throw(ArgumentError("Unsupported signing alg $(alg_symbol)"))
    end
    aud = normalize_string_vector(audience)
    kid_value = maybe_string(kid)
    jwk_dict = public_jwk === nothing ? derive_signing_jwk(private_key, signer, alg_symbol, kid_value) : normalize_metadata_dict(public_jwk)
    return JWTAccessTokenIssuer(String(issuer), aud, signer, alg_symbol, kid_value, Int(expires_in), jwk_dict)
end

abstract type AccessTokenStore end

struct IssuedAccessToken
    token::String
    claims::Dict{String,Any}
    scope::Vector{String}
    issued_at::DateTime
    expires_at::DateTime
    client_id::Union{String,Nothing}
    subject::Union{String,Nothing}
end

function token_audience(issuer::JWTAccessTokenIssuer, audience)
    aud = audience === nothing ? issuer.audience : normalize_string_vector(audience)
    return length(aud) == 1 ? aud[1] : aud
end

function issue_access_token(issuer::JWTAccessTokenIssuer; subject=nothing, client_id=nothing, scope=String[], authorization_details=nothing, extra_claims=Dict{String,Any}(), audience=nothing, now::DateTime=Dates.now(UTC), store::Union{Nothing,AccessTokenStore}=nothing)
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
    header = Dict{String,Any}("typ" => "JWT")
    issuer.kid !== nothing && (header["kid"] = issuer.kid)
    token = build_jws_compact(header, claims, issuer.signer, issuer.alg)
    issued = IssuedAccessToken(token, claims, normalize_string_vector(scope), now, expires_at, client_id === nothing ? nothing : String(client_id), subject === nothing ? nothing : String(subject))
    store === nothing || store_access_token!(store, issued)
    return issued
end

function ensure_public_jwk!(issuer::JWTAccessTokenIssuer)
    issuer.public_jwk === nothing && error("JWT access token issuer is missing a public JWK")
    return issuer.public_jwk
end

public_jwk(issuer::JWTAccessTokenIssuer) = ensure_public_jwk!(issuer)

function derive_signing_jwk(private_key, signer::RSASigner, alg::Symbol, kid::Union{String,Nothing})
    modulus, exponent = rsa_public_components_from_private_bytes(private_key)
    jwk = Dict(
        "kty" => "RSA",
        "n" => base64urlencode(modulus),
        "e" => base64urlencode(exponent),
        "alg" => String(alg),
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
        "alg" => String(alg),
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
end

mutable struct InMemoryTokenStore <: AccessTokenStore
    lock::ReentrantLock
    records::Dict{String,AccessTokenRecord}
end

InMemoryTokenStore() = InMemoryTokenStore(ReentrantLock(), Dict{String,AccessTokenRecord}())

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
    )
    lock(store.lock) do
        store.records[issued.token] = record
    end
    return record
end

function lookup_access_token(store::InMemoryTokenStore, token::AbstractString)
    lock(store.lock) do
        return get(store.records, String(token), nothing)
    end
end

function revoke_access_token!(store::InMemoryTokenStore, token::AbstractString)
    lock(store.lock) do
        record = get(store.records, String(token), nothing)
        record === nothing && return false
        record.revoked = true
        return true
    end
end

abstract type EndpointAuthenticator end
struct AllowAllAuthenticator <: EndpointAuthenticator end
struct BasicCredentialsAuthenticator <: EndpointAuthenticator
    realm::String
    credentials::Dict{String,String}
end

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

struct TokenValidationConfig
    issuer::String
    audience::Vector{String}
    allowed_algs::Set{Symbol}
    leeway::Dates.Second
    keys::Vector{VerificationKey}
end

struct AccessTokenClaims
    token::String
    subject::Union{String,Nothing}
    client_id::Union{String,Nothing}
    scope::Vector{String}
    audience::Vector{String}
    expires_at::DateTime
    issued_at::Union{DateTime,Nothing}
    claims::Dict{String,Any}
end

function AccessTokenClaims(; token, subject, client_id, scope, audience, expires_at, issued_at, claims)
    return AccessTokenClaims(
        String(token),
        subject,
        client_id,
        scope,
        audience,
        expires_at,
        issued_at,
        claims,
    )
end

function TokenValidationConfig(; issuer, audience, jwks, allowed_algs=(:RS256, :ES256, :ES384), leeway_seconds::Integer=60)
    aud = normalize_string_vector(audience)
    allowed = Set(Symbol.(allowed_algs))
    keys = build_verification_keys(jwks)
    isempty(keys) && throw(ArgumentError("jwks must contain at least one key"))
    return TokenValidationConfig(String(issuer), aud, allowed, Dates.Second(leeway_seconds), keys)
end

function build_verification_keys(jwks)
    key_entries = jwks isa Dict ? (haskey(jwks, "keys") ? jwks["keys"] : jwks) : jwks
    key_entries isa AbstractVector || throw(ArgumentError("jwks must be a Dict or Vector"))
    keys = VerificationKey[]
    for item in key_entries
        kty = uppercase(String(item["kty"]))
        kid = haskey(item, "kid") ? String(item["kid"]) : nothing
        alg = haskey(item, "alg") ? Symbol(String(item["alg"])) : nothing
        use = haskey(item, "use") ? String(item["use"]) : nothing
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
        else
            error("Unsupported JWK kty $(kty)")
        end
        push!(keys, VerificationKey(kid=kid, alg=alg, use=use, kty=kty, verifier=verifier))
    end
    return keys
end

function select_verification_key(config::TokenValidationConfig, alg::Symbol, kid::Union{String,Nothing})
    for key in config.keys
        if kid !== nothing && key.kid !== nothing && key.kid != kid
            continue
        end
        if key.alg !== nothing && key.alg != alg
            continue
        end
        if (key.verifier isa RSAVerifier && alg in SUPPORTED_RSA_ALGS) || (key.verifier isa ECVerifier && alg in SUPPORTED_EC_ALGS)
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
    )
end

function quote_auth_value(value)
    escaped = replace(String(value), "\"" => "\\\"")
    return "\"$(escaped)\""
end

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

function protected_resource_middleware(handler::Function, validator::TokenValidationConfig; resource_metadata_url::AbstractString, realm=nothing, required_scopes=String[], context_key::Symbol=:oauth_token)
    scopes = [String(s) for s in required_scopes]
    function middleware(req::HTTP.Request)
        token = bearer_token(req)
        if isempty(token)
            return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes)
        end
        claims = try
            validate_jwt_access_token(token, validator; required_scopes=scopes)
        catch err
            if err isa OAuthError && err.code == :insufficient_scope
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="insufficient_scope", error_description=err.message, status=403)
            elseif err isa OAuthError
                return unauthorized_response(resource_metadata_url; realm=realm, required_scopes=scopes, error_code="invalid_token", error_description=err.message)
            else
                rethrow()
            end
        end
        req.context[context_key] = claims
        return handler(req)
    end
    return middleware
end

function build_introspection_handler(store::InMemoryTokenStore; authenticator::EndpointAuthenticator=AllowAllAuthenticator())
    function handler(req::HTTP.Request)
        authenticate_request(authenticator, req) || return unauthorized_endpoint_response(authenticator)
        HTTP.method(req) == "POST" || return HTTP.Response(405, HTTP.Headers(["Allow" => "POST"]), "")
        body_bytes = request_body_bytes(req)
        params = parse_form_urlencoded(body_bytes)
        token = get(params, "token", nothing)
        token === nothing && return json_response(Dict("error" => "invalid_request", "error_description" => "token parameter is required"); status=400)
        record = lookup_access_token(store, token)
        if record === nothing || record.revoked || Dates.now(UTC) > record.expires_at
            return json_response(Dict("active" => false))
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
        return json_response(response)
    end
    return handler
end

function build_revocation_handler(store::InMemoryTokenStore; authenticator::EndpointAuthenticator=AllowAllAuthenticator())
    function handler(req::HTTP.Request)
        authenticate_request(authenticator, req) || return unauthorized_endpoint_response(authenticator)
        HTTP.method(req) == "POST" || return HTTP.Response(405, HTTP.Headers(["Allow" => "POST"]), "")
        body_bytes = request_body_bytes(req)
        params = parse_form_urlencoded(body_bytes)
        token = get(params, "token", nothing)
        token === nothing && return json_response(Dict("error" => "invalid_request", "error_description" => "token parameter is required"); status=400)
        revoke_access_token!(store, token)
        return HTTP.Response(200, HTTP.Headers(), "")
    end
    return handler
end
