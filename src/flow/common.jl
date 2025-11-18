
export authorization_details_json, authorization_details_claim, effective_resources,
       extract_special_authorize_params!, normalize_registration_metadata,
       authorization_request_pairs, authorization_request_claims,
       request_object_audience, ensure_request_object_alg,
       build_request_object_jwt, token_transport_kwargs, client_dpop,
       perform_token_request, apply_token_endpoint_auth!,
       build_authorization_url, push_authorization_request,
       verify_token_endpoint_auth_support, dpop_nonce_from_response

function authorization_details_json(details)
    details === nothing && return nothing
    return details isa AbstractString ? String(details) : JSON.json(details)
end

function dpop_nonce_from_response(resp::HTTP.Response)
    nonce_header = HTTP.header(resp.headers, "DPoP-Nonce", "")
    if !isempty(nonce_header)
        return String(nonce_header)
    end
    www_value = HTTP.header(resp.headers, "WWW-Authenticate", "")
    isempty(www_value) && return nothing
    try
        for challenge in parse_www_authenticate(www_value)
            ascii_lc_isequal(challenge.scheme, "dpop") || continue
            nonce = get(challenge.params, "nonce", nothing)
            nonce !== nothing && return String(nonce)
        end
    catch
        lower = lowercase(String(www_value))
        occursin("dpop", lower) || return nothing
        match = match(r"nonce=\"([^\"]+)\"", String(www_value))
        return match === nothing ? nothing : String(match.captures[1])
    end
    return nothing
end

function authorization_details_claim(details)
    details === nothing && return nothing
    if details isa AbstractString
        parsed = try
            JSON.parse(String(details))
        catch
            nothing
        end
        return parsed === nothing ? details : parsed
    else
        return details
    end
end

function effective_resources(config_resources::Vector{String}, resource_meta::Union{ProtectedResourceMetadata,Nothing})
    if !isempty(config_resources)
        return copy(config_resources)
    end
    if resource_meta !== nothing && resource_meta.resource !== nothing
        return [String(resource_meta.resource)]
    end
    return String[]
end

function extract_special_authorize_params!(params::StringParams)
    auth_details = nothing
    resources = String[]
    if haskey(params, "authorization_details")
        auth_details = normalize_authorization_details_value(params["authorization_details"])
        delete!(params, "authorization_details")
    end
    if haskey(params, "resource")
        push!(resources, params["resource"])
        delete!(params, "resource")
    end
    return auth_details, resources
end

function normalize_registration_metadata(metadata)
    metadata isa AbstractDict || throw(ArgumentError("client metadata must be a dictionary"))
    normalized = Dict{String,Any}()
    for (k, v) in metadata
        normalized[String(k)] = v
    end
    return normalized
end

function authorization_request_pairs(request::AuthorizationRequest)
    if request.request_uri !== nothing
        return Pair{String,String}[
            "client_id" => request.client_id,
            "request_uri" => request.request_uri,
        ]
    elseif request.request !== nothing
        return Pair{String,String}[
            "client_id" => request.client_id,
            "request" => request.request,
        ]
    end
    params = FormParams()
    set!(params, "response_type", request.response_type)
    set!(params, "client_id", request.client_id)
    set!(params, "redirect_uri", request.redirect_uri)
    request.scope !== nothing && set!(params, "scope", request.scope)
    set!(params, "state", request.state)
    if request.code_challenge !== nothing
        set!(params, "code_challenge", request.code_challenge)
        method = something(request.code_challenge_method, "plain")
        set!(params, "code_challenge_method", method)
    end
    if !isempty(request.resources)
        for resource in request.resources
            push!(params, "resource", resource)
        end
    end
    auth_details = authorization_details_json(request.authorization_details)
    auth_details !== nothing && set!(params, "authorization_details", auth_details)
    if !isempty(request.extra)
        for key in sort(collect(keys(request.extra)))
            set!(params, key, request.extra[key])
        end
    end
    return form_pairs(params)
end

function authorization_request_claims(request::AuthorizationRequest)
    claims = Dict{String,Any}(
        "response_type" => request.response_type,
        "client_id" => request.client_id,
        "redirect_uri" => request.redirect_uri,
        "state" => request.state,
    )
    request.scope !== nothing && (claims["scope"] = request.scope)
    if request.code_challenge !== nothing
        claims["code_challenge"] = request.code_challenge
        method = something(request.code_challenge_method, "plain")
        claims["code_challenge_method"] = method
    end
    if !isempty(request.resources)
        claims["resource"] = copy(request.resources)
    end
    auth_details = authorization_details_claim(request.authorization_details)
    auth_details !== nothing && (claims["authorization_details"] = auth_details)
    for (k, v) in request.extra
        claims[k] = v
    end
    return claims
end

function request_object_audience(metadata::AuthorizationServerMetadata)
    metadata.issuer !== nothing && return String(metadata.issuer)
    metadata.authorization_endpoint !== nothing && return String(metadata.authorization_endpoint)
    return nothing
end

function ensure_request_object_alg(metadata::AuthorizationServerMetadata, signer::RequestObjectSigner)
    allowed = metadata.request_object_signing_alg_values_supported
    if !isempty(allowed)
        normalized = uppercase.(String.(allowed))
        alg_value = uppercase(String(signer.alg))
        alg_value in normalized || throw(OAuthError(:metadata_error, "Authorization server does not allow request object alg $(alg_value)"))
    end
end

function build_request_object_jwt(signer::RequestObjectSigner, request::AuthorizationRequest, metadata::AuthorizationServerMetadata, now::DateTime)
    ensure_request_object_alg(metadata, signer)
    payload = authorization_request_claims(request)
    aud = signer.audience === nothing ? request_object_audience(metadata) : signer.audience
    aud === nothing && throw(OAuthError(:configuration_error, "Unable to determine request object audience"))
    issued_at = Int(floor(Dates.datetime2unix(now))) - max(signer.clock_skew, 0)
    expires_at = issued_at + max(signer.expires_in, 0)
    payload["iss"] = request.client_id
    payload["sub"] = request.client_id
    payload["aud"] = String(aud)
    payload["iat"] = issued_at
    payload["exp"] = expires_at
    payload["jti"] = random_state()
    for (k, v) in signer.extra_claims
        payload[String(k)] = v
    end
    header = Dict{String,Any}("typ" => "JWT")
    signer.kid !== nothing && (header["kid"] = signer.kid)
    return build_jws_compact(header, payload, signer.signer, signer.alg)
end

token_transport_kwargs(::TokenEndpointAuth) = NamedTuple()
token_transport_kwargs(auth::TLSClientAuth) = (sslconfig = auth.sslconfig,)

client_dpop(config::PublicClientConfig) = config.dpop
client_dpop(config::ConfidentialClientConfig) = config.dpop

function perform_token_request(
    http,
    url::AbstractString,
    headers_pairs::Vector{Pair{String,String}},
    body::AbstractString,
    dpop::Union{DPoPAuth,Nothing};
    verbose::Bool=false,
    request_kwargs::NamedTuple=NamedTuple(),
)
    attempts = 0
    nonce_value = dpop === nothing ? nothing : cached_dpop_nonce(dpop, url)
    while true
        issued_at = now(UTC)
        request_headers = copy(headers_pairs)
        if dpop !== nothing
            proof = create_dpop_proof(dpop, "POST", url, issued_at; nonce=nonce_value)
            push!(request_headers, "DPoP" => proof)
        end
        headers = HTTP.Headers(request_headers)
        resp = http_request(http, "POST", url; headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT..., request_kwargs...)
        resp_nonce = dpop_nonce_from_response(resp)
        if dpop !== nothing && resp_nonce !== nothing
            cache_dpop_nonce!(dpop, url, resp_nonce)
        end
        should_retry = false
        if !(resp.status in 200:299) && dpop !== nothing && resp_nonce !== nothing && attempts < MAX_DPOP_NONCE_RETRIES
            json_err = try
                JSON.parse(String(resp.body))
            catch
                nothing
            end
            if json_err isa AbstractDict
                err_code = get(json_err, "error", nothing)
                if err_code isa AbstractString && lowercase(String(err_code)) == "use_dpop_nonce"
                    should_retry = true
                end
            end
        end
        if should_retry
            attempts += 1
            nonce_value = resp_nonce
            continue
        end
        return resp, issued_at
    end
end

function apply_token_endpoint_auth!(
    form::FormParams,
    headers::Vector{Pair{String,String}},
    credential::TokenEndpointAuth,
    client_id::String,
    endpoint::AbstractString,
)
    if credential isa ClientSecretAuth
        if credential.method == :client_secret_post
            set!(form, "client_id", client_id)
            set!(form, "client_secret", credential.secret)
        elseif credential.method == :client_secret_basic
            credentials = string(form_escape(client_id), ":", form_escape(credential.secret))
            encoded = Base64.base64encode(credentials)
            push!(headers, "Authorization" => "Basic $(encoded)")
        else
            throw(OAuthError(:configuration_error, "Unsupported client secret auth method $(credential.method)"))
        end
        return NamedTuple()
    elseif credential isa PrivateKeyJWTAuth
        audience = credential.audience === nothing ? String(endpoint) : String(credential.audience)
        assertion_time = now(UTC)
        assertion = build_client_assertion(credential, client_id, audience, assertion_time)
        set!(form, "client_assertion", assertion)
        set!(form, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        set!(form, "client_id", client_id)
        return NamedTuple()
    elseif credential isa ClientSecretJWTAuth
        audience = String(endpoint)
        assertion_time = now(UTC)
        assertion = build_client_assertion(credential, client_id, audience, assertion_time)
        set!(form, "client_assertion", assertion)
        set!(form, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        set!(form, "client_id", client_id)
        return NamedTuple()
    elseif credential isa TLSClientAuth
        set!(form, "client_id", client_id)
        return token_transport_kwargs(credential)
    else
        throw(OAuthError(:configuration_error, "Unsupported token endpoint credential type $(typeof(credential))"))
    end
end

"""
    build_authorization_url(request::AuthorizationRequest) -> String

Percent-encodes every parameter contained in an [`AuthorizationRequest`](@ref)
and returns the ready-to-launch URL.  Used internally by `start_pkce_authorization`,
but you can call it when you want to hand-craft the request struct first
(for example to tweak `authorization_details`).
"""
function build_authorization_url(request::AuthorizationRequest)
    params = authorization_request_pairs(request)
    query = join(escape_pair.(params), '&')
    delimiter = occursin('?', request.authorization_endpoint) ? '&' : '?'
    return string(request.authorization_endpoint, delimiter, query)
end

function push_authorization_request(http, endpoint::AbstractString, request::AuthorizationRequest; verbose::Bool=false)
    ensure_https_url(endpoint, "pushed_authorization_request_endpoint")
    headers = HTTP.Headers([
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ])
    pairs = authorization_request_pairs(request)
    body = encode_form(pairs)
    resp = http_request(http, "POST", endpoint; headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    if !(status in 200:299)
        message = "Pushed authorization request failed (status=$(status))"
        parsed = try
            JSON.parse(String(resp.body))
        catch
            nothing
        end
        if parsed isa AbstractDict
            err_code = get(parsed, "error", nothing)
            err_desc = get(parsed, "error_description", nothing)
            if err_code isa AbstractString
                message = String(err_code)
                if err_desc isa AbstractString
                    message = string(message, ": ", err_desc)
                end
            end
        end
        throw(OAuthError(:http_error, message))
    end
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object from PAR endpoint"))
    request_uri = get(data, "request_uri", nothing)
    request_uri isa AbstractString || throw(OAuthError(:metadata_error, "PAR response missing request_uri"))
    return String(request_uri)
end

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::ClientSecretAuth)
    if !isempty(metadata.token_endpoint_auth_methods_supported)
        supported = lowercase.(String.(metadata.token_endpoint_auth_methods_supported))
        method = lowercase(String(credential.method))
        method in supported || throw(OAuthError(:metadata_error, "Authorization server does not support token endpoint auth method $(method)"))
    end
end

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::PrivateKeyJWTAuth)
    if !isempty(metadata.token_endpoint_auth_methods_supported)
        supported = lowercase.(String.(metadata.token_endpoint_auth_methods_supported))
        "private_key_jwt" in supported || throw(OAuthError(:metadata_error, "Authorization server does not support private_key_jwt authentication"))
    end
    if !isempty(metadata.token_endpoint_auth_signing_alg_values_supported)
        allowed = uppercase.(String.(metadata.token_endpoint_auth_signing_alg_values_supported))
        alg = uppercase(String(credential.alg))
        alg in allowed || throw(OAuthError(:metadata_error, "Authorization server does not support JWT signing alg $(alg) for token endpoint authentication"))
    end
end

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::ClientSecretJWTAuth)
    if !isempty(metadata.token_endpoint_auth_methods_supported)
        supported = lowercase.(String.(metadata.token_endpoint_auth_methods_supported))
        "client_secret_jwt" in supported || throw(OAuthError(:metadata_error, "Authorization server does not support client_secret_jwt authentication"))
    end
    if !isempty(metadata.token_endpoint_auth_signing_alg_values_supported)
        allowed = uppercase.(String.(metadata.token_endpoint_auth_signing_alg_values_supported))
        alg = uppercase(String(credential.alg))
        alg in allowed || throw(OAuthError(:metadata_error, "Authorization server does not support JWT signing alg $(alg) for token endpoint authentication"))
    end
end

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::TLSClientAuth)
    if !isempty(metadata.token_endpoint_auth_methods_supported)
        supported = lowercase.(String.(metadata.token_endpoint_auth_methods_supported))
        method = lowercase(String(credential.method))
        method in supported || throw(OAuthError(:metadata_error, "Authorization server does not support $(credential.method) authentication"))
    end
end

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::TokenEndpointAuth)
    throw(OAuthError(:configuration_error, "Unsupported credential type $(typeof(credential)) for token endpoint authentication"))
end
