const DEFAULT_TIMEOUT = (readtimeout = 20, connecttimeout = 10)

function ensure_https_fields(metadata::AuthorizationServerMetadata)
    for (field, value) in (
        ("authorization_endpoint", metadata.authorization_endpoint),
        ("token_endpoint", metadata.token_endpoint),
        ("device_authorization_endpoint", metadata.device_authorization_endpoint),
        ("jwks_uri", metadata.jwks_uri),
        ("introspection_endpoint", metadata.introspection_endpoint),
        ("revocation_endpoint", metadata.revocation_endpoint),
        ("pushed_authorization_request_endpoint", metadata.pushed_authorization_request_endpoint),
        ("backchannel_authentication_endpoint", metadata.backchannel_authentication_endpoint),
        ("end_session_endpoint", metadata.end_session_endpoint),
        ("registration_endpoint", metadata.registration_endpoint),
    )
        value === nothing && continue
        ensure_https_url(String(value), field)
    end
    for (alias, endpoint) in metadata.mtls_endpoint_aliases
        ensure_https_url(String(endpoint), "mtls_endpoint_aliases.$alias")
    end
end

function fetch_protected_resource_metadata(url::AbstractString; headers=HTTP.Headers(), http=HTTP, verbose::Bool=false, kwargs...)
    ensure_https_url(url, "Protected resource metadata URL")
    resp = http_request(http, "GET", url; headers=headers, verbose=verbose, DEFAULT_TIMEOUT..., kwargs...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Failed to fetch protected resource metadata (status=$status)"))
    json = JSON.parse(String(resp.body))
    json isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    return ProtectedResourceMetadata(json)
end

function fetch_authorization_server_metadata(issuer::AbstractString; headers=HTTP.Headers(), http=HTTP, verbose::Bool=false, kwargs...)
    issuer_url = strip_trailing_slash(String(issuer))
    ensure_https_url(issuer_url, "Issuer URL")
    endpoints = [
        string(issuer_url, "/.well-known/oauth-authorization-server"),
        string(issuer_url, "/.well-known/openid-configuration"),
    ]
    last_err = nothing
    for endpoint in endpoints
        try
            resp = http_request(http, "GET", endpoint; headers=headers, verbose=verbose, DEFAULT_TIMEOUT..., kwargs...)
            status = resp.status
            status in 200:299 || throw(OAuthError(:http_error, "metadata request failed (status=$status)"))
            json = JSON.parse(String(resp.body))
            json isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
            metadata = AuthorizationServerMetadata(json)
            metadata.issuer === nothing && throw(OAuthError(:metadata_error, "Issuer metadata is missing the issuer field"))
            expected_issuer = strip_trailing_slash(String(metadata.issuer))
            expected_issuer == issuer_url || throw(OAuthError(:metadata_error, "Issuer mismatch: expected $(issuer_url), got $(expected_issuer)"))
            ensure_https_fields(metadata)
            return metadata
        catch err
            if err isa OAuthError && (err.code in (:metadata_error, :invalid_uri, :insecure_endpoint))
                throw(err)
            end
            last_err = err
        end
    end
    if last_err isa OAuthError
        throw(last_err)
    end
    throw(OAuthError(:metadata_error, "Unable to fetch authorization server metadata for issuer $issuer_url"))
end

function discover_oauth_metadata(prm_url::AbstractString; issuer::Union{Nothing,AbstractString}=nothing, headers=HTTP.Headers(), http=HTTP, verbose::Bool=false, kwargs...)
    resource_meta = fetch_protected_resource_metadata(prm_url; headers=headers, http=http, verbose=verbose, kwargs...)
    issuer_url = select_authorization_server(resource_meta; issuer=issuer)
    auth_meta = fetch_authorization_server_metadata(issuer_url; headers=headers, http=http, verbose=verbose, kwargs...)
    return OAuthDiscoveryContext(auth_meta, resource_meta)
end

function discover_oauth_metadata_from_issuer(issuer_url::AbstractString; headers=HTTP.Headers(), http=HTTP, verbose::Bool=false, kwargs...)
    auth_meta = fetch_authorization_server_metadata(issuer_url; headers=headers, http=http, verbose=verbose, kwargs...)
    return OAuthDiscoveryContext(auth_meta, nothing)
end

function select_authorization_server(metadata::ProtectedResourceMetadata; issuer::Union{Nothing,AbstractString}=nothing)
    isempty(metadata.authorization_servers) && throw(OAuthError(:metadata_error, "No authorization servers declared by resource"))
    if issuer !== nothing
        for candidate in metadata.authorization_servers
            candidate == issuer && return candidate
        end
        throw(OAuthError(:metadata_error, "Issuer $(issuer) not found in resource metadata"))
    end
    return first(metadata.authorization_servers)
end
