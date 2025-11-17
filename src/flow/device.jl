 

function start_device_authorization(
    metadata::AuthorizationServerMetadata,
    config::Union{PublicClientConfig,ConfidentialClientConfig};
    http=HTTP,
    extra_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
    resource_metadata::Union{ProtectedResourceMetadata,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    metadata.device_authorization_endpoint === nothing && throw(OAuthError(:metadata_error, "Device authorization endpoint missing in issuer metadata"))
    endpoint = String(metadata.device_authorization_endpoint)
    ensure_https_url(endpoint, "device_authorization_endpoint")
    form = FormParams()
    scope_values = effective_scope_list(config.scopes, resource_metadata, metadata)
    !isempty(scope_values) && set!(form, "scope", join(scope_values, ' '))
    extras = copy(config.additional_parameters)
    for (k, v) in extra_params
        extras[String(k)] = String(v)
    end
    auth_override, resource_override = extract_special_authorize_params!(extras)
    for (k, v) in extras
        set!(form, k, v)
    end
    resources_value = isempty(resource_override) ? effective_resources(config.resources, resource_metadata) : resource_override
    auth_details_value = auth_override === nothing ? config.authorization_details : auth_override
    headers = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    request_kwargs = NamedTuple()
    if config isa ConfidentialClientConfig
        request_kwargs = apply_token_endpoint_auth!(form, headers, config.credential, config.client_id, endpoint)
    else
        set!(form, "client_id", config.client_id)
    end
    auth_text = authorization_details_json(auth_details_value)
    auth_text !== nothing && set!(form, "authorization_details", auth_text)
    if !isempty(resources_value)
        for resource in resources_value
            push!(form, "resource", resource)
        end
    end
    body = encode_form(form)
    resp, issued_at = perform_token_request(http, endpoint, headers, body, client_dpop(config); verbose=verbose, request_kwargs=request_kwargs)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Device authorization request failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    return DeviceAuthorizationResponse(data; issued_at=issued_at)
end

function start_device_authorization(
    prm_url::AbstractString,
    config::Union{PublicClientConfig,ConfidentialClientConfig};
    http=HTTP,
    issuer=nothing,
    extra_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata(prm_url; issuer=issuer, http=http, verbose=verbose)
    device = start_device_authorization(
        discovery.authorization_server,
        config;
        http=http,
        extra_params=extra_params,
        verbose=verbose,
        resource_metadata=discovery.resource,
    )
    return (
        device = device,
        authorization_server = discovery.authorization_server,
        resource = discovery.resource,
        discovery = discovery,
    )
end

function start_device_authorization_from_issuer(
    issuer_url::AbstractString,
    config::Union{PublicClientConfig,ConfidentialClientConfig};
    http=HTTP,
    extra_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata_from_issuer(issuer_url; http=http, verbose=verbose)
    device = start_device_authorization(
        discovery.authorization_server,
        config;
        http=http,
        extra_params=extra_params,
        verbose=verbose,
        resource_metadata=nothing,
    )
    return (device = device, authorization_server = discovery.authorization_server, discovery = discovery)
end

function poll_device_authorization_token(
    metadata::AuthorizationServerMetadata,
    config::Union{PublicClientConfig,ConfidentialClientConfig},
    device::DeviceAuthorizationResponse;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
    sleep_function::Function=sleep,
)
    verbose = effective_verbose(config, verbose)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    endpoint = String(metadata.token_endpoint)
    ensure_https_url(endpoint, "token_endpoint")
    interval = device.interval
    has_polled = false
    while true
        now_time = now(UTC)
        now_time > device.expires_at && break
        if has_polled
            wait_seconds = max(Dates.value(interval), 0)
            wait_seconds > 0 && sleep_function(float(wait_seconds))
        else
            has_polled = true
        end
        form = FormParams()
        set!(form, "grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        set!(form, "device_code", device.device_code)
        if config isa PublicClientConfig
            set!(form, "client_id", config.client_id)
        end
        token_extra = copy(config.additional_parameters)
        for (k, v) in extra_token_params
            token_extra[String(k)] = String(v)
        end
        auth_override, resource_override = extract_special_authorize_params!(token_extra)
        for (k, v) in token_extra
            set!(form, k, v)
        end
        resources_value = isempty(resource_override) ? config.resources : resource_override
        auth_details_value = auth_override === nothing ? config.authorization_details : auth_override
        auth_text = authorization_details_json(auth_details_value)
        auth_text !== nothing && set!(form, "authorization_details", auth_text)
        headers = [
            "Content-Type" => "application/x-www-form-urlencoded",
            "Accept" => "application/json",
        ]
        request_kwargs = NamedTuple()
        if config isa ConfidentialClientConfig
            request_kwargs = apply_token_endpoint_auth!(form, headers, config.credential, config.client_id, endpoint)
        end
        if !isempty(resources_value)
            for resource in resources_value
                push!(form, "resource", resource)
            end
        end
        body = encode_form(form)
        resp, issued_at = perform_token_request(http, endpoint, headers, body, client_dpop(config); verbose=verbose, request_kwargs=request_kwargs)
        nonce_value = dpop_nonce_from_response(resp)
        status = resp.status
        if status in 200:299
            data = JSON.parse(String(resp.body))
            data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
            token = TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
            if config isa PublicClientConfig
                persist_refresh_token!(config, token)
            end
            return token
        end
        status in 400:499 || throw(OAuthError(:http_error, "Device token request failed (status=$status)"))
        err = try
            JSON.parse(String(resp.body))
        catch
            nothing
        end
        error_code = err isa AbstractDict ? get(err, "error", nothing) : nothing
        if error_code isa AbstractString
            code_lc = lowercase(String(error_code))
            if code_lc == "authorization_pending"
                continue
            elseif code_lc == "slow_down"
                interval += Dates.Second(5)
                continue
            elseif code_lc == "expired_token"
                throw(OAuthError(:invalid_grant, "Device code expired"))
            elseif code_lc == "access_denied"
                throw(OAuthError(:access_denied, "Device authorization denied"))
            end
        end
        description = err isa AbstractDict ? get(err, "error_description", nothing) : nothing
        message = description isa AbstractString ? String(description) : "Device token request failed"
        throw(OAuthError(:http_error, message))
    end
    throw(OAuthError(:timeout, "Device authorization expired before completion"))
end
