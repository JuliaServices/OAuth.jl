 

function request_client_credentials_token(
    metadata::AuthorizationServerMetadata,
    config::ConfidentialClientConfig;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
    resource_metadata::Union{ProtectedResourceMetadata,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    ensure_https_url(String(metadata.token_endpoint), "token_endpoint")
    if !isempty(metadata.grant_types_supported)
        has_client_credentials = any(gt -> lowercase(String(gt)) == "client_credentials", metadata.grant_types_supported)
        has_client_credentials || throw(OAuthError(:metadata_error, "Authorization server does not advertise client_credentials grant support"))
    end
    verify_token_endpoint_auth_support(metadata, config.credential)
    form = FormParams()
    scope_candidates = effective_scope_list(config.scopes, resource_metadata, metadata)
    if !isempty(scope_candidates)
        set!(form, "scope", join(scope_candidates, ' '))
    end
    combined_params = copy(config.additional_parameters)
    for (k, v) in extra_token_params
        combined_params[String(k)] = String(v)
    end
    auth_override, resource_override = extract_special_authorize_params!(combined_params)
    for (k, v) in combined_params
        set!(form, k, v)
    end
    resources_value = isempty(resource_override) ? effective_resources(config.resources, resource_metadata) : resource_override
    auth_details_value = auth_override === nothing ? config.authorization_details : auth_override
    headers_data = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    credential = config.credential
    endpoint = String(metadata.token_endpoint)
    request_kwargs = apply_token_endpoint_auth!(form, headers_data, credential, config.client_id, endpoint)
    set!(form, "grant_type", "client_credentials")
    auth_text = authorization_details_json(auth_details_value)
    auth_text !== nothing && set!(form, "authorization_details", auth_text)
    if !isempty(resources_value)
        for resource in resources_value
            push!(form, "resource", resource)
        end
    end
    body = encode_form(form)
    resp, issued_at = perform_token_request(http, endpoint, headers_data, body, config.dpop; verbose=verbose, request_kwargs=request_kwargs)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Token request failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    nonce_value = dpop_nonce_from_response(resp)
    return TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
end

function request_client_credentials_token_from_issuer(
    issuer_url::AbstractString,
    config::ConfidentialClientConfig;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata_from_issuer(issuer_url; http=http, verbose=verbose)
    token = request_client_credentials_token(
        discovery.authorization_server,
        config;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
        resource_metadata=nothing,
    )
    return (token = token, authorization_server = discovery.authorization_server, discovery = discovery)
end

function request_client_credentials_token(
    prm_url::AbstractString,
    config::ConfidentialClientConfig;
    http=HTTP,
    issuer=nothing,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata(prm_url; issuer=issuer, http=http, verbose=verbose)
    token = request_client_credentials_token(
        discovery.authorization_server,
        config;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
        resource_metadata=discovery.resource,
    )
    return (
        token = token,
        authorization_server = discovery.authorization_server,
        resource = discovery.resource,
        discovery = discovery,
    )
end

function register_dynamic_client(
    metadata::AuthorizationServerMetadata,
    client_metadata;
    http=HTTP,
    initial_access_token=nothing,
    verbose::Bool=false,
)
    metadata.registration_endpoint === nothing && throw(OAuthError(:metadata_error, "Registration endpoint missing in issuer metadata"))
    endpoint = String(metadata.registration_endpoint)
    ensure_https_url(endpoint, "registration_endpoint")
    payload = normalize_registration_metadata(client_metadata)
    headers = HTTP.Headers([
        "Content-Type" => "application/json",
        "Accept" => "application/json",
    ])
    if initial_access_token !== nothing
        set_request_header!(headers, "Authorization", string("Bearer ", initial_access_token))
    end
    body = JSON.json(payload)
    resp = http_request(http, "POST", endpoint; headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Client registration failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object from registration endpoint"))
    return JSONObject(data)
end

function register_dynamic_client_from_issuer(
    issuer_url::AbstractString,
    client_metadata;
    http=HTTP,
    initial_access_token=nothing,
    verbose::Bool=false,
)
    metadata = fetch_authorization_server_metadata(issuer_url; http=http, verbose=verbose)
    client = register_dynamic_client(
        metadata,
        client_metadata;
        http=http,
        initial_access_token=initial_access_token,
        verbose=verbose,
    )
    return (client = client, authorization_server = metadata)
end

function update_dynamic_client(
    configuration_endpoint::AbstractString,
    client_metadata;
    http=HTTP,
    registration_access_token,
    verbose::Bool=false,
)
    registration_access_token === nothing && throw(ArgumentError("registration_access_token is required for client update"))
    ensure_https_url(configuration_endpoint, "client_configuration_endpoint")
    payload = normalize_registration_metadata(client_metadata)
    headers = HTTP.Headers([
        "Content-Type" => "application/json",
        "Accept" => "application/json",
        "Authorization" => string("Bearer ", registration_access_token),
    ])
    body = JSON.json(payload)
    resp = http_request(http, "PUT", configuration_endpoint; headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Client update failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object from client configuration endpoint"))
    return JSONObject(data)
end

function delete_dynamic_client(
    configuration_endpoint::AbstractString;
    http=HTTP,
    registration_access_token,
    verbose::Bool=false,
)
    registration_access_token === nothing && throw(ArgumentError("registration_access_token is required for client deletion"))
    ensure_https_url(configuration_endpoint, "client_configuration_endpoint")
    headers = HTTP.Headers([
        "Accept" => "application/json",
        "Authorization" => string("Bearer ", registration_access_token),
    ])
    resp = http_request(http, "DELETE", configuration_endpoint; headers=headers, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Client deletion failed (status=$status)"))
    return true
end
