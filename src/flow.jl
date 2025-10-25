const DEFAULT_RESPONSE_TYPE = "code"

function build_authorization_url(request::AuthorizationRequest)
    params = Pair{String,String}[]
    push!(params, "response_type" => request.response_type)
    push!(params, "client_id" => request.client_id)
    push!(params, "redirect_uri" => request.redirect_uri)
    request.scope !== nothing && push!(params, "scope" => request.scope)
    push!(params, "state" => request.state)
    if request.code_challenge !== nothing
        push!(params, "code_challenge" => request.code_challenge)
        method = something(request.code_challenge_method, "S256")
        push!(params, "code_challenge_method" => method)
    end
    if !isempty(request.extra)
        for key in sort(collect(keys(request.extra)))
            push!(params, key => request.extra[key])
        end
    end
    query = join(escape_pair.(params), '&')
    delimiter = occursin('?', request.authorization_endpoint) ? '&' : '?'
    return string(request.authorization_endpoint, delimiter, query)
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

function verify_token_endpoint_auth_support(metadata::AuthorizationServerMetadata, credential::TokenEndpointAuth)
    throw(OAuthError(:configuration_error, "Unsupported credential type $(typeof(credential)) for token endpoint authentication"))
end

function start_pkce_authorization(
    prm_url::AbstractString,
    config::PublicClientConfig;
    http=HTTP,
    state=nothing,
    verifier::Union{PKCEVerifier,Nothing}=nothing,
    open_browser::Bool=true,
    wait::Bool=false,
    browser_command::Union{Cmd,Nothing}=nothing,
    issuer::Union{String,Nothing}=nothing,
    extra_authorize_params=Dict{String,String}(),
    verbose::Bool=false,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
)
    resource_meta = fetch_protected_resource_metadata(prm_url; http=http, verbose=verbose)
    issuer_url = select_authorization_server(resource_meta; issuer=issuer)
    auth_meta = fetch_authorization_server_metadata(issuer_url; http=http, verbose=verbose)
    return prepare_pkce_session(
        auth_meta,
        resource_meta,
        config;
        state=state,
        verifier=verifier,
        open_browser=open_browser,
        wait=wait,
        browser_command=browser_command,
        extra_authorize_params=extra_authorize_params,
        verbose=verbose,
        redirect_uri=redirect_uri,
        start_listener=start_listener,
        listener_host=listener_host,
        listener_port=listener_port,
        listener_path=listener_path,
    )
end

function start_pkce_authorization_from_issuer(
    issuer_url::AbstractString,
    config::PublicClientConfig;
    http=HTTP,
    state=nothing,
    verifier::Union{PKCEVerifier,Nothing}=nothing,
    open_browser::Bool=true,
    wait::Bool=false,
    browser_command::Union{Cmd,Nothing}=nothing,
    extra_authorize_params=Dict{String,String}(),
    verbose::Bool=false,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
)
    auth_meta = fetch_authorization_server_metadata(issuer_url; http=http, verbose=verbose)
    return prepare_pkce_session(
        auth_meta,
        nothing,
        config;
        state=state,
        verifier=verifier,
        open_browser=open_browser,
        wait=wait,
        browser_command=browser_command,
        extra_authorize_params=extra_authorize_params,
        verbose=verbose,
        redirect_uri=redirect_uri,
        start_listener=start_listener,
        listener_host=listener_host,
        listener_port=listener_port,
        listener_path=listener_path,
    )
end

function prepare_pkce_session(
    auth_meta::AuthorizationServerMetadata,
    resource_meta::Union{ProtectedResourceMetadata,Nothing},
    config::PublicClientConfig;
    state,
    verifier,
    open_browser::Bool,
    wait::Bool,
    browser_command::Union{Cmd,Nothing},
    extra_authorize_params::Dict{String,String},
    verbose::Bool,
    redirect_uri,
    start_listener::Bool,
    listener_host::AbstractString,
    listener_port::Integer,
    listener_path::AbstractString,
)
    auth_meta.authorization_endpoint === nothing && throw(OAuthError(:metadata_error, "Authorization endpoint missing in issuer metadata"))
    if !isempty(auth_meta.code_challenge_methods_supported)
        methods = String.(auth_meta.code_challenge_methods_supported)
        supports_s256 = any(method -> uppercase(method) == "S256", methods)
        if supports_s256
            # ok
        elseif any(method -> lowercase(method) == "plain", methods)
            throw(OAuthError(:pkce_unsupported, "Authorization server only supports plain PKCE challenge which is insecure"))
        else
            throw(OAuthError(:pkce_unsupported, "Authorization server does not advertise PKCE S256 support"))
        end
    end
    if !isempty(auth_meta.grant_types_supported)
        has_auth_code = any(gt -> lowercase(String(gt)) == "authorization_code", auth_meta.grant_types_supported)
        has_auth_code || throw(OAuthError(:metadata_error, "Authorization server does not advertise authorization_code grant support"))
    end
    verifier = verifier === nothing ? generate_pkce_verifier() : verifier
    challenge = pkce_challenge(verifier)
    state_value = state === nothing ? random_state() : String(state)
    dest_redirect = redirect_uri === nothing ? config.redirect_uri : redirect_uri
    normalized_path = ensure_slash(listener_path)
    default_redirect = "http://$(listener_host):$(listener_port)$(normalized_path)"
    effective_redirect = dest_redirect === nothing ? default_redirect : String(dest_redirect)
    start_loopback = start_listener && urls_equivalent(effective_redirect, default_redirect) && startswith(lowercase(effective_redirect), "http://")
    if !start_loopback && dest_redirect === nothing && !start_listener
        throw(OAuthError(:redirect_uri_missing, "redirect_uri must be provided when loopback listener is disabled"))
    end
    listener = nothing
    if start_loopback
        try
            listener = start_loopback_listener(listener_host, listener_port, normalized_path; verbose=verbose)
        catch err
            throw(OAuthError(:listener_error, "Failed to start loopback listener: $(err)"))
        end
    end
    scope_value = isempty(config.scopes) ? nothing : join(config.scopes, ' ')
    extra = StringParams()
    for (k, v) in config.additional_parameters
        extra[k] = v
    end
    for (k, v) in extra_authorize_params
        extra[String(k)] = String(v)
    end
    session_config = PublicClientConfig(
        client_id = config.client_id,
        redirect_uri = effective_redirect,
        scopes = config.scopes,
        additional_parameters = config.additional_parameters,
        dpop = config.dpop,
    )
    try
        request = AuthorizationRequest(
            authorization_endpoint = String(auth_meta.authorization_endpoint),
            response_type = DEFAULT_RESPONSE_TYPE,
            client_id = session_config.client_id,
            redirect_uri = session_config.redirect_uri === nothing ? default_redirect : session_config.redirect_uri,
            scope = scope_value,
            state = state_value,
            code_challenge = challenge,
            code_challenge_method = "S256",
            extra = extra,
        )
        url = build_authorization_url(request)
        if open_browser
            launch_browser(url; wait=wait, command=browser_command)
        end
        return AuthorizationSession(
            authorization_url = url,
            redirect_uri = request.redirect_uri,
            verifier = verifier,
            state = state_value,
            authorization_server = auth_meta,
            resource = resource_meta,
            client_config = session_config,
            listener = listener,
        )
    catch err
        listener !== nothing && stop_loopback_listener(listener)
        rethrow(err)
    end
end

function exchange_code_for_token(metadata::AuthorizationServerMetadata, config::PublicClientConfig, code::AbstractString, verifier::PKCEVerifier; http=HTTP, extra_params=Dict{String,String}(), verbose::Bool=false)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    ensure_https_url(String(metadata.token_endpoint), "token_endpoint")
    config.redirect_uri === nothing && throw(OAuthError(:configuration_error, "redirect_uri required for token exchange"))
    issued_at = now(UTC)
    form = Dict{String,String}(
        "grant_type" => "authorization_code",
        "code" => String(code),
        "client_id" => config.client_id,
        "redirect_uri" => config.redirect_uri,
        "code_verifier" => verifier.verifier,
    )
    for (k, v) in extra_params
        form[String(k)] = String(v)
    end
    body = encode_form(form)
    headers_pairs = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    if config.dpop !== nothing
        proof = create_dpop_proof(config.dpop, "POST", String(metadata.token_endpoint), issued_at)
        push!(headers_pairs, "DPoP" => proof)
    end
    headers = HTTP.Headers(headers_pairs)
    resp = http_request(http, "POST", String(metadata.token_endpoint); headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Token request failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    nonce_header = HTTP.header(resp.headers, "DPoP-Nonce")
    nonce_value = isempty(nonce_header) ? nothing : String(nonce_header)
    return TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
end

function wait_for_authorization_code(session::AuthorizationSession; timeout::Real=120)
    listener = session.listener
    listener === nothing && throw(OAuthError(:listener_missing, "No loopback listener available for this session"))
    params = try
        take_with_timeout(listener.result_channel, timeout)
    catch err
        stop_loopback_listener(listener)
        rethrow(err)
    end
    stop_loopback_listener(listener)
    if haskey(params, "error")
        description = get(params, "error_description", "")
        message = isempty(description) ? params["error"] : "$(params["error"]): $description"
        throw(OAuthError(:authorization_error, message))
    end
    code = get(params, "code", nothing)
    code === nothing && throw(OAuthError(:authorization_error, "Authorization response missing code parameter"))
    resp_state = get(params, "state", nothing)
    resp_state === nothing && throw(OAuthError(:authorization_error, "Authorization response missing state parameter"))
    resp_state == session.state || throw(OAuthError(:state_mismatch, "Authorization response state did not match request"))
    return (code = String(code), state = String(resp_state), params = params)
end

function complete_pkce_authorization(
    prm_url::AbstractString,
    config::PublicClientConfig;
    http=HTTP,
    state=nothing,
    verifier::Union{PKCEVerifier,Nothing}=nothing,
    open_browser::Bool=true,
    wait::Bool=false,
    browser_command::Union{Cmd,Nothing}=nothing,
    issuer::Union{String,Nothing}=nothing,
    extra_authorize_params=Dict{String,String}(),
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
    timeout::Real=180,
)
    session = start_pkce_authorization(
        prm_url,
        config;
        http=http,
        state=state,
        verifier=verifier,
        open_browser=open_browser,
        wait=wait,
        browser_command=browser_command,
        issuer=issuer,
        extra_authorize_params=extra_authorize_params,
        verbose=verbose,
        redirect_uri=redirect_uri,
        start_listener=start_listener,
        listener_host=listener_host,
        listener_port=listener_port,
        listener_path=listener_path,
    )
    return finalize_pkce_session(
        session;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
        timeout=timeout,
    )
end

function complete_pkce_authorization_from_issuer(
    issuer_url::AbstractString,
    config::PublicClientConfig;
    http=HTTP,
    state=nothing,
    verifier::Union{PKCEVerifier,Nothing}=nothing,
    open_browser::Bool=true,
    wait::Bool=false,
    browser_command::Union{Cmd,Nothing}=nothing,
    extra_authorize_params=Dict{String,String}(),
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
    timeout::Real=180,
)
    session = start_pkce_authorization_from_issuer(
        issuer_url,
        config;
        http=http,
        state=state,
        verifier=verifier,
        open_browser=open_browser,
        wait=wait,
        browser_command=browser_command,
        extra_authorize_params=extra_authorize_params,
        verbose=verbose,
        redirect_uri=redirect_uri,
        start_listener=start_listener,
        listener_host=listener_host,
        listener_port=listener_port,
        listener_path=listener_path,
    )
    return finalize_pkce_session(
        session;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
        timeout=timeout,
    )
end

function finalize_pkce_session(
    session::AuthorizationSession;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
    timeout::Real=180,
)
    extra_params = Dict{String,String}()
    for (k, v) in extra_token_params
        extra_params[String(k)] = String(v)
    end
    try
        callback = wait_for_authorization_code(session; timeout=timeout)
        token = exchange_code_for_token(
            session.authorization_server,
            session.client_config,
            callback.code,
            session.verifier;
            http=http,
            extra_params=extra_params,
            verbose=verbose,
        )
        return (token = token, session = session, callback = callback)
    catch err
        session.listener !== nothing && stop_loopback_listener(session.listener)
        rethrow(err)
    end
end

# ----- client credentials flow -----

function request_client_credentials_token(
    metadata::AuthorizationServerMetadata,
    config::ConfidentialClientConfig;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    ensure_https_url(String(metadata.token_endpoint), "token_endpoint")
    if !isempty(metadata.grant_types_supported)
        has_client_credentials = any(gt -> lowercase(String(gt)) == "client_credentials", metadata.grant_types_supported)
        has_client_credentials || throw(OAuthError(:metadata_error, "Authorization server does not advertise client_credentials grant support"))
    end
    verify_token_endpoint_auth_support(metadata, config.credential)
    issued_at = now(UTC)
    form = StringParams()
    if !isempty(config.scopes)
        form["scope"] = join(config.scopes, ' ')
    end
    for (k, v) in config.additional_parameters
        form[k] = v
    end
    for (k, v) in extra_token_params
        form[String(k)] = String(v)
    end
    headers_data = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    credential = config.credential
    endpoint = String(metadata.token_endpoint)
    if credential isa ClientSecretAuth
        if credential.method == :client_secret_post
            form["client_id"] = config.client_id
            form["client_secret"] = credential.secret
        elseif credential.method == :client_secret_basic
            credentials = string(form_escape(config.client_id), ":", form_escape(credential.secret))
            encoded = Base64.base64encode(credentials)
            push!(headers_data, "Authorization" => "Basic $(encoded)")
        else
            throw(OAuthError(:configuration_error, "Unsupported client secret auth method $(credential.method)"))
        end
    elseif credential isa PrivateKeyJWTAuth
        audience = credential.audience === nothing ? endpoint : String(credential.audience)
        assertion = build_client_assertion(credential, config.client_id, audience, issued_at)
        form["client_assertion"] = assertion
        form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        form["client_id"] = config.client_id
    else
        throw(OAuthError(:configuration_error, "Unsupported token endpoint credential type $(typeof(credential))"))
    end
    form["grant_type"] = "client_credentials"
    body = encode_form(form)
    if config.dpop !== nothing
        proof = create_dpop_proof(config.dpop, "POST", endpoint, issued_at)
        push!(headers_data, "DPoP" => proof)
    end
    headers = HTTP.Headers(headers_data)
    resp = http_request(http, "POST", endpoint; headers=headers, body=body, verbose=verbose, DEFAULT_TIMEOUT...)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Token request failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    nonce_header = HTTP.header(resp.headers, "DPoP-Nonce")
    nonce_value = isempty(nonce_header) ? nothing : String(nonce_header)
    return TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
end

function request_client_credentials_token_from_issuer(
    issuer_url::AbstractString,
    config::ConfidentialClientConfig;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
)
    auth_meta = fetch_authorization_server_metadata(issuer_url; http=http, verbose=verbose)
    token = request_client_credentials_token(
        auth_meta,
        config;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
    )
    return (token = token, authorization_server = auth_meta)
end

function request_client_credentials_token(
    prm_url::AbstractString,
    config::ConfidentialClientConfig;
    http=HTTP,
    issuer=nothing,
    extra_token_params=Dict{String,String}(),
    verbose::Bool=false,
)
    resource_meta = fetch_protected_resource_metadata(prm_url; http=http, verbose=verbose)
    issuer_url = select_authorization_server(resource_meta; issuer=issuer)
    result = request_client_credentials_token_from_issuer(
        issuer_url,
        config;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
    )
    return (token = result.token, authorization_server = result.authorization_server, resource = resource_meta)
end
