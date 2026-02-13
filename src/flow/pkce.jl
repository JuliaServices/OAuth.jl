"""
    start_pkce_authorization(prm_url, config; kwargs...) -> AuthorizationSession

Discovers metadata for the protected resource at `prm_url`, spins up (if
requested) a loopback HTTP listener, generates PKCE state/verifier values,
and optionally opens the user’s browser.  Returns an [`AuthorizationSession`](@ref)
that you can feed to [`wait_for_authorization_code`](@ref) or
[`finalize_pkce_session`](@ref).

# Examples
```julia
session = start_pkce_authorization(
    \"https://api.example/.well-known/oauth-resource\",
    PublicClientConfig(client_id = \"my-cli\"),
    open_browser = false,
    listener_port = 8888,
)

println(\"Open this URL: \", session.authorization_url)
```
"""
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
    verbose::Union{Bool,Nothing}=nothing,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata(prm_url; issuer=issuer, http=http, verbose=verbose)
    return prepare_pkce_session(
        discovery.authorization_server,
        discovery.resource,
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
        discovery_context=discovery,
        http=http,
    )
end

"""
    start_pkce_authorization_from_issuer(issuer_url, config; kwargs...) -> AuthorizationSession

Convenience wrapper when you already know the issuer URL and do not need to
look up protected resource metadata.  Otherwise identical to
[`start_pkce_authorization`](@ref).
"""
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
    verbose::Union{Bool,Nothing}=nothing,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
)
    verbose = effective_verbose(config, verbose)
    discovery = discover_oauth_metadata_from_issuer(issuer_url; http=http, verbose=verbose)
    return prepare_pkce_session(
        discovery.authorization_server,
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
        discovery_context=discovery,
        http=http,
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
    verbose::Union{Bool,Nothing}=nothing,
    redirect_uri,
    start_listener::Bool,
    listener_host::AbstractString,
    listener_port::Integer,
    listener_path::AbstractString,
    discovery_context::Union{OAuthDiscoveryContext,Nothing}=nothing,
    http=HTTP,
)
    verbose = effective_verbose(config, verbose)
    auth_meta.authorization_endpoint === nothing && throw(OAuthError(:metadata_error, "Authorization endpoint missing in issuer metadata"))
    methods = String.(auth_meta.code_challenge_methods_supported)
    normalized_methods = uppercase.(methods)
    allow_plain = config.allow_plain_pkce
    use_plain_pkce = false
    if isempty(methods)
        if allow_plain
            @warn "Authorization server metadata omits code_challenge_methods_supported; allow_plain_pkce=true so falling back to plain PKCE"
            use_plain_pkce = true
        end
    else
        supports_s256 = any(method -> method == "S256", normalized_methods)
        supports_plain = any(method -> method == "PLAIN", normalized_methods)
        if supports_s256
            # ok
        elseif supports_plain
            if allow_plain
                @warn "Authorization server only advertises PKCE plain; allow_plain_pkce=true so falling back to insecure plain challenge"
                use_plain_pkce = true
            else
                throw(OAuthError(:pkce_unsupported, "Authorization server only supports plain PKCE challenge; enable allow_plain_pkce to continue"))
            end
        else
            throw(OAuthError(:pkce_unsupported, "Authorization server does not advertise PKCE S256 support"))
        end
    end
    if !isempty(auth_meta.grant_types_supported)
        has_auth_code = any(gt -> lowercase(String(gt)) == "authorization_code", auth_meta.grant_types_supported)
        has_auth_code || throw(OAuthError(:metadata_error, "Authorization server does not advertise authorization_code grant support"))
    end
    verifier = verifier === nothing ? generate_pkce_verifier() : verifier
    challenge = use_plain_pkce ? verifier.verifier : pkce_challenge(verifier)
    challenge_method = use_plain_pkce ? "plain" : "S256"
    state_value = state === nothing ? random_state() : String(state)
    dest_redirect = redirect_uri === nothing ? config.redirect_uri : redirect_uri
    normalized_path = ensure_slash(listener_path)
    default_redirect = "http://$(listener_host):$(listener_port)$(normalized_path)"
    effective_redirect = dest_redirect === nothing ? default_redirect : String(dest_redirect)
    start_loopback = start_listener && urls_equivalent(effective_redirect, default_redirect) && startswith(lowercase(effective_redirect), "http://")
    if !start_loopback
        ensure_https_url(effective_redirect, "redirect_uri"; allow_loopback=true)
    end
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
    scope_candidates = effective_scope_list(config.scopes, resource_meta, auth_meta)
    scope_value = isempty(scope_candidates) ? nothing : join(scope_candidates, ' ')
    resource_defaults = effective_resources(config.resources, resource_meta)
    discovery_value = discovery_context === nothing ? OAuthDiscoveryContext(auth_meta, resource_meta) : discovery_context
    extra = copy(config.additional_parameters)
    for (k, v) in extra_authorize_params
        extra[String(k)] = String(v)
    end
    authz_override, resource_override = extract_special_authorize_params!(extra)
    resources_value = isempty(resource_override) ? resource_defaults : resource_override
    auth_details_value = authz_override === nothing ? config.authorization_details : authz_override
    use_par_preference = config.use_par
    require_par = auth_meta.require_pushed_authorization_requests
    use_par = require_par || use_par_preference
    par_endpoint = auth_meta.pushed_authorization_request_endpoint
    if use_par
        par_endpoint === nothing && throw(OAuthError(:metadata_error, "Authorization server metadata missing pushed_authorization_request_endpoint"))
        auth_meta.request_uri_parameter_supported || throw(OAuthError(:metadata_error, "Authorization server does not support request_uri parameter required for PAR"))
    end
    session_config = PublicClientConfig(
        client_id = config.client_id,
        redirect_uri = effective_redirect,
        scopes = scope_candidates,
        resources = resources_value,
        authorization_details = auth_details_value,
        additional_parameters = config.additional_parameters,
        dpop = config.dpop,
        refresh_token_store = config.refresh_token_store,
        allow_plain_pkce = config.allow_plain_pkce,
        use_par = use_par,
        request_object_signer = config.request_object_signer,
        verbose = verbose,
    )
    base_kwargs = (
        authorization_endpoint = String(auth_meta.authorization_endpoint),
        response_type = DEFAULT_RESPONSE_TYPE,
        client_id = session_config.client_id,
        redirect_uri = session_config.redirect_uri === nothing ? default_redirect : session_config.redirect_uri,
        scope = scope_value,
        state = state_value,
        code_challenge = challenge,
        code_challenge_method = challenge_method,
        resources = resources_value,
        authorization_details = auth_details_value,
        extra = extra,
    )
    request = AuthorizationRequest(; base_kwargs..., request=nothing, request_uri=nothing)
    request_signer = session_config.request_object_signer
    use_request_object = request_signer !== nothing
    if use_request_object && !use_par && !auth_meta.request_parameter_supported
        throw(OAuthError(:metadata_error, "Authorization server does not support request parameter for JWT authorization requests"))
    end
    if use_request_object
        request_jwt = build_request_object_jwt(request_signer, request, auth_meta, now(UTC))
        request = AuthorizationRequest(; base_kwargs..., request=request_jwt, request_uri=nothing)
    end
    if use_par
        request_uri = push_authorization_request(http, String(par_endpoint), request; verbose=verbose)
        request = AuthorizationRequest(; base_kwargs..., request=nothing, request_uri=request_uri)
    end
    try
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
            discovery = discovery_value,
        )
    catch err
        listener !== nothing && stop_loopback_listener(listener)
        rethrow(err)
    end
end

"""
    exchange_code_for_token(metadata, config, code, verifier; http=HTTP, extra_params=Dict(), verbose=nothing) -> TokenResponse

Swaps the authorization `code` returned by the browser step for tokens at
the discovered token endpoint.  Handles DPoP proof attachment, saves new
refresh tokens automatically, and surfaces HTTP/JSON problems as
`OAuthError`s.
"""
function exchange_code_for_token(metadata::AuthorizationServerMetadata, config::PublicClientConfig, code::AbstractString, verifier::PKCEVerifier; http=HTTP, extra_params=Dict{String,String}(), verbose::Union{Bool,Nothing}=nothing)
    verbose = effective_verbose(config, verbose)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    ensure_https_url(String(metadata.token_endpoint), "token_endpoint")
    config.redirect_uri === nothing && throw(OAuthError(:configuration_error, "redirect_uri required for token exchange"))
    form = FormParams()
    set!(form, "grant_type", "authorization_code")
    set!(form, "code", String(code))
    set!(form, "client_id", config.client_id)
    set!(form, "redirect_uri", config.redirect_uri)
    set!(form, "code_verifier", verifier.verifier)
    token_extra = normalize_string_params(extra_params)
    auth_override, resource_override = extract_special_authorize_params!(token_extra)
    for (k, v) in token_extra
        set!(form, k, v)
    end
    resources_value = isempty(resource_override) ? config.resources : resource_override
    auth_details_value = auth_override === nothing ? config.authorization_details : auth_override
    auth_details_text = authorization_details_json(auth_details_value)
    auth_details_text !== nothing && set!(form, "authorization_details", auth_details_text)
    if !isempty(resources_value)
        for resource in resources_value
            push!(form, "resource", resource)
        end
    end
    body = encode_form(form)
    headers_pairs = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    endpoint = String(metadata.token_endpoint)
    resp, issued_at = perform_token_request(http, endpoint, headers_pairs, body, config.dpop; verbose=verbose)
    status = resp.status
    status in 200:299 || throw(OAuthError(:http_error, "Token request failed (status=$status)"))
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    nonce_value = dpop_nonce_from_response(resp)
    token = TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
    persist_refresh_token!(config, token)
    return token
end

"""
    refresh_pkce_token(source, config; refresh_token=nothing, http=HTTP, extra_token_params=Dict(), verbose=nothing)

Refreshes an access token using the stored refresh token.  `source` can be:

1. `AuthorizationServerMetadata` — you already have issuer metadata.
2. Protected resource URL (`String`) — discovery runs again.
3. Named tuple returned by `complete_pkce_authorization` — we reuse the session metadata.

When `refresh_token` is omitted we fall back to whatever the configured
`RefreshTokenStore` persisted earlier.
"""
function refresh_pkce_token(
    metadata::AuthorizationServerMetadata,
    config::PublicClientConfig;
    refresh_token=nothing,
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    metadata.token_endpoint === nothing && throw(OAuthError(:metadata_error, "Token endpoint missing in issuer metadata"))
    ensure_https_url(String(metadata.token_endpoint), "token_endpoint")
    token_value = refresh_token === nothing ? load_refresh_token(config) : String(refresh_token)
    token_value === nothing && throw(OAuthError(:configuration_error, "refresh_token is not available"))
    form = FormParams()
    set!(form, "grant_type", "refresh_token")
    set!(form, "refresh_token", token_value)
    set!(form, "client_id", config.client_id)
    token_extra = normalize_string_params(extra_token_params)
    auth_override, resource_override = extract_special_authorize_params!(token_extra)
    for (k, v) in token_extra
        set!(form, k, v)
    end
    resources_value = isempty(resource_override) ? config.resources : resource_override
    auth_details_value = auth_override === nothing ? config.authorization_details : auth_override
    auth_text = authorization_details_json(auth_details_value)
    auth_text !== nothing && set!(form, "authorization_details", auth_text)
    if !isempty(resources_value)
        for resource in resources_value
            push!(form, "resource", resource)
        end
    end
    body = encode_form(form)
    headers_pairs = [
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept" => "application/json",
    ]
    endpoint = String(metadata.token_endpoint)
    resp, issued_at = perform_token_request(http, endpoint, headers_pairs, body, config.dpop; verbose=verbose)
    status = resp.status
    if !(status in 200:299)
        if status in 400:499
            err = try
                JSON.parse(String(resp.body))
            catch
                nothing
            end
            if err isa AbstractDict
                err_code = get(err, "error", nothing)
                if err_code isa AbstractString && lowercase(String(err_code)) == "invalid_grant"
                    clear_refresh_token!(config)
                    description = get(err, "error_description", "invalid_grant")
                    message = description isa AbstractString ? String(description) : "invalid_grant"
                    throw(OAuthError(:invalid_grant, "Refresh token rejected: $(message)"))
                end
            end
        end
        throw(OAuthError(:http_error, "Refresh token request failed (status=$status)"))
    end
    data = JSON.parse(String(resp.body))
    data isa AbstractDict || throw(OAuthError(:json_error, "Expected JSON object"))
    nonce_value = dpop_nonce_from_response(resp)
    token = TokenResponse(data; issued_at=issued_at, dpop_nonce=nonce_value)
    persist_refresh_token!(config, token)
    return token
end

"""
    refresh_pkce_token_from_issuer(issuer_url, config; kwargs...)

Shortcut when you already know the issuer.  Returns a named tuple that
includes the refreshed [`TokenResponse`](@ref) and the metadata used, so
you can keep calling `refresh_pkce_token` with the resulting session later.
"""
function refresh_pkce_token_from_issuer(
    issuer_url::AbstractString,
    config::PublicClientConfig;
    refresh_token=nothing,
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    auth_meta = fetch_authorization_server_metadata(issuer_url; http=http, verbose=verbose)
    token = refresh_pkce_token(
        auth_meta,
        config;
        refresh_token=refresh_token,
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
    )
    return (token = token, authorization_server = auth_meta, discovery = OAuthDiscoveryContext(auth_meta, nothing))
end

function refresh_pkce_token(
    prm_url::AbstractString,
    config::PublicClientConfig;
    issuer=nothing,
    refresh_token=nothing,
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    resource_meta = fetch_protected_resource_metadata(prm_url; http=http, verbose=verbose)
    issuer_url = select_authorization_server(resource_meta; issuer=issuer)
    result = refresh_pkce_token_from_issuer(
        issuer_url,
        config;
        refresh_token=refresh_token,
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
    )
    return (
        token = result.token,
        authorization_server = result.authorization_server,
        resource = resource_meta,
        discovery = OAuthDiscoveryContext(result.authorization_server, resource_meta),
    )
end

function refresh_pkce_token(
    result::NamedTuple;
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    haskey(result, :session) || throw(ArgumentError("result must have a :session field (from complete_pkce_authorization)"))
    session = result.session
    refreshed_token = refresh_pkce_token(
        session.authorization_server,
        session.client_config;
        http=http,
        extra_token_params=extra_token_params,
        verbose=verbose,
    )
    return (
        token = refreshed_token,
        session = session,
        callback = result.callback,
        discovery = result.discovery,
    )
end

"""
    refresh_if_expiring(result; skew_seconds=60, http=HTTP, extra_token_params=Dict(), verbose=nothing) -> NamedTuple

Refreshes a PKCE result if the access token is expiring soon. Returns the
original result when the token is still valid.
"""
function refresh_if_expiring(
    result::NamedTuple;
    skew_seconds::Integer=60,
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    haskey(result, :token) || throw(ArgumentError("result must include a :token field"))
    token_expiring(result.token; skew_seconds=skew_seconds) || return result
    return refresh_pkce_token(result; http=http, extra_token_params=extra_token_params, verbose=verbose)
end

"""
    load_or_refresh_token(metadata, config; skew_seconds=60, http=HTTP, extra_token_params=Dict(), verbose=nothing) -> TokenResponse

Loads the stored token response from the configured refresh token store and
refreshes it if it is close to expiring.  Requires a store that persists
full token responses (e.g. `FileBasedRefreshTokenStore`).
"""
function load_or_refresh_token(
    metadata::AuthorizationServerMetadata,
    config::PublicClientConfig;
    skew_seconds::Integer=60,
    http=HTTP,
    extra_token_params=Dict{String,String}(),
    verbose::Union{Bool,Nothing}=nothing,
)
    verbose = effective_verbose(config, verbose)
    token = load_token_response(config)
    token === nothing && throw(OAuthError(:configuration_error, "Stored token response is not available"))
    token_expiring(token; skew_seconds=skew_seconds) || return token
    refreshed = refresh_pkce_token(metadata, config; http=http, extra_token_params=extra_token_params, verbose=verbose)
    return refreshed
end

"""
    wait_for_authorization_code(session; timeout=120) -> NamedTuple

Blocks until the loopback listener created in `start_pkce_authorization`
receives the browser redirect.  Validates the returned state parameter,
raises `OAuthError` when the IdP returned an error, and yields a
`(code, state, params)` named tuple upon success.
"""
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

"""
    complete_pkce_authorization(prm_url, config; kwargs...) -> NamedTuple

High-level helper that runs the entire PKCE flow end-to-end: discovery,
loopback listener, browser launch, waiting for the authorization code, and
token exchange.  Returns a named tuple with the `token`, session metadata,
the raw callback parameters, and discovery context so you can reuse it
later (e.g., refresh).
"""
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
    verbose::Union{Bool,Nothing}=nothing,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
    timeout::Real=180,
)
    verbose = effective_verbose(config, verbose)
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

"""
    complete_pkce_authorization_from_issuer(issuer_url, config; kwargs...) -> NamedTuple

Same as [`complete_pkce_authorization`](@ref), but skips the protected
resource metadata lookup.
"""
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
    verbose::Union{Bool,Nothing}=nothing,
    redirect_uri=nothing,
    start_listener::Bool=true,
    listener_host::AbstractString=DEFAULT_LOOPBACK_HOST,
    listener_port::Integer=DEFAULT_LOOPBACK_PORT,
    listener_path::AbstractString=DEFAULT_LOOPBACK_PATH,
    timeout::Real=180,
)
    verbose = effective_verbose(config, verbose)
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
    verbose::Union{Bool,Nothing}=nothing,
    timeout::Real=180,
)
    verbose = effective_verbose(session, verbose)
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
        discovery = session_discovery(session)
        return (token = token, session = session, callback = callback, discovery = discovery)
    catch err
        session.listener !== nothing && stop_loopback_listener(session.listener)
        rethrow(err)
    end
end
