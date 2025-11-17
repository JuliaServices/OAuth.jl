 

function requires_dpop_nonce_retry(resp::HTTP.Response)
    header_value = HTTP.header(resp.headers, "WWW-Authenticate", "")
    isempty(header_value) && return false
    try
        challenges = parse_www_authenticate(header_value)
        for challenge in challenges
            err = get(challenge.params, "error", nothing)
            if err !== nothing && lowercase(String(err)) == "use_dpop_nonce"
                return true
            end
        end
    catch
        return occursin("use_dpop_nonce", lowercase(String(header_value)))
    end
    return false
end

function oauth_request(
    http,
    method::AbstractString,
    url::AbstractString;
    token::TokenResponse,
    config::Union{PublicClientConfig,ConfidentialClientConfig,Nothing}=nothing,
    dpop::Union{DPoPAuth,Nothing}=nothing,
    headers=HTTP.Headers(),
    body=nothing,
    verbose::Bool=false,
    max_nonce_retries::Integer=MAX_DPOP_NONCE_RETRIES,
    kwargs...,
)
    scheme_value = isempty(token.token_type) ? "Bearer" : String(token.token_type)
    auth_header = string(scheme_value, " ", token.access_token)
    base_headers = prepare_headers(headers)
    set_request_header!(base_headers, "Authorization", auth_header)
    dpop_auth = dpop === nothing ? (config === nothing ? nothing : config.dpop) : dpop
    scheme_lc = lowercase(scheme_value)
    use_dpop = dpop_auth !== nothing && scheme_lc == "dpop"
    if scheme_lc == "dpop" && dpop_auth === nothing
        throw(OAuthError(:configuration_error, "DPoP token requires DPoP credentials"))
    end
    attempts = 0
    nonce_value = use_dpop ? cached_dpop_nonce(dpop_auth, url) : nothing
    while true
        headers_obj = HTTP.Headers(base_headers)
        issued_at = now(UTC)
        if use_dpop
            proof = create_dpop_proof(dpop_auth, method, url, issued_at; nonce=nonce_value, access_token=token.access_token)
            set_request_header!(headers_obj, "DPoP", proof)
        end
        resp = http_request(http, method, url; headers=headers_obj, body=body, verbose=verbose, DEFAULT_TIMEOUT..., kwargs...)
        if !use_dpop
            return resp
        end
        resp_nonce = dpop_nonce_from_response(resp)
        if resp_nonce !== nothing
            cache_dpop_nonce!(dpop_auth, url, resp_nonce)
        end
        retry = resp_nonce !== nothing && requires_dpop_nonce_retry(resp) && attempts < max_nonce_retries
        if retry
            attempts += 1
            nonce_value = resp_nonce
            continue
        end
        return resp
    end
end
