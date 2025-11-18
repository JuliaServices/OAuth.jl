const StringParams = Dict{String,String}

import Base: push!

ascii_lower(byte::UInt8) = (0x41 <= byte <= 0x5a) ? byte + 0x20 : byte

function ascii_lc_isequal(a::AbstractString, b::AbstractString)
    na = ncodeunits(a)
    nb = ncodeunits(b)
    na == nb || return false
    ua = codeunits(a)
    ub = codeunits(b)
    for i in eachindex(ua, ub)
        ascii_lower(ua[i]) == ascii_lower(ub[i]) || return false
    end
    return true
end

mutable struct FormParams
    unique::Dict{String,String}
    repeated::Vector{Pair{String,String}}
end

FormParams() = FormParams(Dict{String,String}(), Pair{String,String}[])

function set!(form::FormParams, key, value)
    form.unique[String(key)] = String(value)
    return form
end

function push!(form::FormParams, key, value)
    push!(form.repeated, String(key) => String(value))
    return form
end

function append_pairs!(form::FormParams, pairs::Vector{Pair{String,String}})
    for pair in pairs
        push!(form.repeated, String(pair.first) => String(pair.second))
    end
    return form
end

function form_pairs(form::FormParams; sort_unique::Bool=true)
    pairs = Pair{String,String}[]
    unique_keys = collect(keys(form.unique))
    sort_unique && sort!(unique_keys)
    for key in unique_keys
        push!(pairs, key => form.unique[key])
    end
    append!(pairs, form.repeated)
    return pairs
end

"""
    LoopbackListener

Represents the tiny HTTP server the PKCE helpers spin up on
`http://127.0.0.1` so the system browser can post the authorization code
back to your app.  The struct holds the running `HTTP.Server`, the async
`Task` that drives it, a `Channel` where captured query parameters are
delivered, plus the host/port/path that callers can present to an
authorization server as their redirect URI.

Most users never touch this type manually, but you can use it to build your
own authorization UX if desired:

```julia
julia> listener = start_loopback_listener(\"127.0.0.1\", 5338, \"/oauth/callback\");

julia> loopback_url(listener)
\"http://127.0.0.1:5338/oauth/callback\"

# Later, once you have received the redirect:
julia> stop_loopback_listener(listener)
```
"""
struct LoopbackListener
    server::HTTP.Server
    task::Task
    result_channel::Channel{StringParams}
    host::String
    port::Int
    path::String
end

loopback_url(listener::LoopbackListener) = "http://$(listener.host):$(listener.port)$(listener.path)"

Base.isopen(listener::LoopbackListener) = !istaskdone(listener.task)

"""
    DEFAULT_LOOPBACK_HOST

Hostname we bind the temporary loopback HTTP server to.  Override it if you
run inside a container or a network namespace where `127.0.0.1` is not the
correct interface.
"""
const DEFAULT_LOOPBACK_HOST = "127.0.0.1"

"""
    DEFAULT_LOOPBACK_PORT

The TCP port the loopback listener tries first.  When you need to run
multiple concurrent PKCE sessions, increment this value or pass an explicit
port to `start_pkce_authorization`.
"""
const DEFAULT_LOOPBACK_PORT = 5338

"""
    DEFAULT_LOOPBACK_PATH

Path segment appended to the loopback host/port when constructing redirect
URIs for PKCE helpers.  You rarely need to change this unless you already
have an embedded server that handles a different callback path.
"""
const DEFAULT_LOOPBACK_PATH = "/oauth/callback"

function normalize_headers(headers)
    if headers isa AbstractVector
        return copy(headers)
    else
        return HTTP.Headers(headers)
    end
end

prepare_headers(headers) = HTTP.Headers(normalize_headers(headers))

function set_request_header!(headers, key::AbstractString, value::AbstractString)
    for idx in eachindex(headers)
        header_pair = headers[idx]
        if ascii_lc_isequal(String(header_pair.first), key)
            headers[idx] = String(key) => String(value)
            return headers
        end
    end
    push!(headers, String(key) => String(value))
    return headers
end

function normalize_body(body)
    if body === nothing
        return UInt8[]
    elseif body isa AbstractVector{UInt8}
        return body
    elseif body isa AbstractString
        return Vector{UInt8}(codeunits(body))
    else
        return Vector{UInt8}(codeunits(string(body)))
    end
end

function http_request(http, method::AbstractString, url::AbstractString; verbose::Bool=false, kwargs...)
    headers_in = get(kwargs, :headers, HTTP.Headers())
    headers_vec = normalize_headers(headers_in)
    body_in = get(kwargs, :body, nothing)
    if verbose
        method_str = uppercase(String(method))
        req_body = normalize_body(body_in)
        req = HTTP.Request(method_str, url, headers_vec, req_body)
        println("→ HTTP $(method_str) $url")
        show(stdout, MIME"text/plain"(), req)
        println()
    end
    response = if hasproperty(http, :request)
        getproperty(http, :request)(method, url; kwargs...)
    else
        method_sym = Symbol(lowercase(String(method)))
        if hasproperty(http, method_sym)
            getproperty(http, method_sym)(url; kwargs...)
        else
            HTTP.request(method, url; kwargs...)
        end
    end
    if verbose
        method_str = uppercase(String(method))
        println("← HTTP $(method_str) $url (status $(response.status))")
        show(stdout, MIME"text/plain"(), response)
        println()
    end
    return response
end

function base64url(bytes::AbstractVector{UInt8})
    encoded = Base64.base64encode(bytes)
    stripped = replace(encoded, "+" => "-", "/" => "_")
    return String(strip_trailing_equals(stripped))
end

function base64urldecode(str::AbstractString)
    normalized = replace(replace(String(str), '-' => '+'), '_' => '/')
    padding = (4 - length(normalized) % 4) % 4
    padded = normalized * repeat("=", padding)
    return Base64.base64decode(padded)
end

function strip_trailing_equals(str::AbstractString)
    idx = lastindex(str)
    while idx >= firstindex(str) && str[idx] == '='
        idx = Base.prevind(str, idx)
    end
    return idx < firstindex(str) ? "" : str[firstindex(str):idx]
end

strip_trailing_slash(url::String) = endswith(url, "/") ? url[1:end-1] : url

form_escape(value::AbstractString) = replace(HTTP.escapeuri(value), "%20" => "+")
form_escape(value) = form_escape(string(value))

escape_pair(pair::Pair{String,String}) = string(form_escape(pair.first), '=', form_escape(pair.second))

function encode_form(fields::Dict{String,String})
    form = FormParams()
    for (k, v) in fields
        set!(form, k, v)
    end
    return encode_form(form; sort_keys=true)
end

function encode_form(pairs::Vector{Pair{String,String}})
    return join((escape_pair(pair) for pair in pairs), '&')
end

function encode_form(form::FormParams; sort_keys::Bool=true)
    return encode_form(form_pairs(form; sort_unique=sort_keys))
end

function normalize_string_params(params)
    string_params = StringParams()
    params === nothing && return string_params
    for (k, v) in params
        string_params[String(k)] = String(v)
    end
    return string_params
end

"""
    secure_random_bytes(len; rng=RandomDevice())

Return `len` uniformly distributed bytes sourced from a cryptographically secure RNG.
Always prefer this helper when generating OAuth secrets (state, PKCE verifiers, JWT IDs, etc.)
to avoid regressions that fall back to non-secure RNGs.
"""
function secure_random_bytes(len::Integer; rng=nothing)
    len > 0 || throw(ArgumentError("len must be positive"))
    source = rng === nothing ? RandomDevice() : rng
    return rand(source, UInt8, len)
end

function random_state(; rng=nothing, bytes=16)
    bytes > 0 || throw(ArgumentError("bytes must be positive"))
    return base64url(secure_random_bytes(bytes; rng=rng))
end

ensure_slash(path::AbstractString) = startswith(path, "/") ? String(path) : "/" * String(path)

const LOOPBACK_HOSTS = Set(["127.0.0.1", "localhost", "::1", "[::1]"])

function parse_uri_or_throw(url::AbstractString, field::AbstractString)
    try
        uri = HTTP.URI(String(url))
        isempty(String(uri.scheme)) && throw(ArgumentError("missing scheme"))
        return uri
    catch err
        throw(OAuthError(:invalid_uri, "$field is not a valid URI: $(url) (reason: $(err))"))
    end
end

is_loopback_host(host::AbstractString) = String(lowercase(host)) in LOOPBACK_HOSTS

function ensure_https_url(url::AbstractString, field::AbstractString; allow_loopback::Bool=false)
    uri = parse_uri_or_throw(url, field)
    scheme = lowercase(String(uri.scheme))
    if scheme == "https"
        return uri
    elseif scheme == "http" && allow_loopback && uri.host !== nothing && is_loopback_host(String(uri.host))
        return uri
    else
        throw(OAuthError(:insecure_endpoint, "$field must use https: $(url)"))
    end
end

function urls_equivalent(a::AbstractString, b::AbstractString)
    try
        ua = HTTP.URI(String(a))
        ub = HTTP.URI(String(b))
        scheme_a = lowercase(String(ua.scheme))
        scheme_b = lowercase(String(ub.scheme))
        host_a = ua.host === nothing ? "" : String(ua.host)
        host_b = ub.host === nothing ? "" : String(ub.host)
        port_a = ua.port === nothing ? ((scheme_a == "https") ? 443 : (scheme_a == "http" ? 80 : ua.port)) : ua.port
        port_b = ub.port === nothing ? ((scheme_b == "https") ? 443 : (scheme_b == "http" ? 80 : ub.port)) : ub.port
        path_a = isempty(String(ua.path)) ? "/" : ensure_slash(String(ua.path))
        path_b = isempty(String(ub.path)) ? "/" : ensure_slash(String(ub.path))
        return scheme_a == scheme_b && host_a == host_b && port_a == port_b && path_a == path_b
    catch
        return a == b
    end
end

function start_loopback_listener(host::AbstractString, port::Integer, path::AbstractString; verbose::Bool=false)
    channel = Channel{StringParams}(1)
    router = HTTP.Router()
    normalized_path = ensure_slash(path)
    handler = function(req)
        uri = HTTP.URI(req.target)
        query = HTTP.URIs.queryparams(uri)
        params = StringParams()
        for (k, v) in query
            params[String(k)] = String(v)
        end
        if !isready(channel)
            put!(channel, params)
        end
        body = """
        <html>
            <head><title>Authentication Complete</title></head>
            <body>
                <h1>Authentication complete</h1>
                <p>You can return to your application.</p>
            </body>
        </html>
        """
        return HTTP.Response(200, ["Content-Type" => "text/html"], body)
    end
    HTTP.register!(router, "GET", normalized_path, handler)
    server = HTTP.serve!(router, host, port)
    task = @async begin
        try
            wait(server)
        catch err
            verbose && @warn "Loopback server stopped" err
        end
    end
    return LoopbackListener(server, task, channel, String(host), Int(port), normalized_path)
end

"""
    stop_loopback_listener(listener::LoopbackListener)

Stops the temporary HTTP server created by `start_loopback_listener` and
waits for its background task to finish.  Call this inside a `finally`
block so you never leak a listening port—especially important when end
users cancel halfway through authorization.

# Examples
```julia
listener = start_loopback_listener(DEFAULT_LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT, DEFAULT_LOOPBACK_PATH)
try
    # wait for OAuth redirect...
finally
    stop_loopback_listener(listener)
end
```
"""
function stop_loopback_listener(listener::LoopbackListener)
    try
        close(listener.server)
    catch
    end
    if !istaskdone(listener.task)
        try
            wait(listener.task)
        catch
        end
    end
end

function take_with_timeout(channel::Channel, timeout::Real)
    deadline = time() + timeout
    while time() <= deadline
        if isready(channel)
            return take!(channel)
        end
        sleep(0.05)
    end
    throw(OAuthError(:timeout, "Timed out waiting for authorization redirect"))
end
