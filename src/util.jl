const StringParams = Dict{String,String}

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

const DEFAULT_LOOPBACK_HOST = "127.0.0.1"
const DEFAULT_LOOPBACK_PORT = 5338
const DEFAULT_LOOPBACK_PATH = "/oauth/callback"

function normalize_headers(headers)
    if headers isa AbstractVector
        return copy(headers)
    else
        return HTTP.Headers(headers)
    end
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
    ordered = sort(collect(keys(fields)))
    return join((escape_pair((key => fields[key])) for key in ordered), '&')
end

random_state(; rng=Random.GLOBAL_RNG, bytes=16) = base64url(rand(rng, UInt8, bytes))

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
