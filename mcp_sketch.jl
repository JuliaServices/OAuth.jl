module MCP

using HTTP, JSON, Logging

struct JSONRPCRequest
    jsonrpc::String
    method::String
    params::Union{Dict{String,Any},Nothing}
    id::Union{String,Int,Nothing}
end

struct JSONRPCResponse
    jsonrpc::String
    result::Any
    id::Union{String,Int}
    error::Union{Dict{String,Any},Nothing}
end

struct MCPToolInputSchema
    type::String
    properties::Dict{String,Any}
    required::Union{Vector{String},Nothing}
end

struct MCPTool
    name::String
    title::Union{String,Nothing}
    description::String
    inputSchema::MCPToolInputSchema
end

# ---------- helpers

function bearer_token(req::HTTP.Request)
    auth = HTTP.header(req.headers, "Authorization", "")
    if !isempty(auth)
        parts = split(auth, ' ')
        if length(parts) == 2 && HTTP.ascii_lc_isequal(parts[1], "bearer")
            return String(parts[2])
        end
    end
    return ""
end

# Change this to your current public URL during ngrok runs:
const PUBLIC_BASE = "http://localhost:8010"
const RESOURCE_URL = "$PUBLIC_BASE/v1/mcp"

const WWW_AUTH_HEADER = [
    "WWW-Authenticate" => "Bearer resource_metadata=\"$PUBLIC_BASE/.well-known/oauth-protected-resource\", scope=\"openid profile email\""
]

unauthorized() = HTTP.Response(401, WWW_AUTH_HEADER, "")

# ---------- JSON-RPC (Streamable HTTP)

function handle_jsonrpc(req::HTTP.Request)
    # Let initialize/tools/list through without auth during development.
    jreq = JSON.parse(req.body, JSONRPCRequest)

    bearer_token(req) == "" && return unauthorized()

    if jreq.id === nothing && jreq.method == "notifications/initialized"
        return HTTP.Response(204)
    end

    # Echo client protocolVersion if present
    client_proto = (jreq.params isa Dict && haskey(jreq.params, "protocolVersion")) ?
                   String(jreq.params["protocolVersion"]) : "2025-06-18"

    if jreq.method == "initialize"
        result = Dict(
            "protocolVersion" => client_proto,
            "capabilities" => Dict(
                "tools" => true,
                "prompts" => false,
                "resources" => false,
                "logging" => false,
                "elicitation" => Dict(),
                "roots" => Dict("listChanged" => false),
            ),
            "serverInfo" => Dict(
                "name" => "Andavo MCP Server",
                "version" => "0.1.0",
                "description" => "Minimal MCP server exposing Andavo user context.",
                "documentationUrl" => "https://developer.andavo.com/mcp",
                "supportsExchange" => true,
            ),
        )
        body = JSON.json(JSONRPCResponse("2.0", result, jreq.id, nothing))
        return HTTP.Response(200, ["Content-Type" => "application/json"], body)

    elseif jreq.method == "tools/list"
        tools = [
            MCPTool(
                "get_andavo_user_details",
                "Get Andavo User Details",
                "Get the user's profile, travel profile, and loyalty programs from Andavo.",
                MCPToolInputSchema(
                    "object",
                    Dict("userId" => Dict("type" => "string", "description" => "Andavo user UID (optional). Defaults to the authenticated caller.")),
                    nothing,  # truly optional
                )
            )
        ]
        body = JSON.json(JSONRPCResponse("2.0", Dict("tools" => tools), jreq.id, nothing))
        return HTTP.Response(200, ["Content-Type" => "application/json"], body)

    else
        @warn "Unhandled jsonrpc request" jreq
        err = Dict("code" => -32601, "message" => "Method not found")
        body = JSON.json(JSONRPCResponse("2.0", nothing, something(jreq.id, 0), err))
        return HTTP.Response(200, ["Content-Type" => "application/json"], body)
    end
end

# ---------- OAuth protected resource metadata

function handle_oauth_protected_resource(_req::HTTP.Request)
    body = JSON.json(Dict(
        "resource" => "https://andavo-api.andavo.io",
        "authorization_servers" => ["https://id.andavo.io"],  # keep, but real OIDC config is needed later
        "scopes_supported" => ["openid", "profile", "email"],
    ))
    return HTTP.Response(200, ["Content-Type" => "application/json"], body)
end

# ---------- Oauth authorization server

function handle_oauth_authorization_server(_req::HTTP.Request)
    oas = JSON.parse(HTTP.get("https://id.andavo.io/.well-known/oauth-authorization-server").body)
    oas.registration_endpoint = "$PUBLIC_BASE/oidc/register"
    oas.authorization_endpoint = "$PUBLIC_BASE/authorize"
    oas.token_endpoint = "$PUBLIC_BASE/token"
    return HTTP.Response(200, JSON.json(oas))
end

# ---------- OIDC register

function handle_oidc_register(_reg::HTTP.Request)
    resp = """
    {
        "client_name": "Andavo MCP Client",
        "client_id": "KfA0VImrpBr8ZNApyIhPkuIGihGYbUjj",
        "client_secret": "jaZLkaT0zdrJe6FcQAqgge2oySGyyzdiXQ-rQvVF8a0_5-pAWoXUV95WZ19PUDnq",
        "redirect_uris": [
            "cursor://anysphere.cursor-mcp/oauth/user-andavo-julia/callback"
        ],
        "token_endpoint_auth_method": "none",
        "client_secret_expires_at": 0
    }
    """
    return HTTP.Response(200, ["Content-Type" => "application/json"], resp)
end

# ---------- authorize

function handle_authorize(_auth::HTTP.Request)
    # "pass" request on to andavo authorization server
    # include all query params and headers from original request
    qp = HTTP.URIs.queryparams(HTTP.URI(_auth.target))
    qp["audience"] = "https://andavo-api.andavo.io"
    delete!(qp, "resource")
    # make request to andavo authorization server
    return HTTP.get("https://id.andavo.io/authorize", query=qp, headers=_auth.headers)
end

# ---------- token exchange

function handle_token_exchange(_token::HTTP.Request)
    # "pass" request on to andavo token exchange server
    # include all query params and headers from original request
    qp = HTTP.URIs.queryparams(HTTP.URI(_token.target))
    qp["audience"] = "https://andavo-api.andavo.io"
    delete!(qp, "resource")
    # make request to andavo token exchange server
    return HTTP.post("https://id.andavo.io/oauth/token", query=qp, headers=_token.headers)
end

# ---------- plumbing

function handle_verbose_logging(f)
    function (req::HTTP.Request)
        @info req
        resp = f(req)
        @info resp
        return resp
    end
end

const ROUTER = HTTP.Router()
HTTP.register!(ROUTER, "POST", "/v1/mcp", handle_jsonrpc)
HTTP.register!(ROUTER, "GET", "/.well-known/oauth-protected-resource", handle_oauth_protected_resource)
HTTP.register!(ROUTER, "GET", "/.well-known/oauth-authorization-server", handle_oauth_authorization_server)
HTTP.register!(ROUTER, "POST", "/oidc/register", handle_oidc_register)
HTTP.register!(ROUTER, "GET", "/authorize", handle_authorize)
HTTP.register!(ROUTER, "POST", "/token", handle_token_exchange)

function run!()
    server = HTTP.serve!(handle_verbose_logging(ROUTER), "127.0.0.1", 8010)
    try
        wait(server)
    finally
        @info "Shutting down MCP server"
        close(server)
    end
end

end
