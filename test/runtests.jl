using Test
using OAuth
using HTTP
using JSON
using Sockets
using Base64

fixtures_path(parts...) = joinpath(@__DIR__, "fixtures", parts...)

fixture_string(name) = read(fixtures_path(name), String)

function decode_segment(segment)
    padding = (4 - length(segment) % 4) % 4
    padded = segment * repeat("=", padding)
    return Base64.base64decode(replace(replace(padded, '-' => '+'), '_' => '/'))
end

@testset "WWW-Authenticate parsing" begin
    header = "Bearer realm=\"example\", error=\"invalid_token\", error_description=\"Token expired\""
    challenges = parse_www_authenticate(header)
    @test length(challenges) == 1
    chal = challenges[1]
    @test chal.scheme == "Bearer"
    @test chal.params["realm"] == "example"
    @test chal.params["error"] == "invalid_token"
    @test chal.params["error_description"] == "Token expired"

    multi = "Bearer scope=\"openid profile\", Basic realm=\"legacy\""
    multi_chals = parse_www_authenticate(multi)
    @test length(multi_chals) == 2
    @test multi_chals[2].scheme == "Basic"
    @test multi_chals[2].params["realm"] == "legacy"
end

@testset "Security validations" begin
    function expect_oauth_error(f, code)
        err = try
            f()
            nothing
        catch e
            e
        end
        @test err isa OAuthError
        err isa OAuthError && @test err.code == code
    end

    expect_oauth_error(() -> fetch_protected_resource_metadata("http://resource.example/.well-known/oauth-protected-resource"), :insecure_endpoint)
    expect_oauth_error(() -> fetch_authorization_server_metadata("http://issuer.example"), :insecure_endpoint)

    bad_oas_doc = Dict(
        "issuer" => "https://evil.example.com",
        "authorization_endpoint" => "https://id.good/authorize",
        "token_endpoint" => "https://id.good/token",
    )
    bad_responses = Dict(
        "https://id.good/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(bad_oas_doc)),
        "https://id.good/.well-known/openid-configuration" => HTTP.Response(404, ""),
    )
    bad_mock = (
        get = (url; kwargs...) -> begin
            response = get(bad_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
    )
    expect_oauth_error(() -> fetch_authorization_server_metadata("https://id.good"; http=bad_mock), :metadata_error)

    function make_auth_meta(doc)
        return AuthorizationServerMetadata(JSON.parse(JSON.json(doc)))
    end
    config = PublicClientConfig(client_id="client", redirect_uri="https://app.example/callback")

    pkce_plain_doc = Dict(
        "issuer" => "https://id.plain",
        "authorization_endpoint" => "https://id.plain/authorize",
        "token_endpoint" => "https://id.plain/token",
        "code_challenge_methods_supported" => ["plain"],
        "grant_types_supported" => ["authorization_code"],
    )
    expect_oauth_error(() -> OAuth.prepare_pkce_session(
        make_auth_meta(pkce_plain_doc),
        nothing,
        config;
        state=nothing,
        verifier=nothing,
        open_browser=false,
        wait=false,
        browser_command=nothing,
        extra_authorize_params=Dict{String,String}(),
        verbose=false,
        redirect_uri="https://app.example/callback",
        start_listener=false,
        listener_host=DEFAULT_LOOPBACK_HOST,
        listener_port=DEFAULT_LOOPBACK_PORT,
        listener_path=DEFAULT_LOOPBACK_PATH,
    ), :pkce_unsupported)

    no_auth_code_doc = Dict(
        "issuer" => "https://id.noauth",
        "authorization_endpoint" => "https://id.noauth/authorize",
        "token_endpoint" => "https://id.noauth/token",
        "code_challenge_methods_supported" => ["S256"],
        "grant_types_supported" => ["client_credentials"],
    )
    expect_oauth_error(() -> OAuth.prepare_pkce_session(
        make_auth_meta(no_auth_code_doc),
        nothing,
        config;
        state=nothing,
        verifier=nothing,
        open_browser=false,
        wait=false,
        browser_command=nothing,
        extra_authorize_params=Dict{String,String}(),
        verbose=false,
        redirect_uri="https://app.example/callback",
        start_listener=false,
        listener_host=DEFAULT_LOOPBACK_HOST,
        listener_port=DEFAULT_LOOPBACK_PORT,
        listener_path=DEFAULT_LOOPBACK_PATH,
    ), :metadata_error)

    bad_auth_method_doc = Dict(
        "issuer" => "https://id.badmethod",
        "token_endpoint" => "https://id.badmethod/token",
        "token_endpoint_auth_methods_supported" => ["private_key_jwt"],
        "grant_types_supported" => ["client_credentials"],
    )
    expect_oauth_error(() -> request_client_credentials_token(
        make_auth_meta(bad_auth_method_doc),
        ConfidentialClientConfig(client_id="client", client_secret="secret", scopes=String[]);
        http=HTTP,
    ), :metadata_error)

    missing_client_credentials_doc = Dict(
        "issuer" => "https://id.nogrant",
        "token_endpoint" => "https://id.nogrant/token",
        "grant_types_supported" => ["authorization_code"],
    )
    expect_oauth_error(() -> request_client_credentials_token(
        make_auth_meta(missing_client_credentials_doc),
        ConfidentialClientConfig(client_id="client", client_secret="secret", scopes=String[]);
        http=HTTP,
    ), :metadata_error)
end

@testset "Private key JWT and DPoP" begin
    metadata_doc = Dict(
        "issuer" => "https://id.jwt",
        "token_endpoint" => "https://id.jwt/token",
        "token_endpoint_auth_methods_supported" => ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported" => ["RS256"],
        "grant_types_supported" => ["client_credentials"],
    )
    captured = Ref{Tuple{HTTP.Headers,String}}()
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.jwt/token"
            headers isa HTTP.Headers || error("Expected HTTP.Headers")
            captured[] = (headers, body)
            response_headers = HTTP.Headers(["DPoP-Nonce" => "nonce123"])
            return HTTP.Response(200, JSON.json(token_doc), response_headers)
        end,
    )
    rsa_pem = fixture_string("rsa_private.pem")
    priv_auth = PrivateKeyJWTAuth(private_key=rsa_pem, alg=:RS256, kid="kid-123", expires_in=90)
    jwk = Dict(
        "kty" => "EC",
        "crv" => "P-256",
        "x" => "cp-fRlYuifWF9f3bsGBq3t5xueGOdsZ0vFSQRqrdJ2Y",
        "y" => "5iaMGjmGzt5OiwUyK6GaMcMIm-IUrO5YbB0MxouBbew",
    )
    dpop = DPoPAuth(
        private_key = fixture_string("ec_private.pem"),
        public_jwk = jwk,
        kid = "dpop-kid",
    )
    token_doc = Dict(
        "access_token" => "jwt-token",
        "token_type" => "DPoP",
        "expires_in" => 120,
        "cnf" => Dict("jkt" => OAuth.dpop_thumbprint(dpop)),
    )
    config = ConfidentialClientConfig(
        client_id = "machine-client",
        credential = priv_auth,
        scopes = ["read"],
        dpop = dpop,
    )
    metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(metadata_doc)))
    token = request_client_credentials_token(
        metadata,
        config;
        http = mock_http,
        extra_token_params = Dict("audience" => "https://api.example"),
    )
    @test token.access_token == "jwt-token"
    @test token.dpop_jkt == OAuth.dpop_thumbprint(dpop)
    @test token.dpop_nonce == "nonce123"
    headers, body = captured[]
    @test HTTP.header(headers, "Authorization") == ""
    dpop_header = HTTP.header(headers, "DPoP")
    @test !isempty(dpop_header)
    form_params = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?$body")))
    @test form_params["grant_type"] == "client_credentials"
    @test form_params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    @test form_params["client_id"] == "machine-client"
    assertion = form_params["client_assertion"]
    parts = split(assertion, '.')
    @test length(parts) == 3
    header = JSON.parse(String(decode_segment(parts[1])))
    payload = JSON.parse(String(decode_segment(parts[2])))
    @test header["alg"] == "RS256"
    @test header["kid"] == "kid-123"
    @test payload["iss"] == "machine-client"
    @test payload["aud"] == "https://id.jwt/token"
    @test haskey(payload, "exp")
    @test haskey(payload, "jti")
    dpop_parts = split(dpop_header, '.')
    dpop_header_json = JSON.parse(String(decode_segment(dpop_parts[1])))
    dpop_claims = JSON.parse(String(decode_segment(dpop_parts[2])))
    @test dpop_header_json["alg"] == "ES256"
    @test dpop_header_json["kid"] == "dpop-kid"
    @test dpop_header_json["typ"] == "dpop+jwt"
    @test dpop_header_json["jwk"] == jwk
    @test dpop_claims["htm"] == "POST"
    @test dpop_claims["htu"] == "https://id.jwt/token"
    @test haskey(dpop_claims, "jti")
end

@testset "Discovery" begin
    prm_doc = Dict(
        "resource" => "https://api.example.com",
        "authorization_servers" => ["https://id.example.com"],
        "scopes_supported" => ["openid", "profile"],
    )
    oas_doc = Dict(
        "issuer" => "https://id.example.com",
        "authorization_endpoint" => "https://id.example.com/auth",
        "token_endpoint" => "https://id.example.com/token",
        "code_challenge_methods_supported" => ["S256"],
    )
    responses = Dict(
        "https://resource.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.example.com/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_doc)),
    )
    mock_http = (
        get = (url; kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; kwargs...) -> error("Unexpected POST for $url"),
    )

    prm = fetch_protected_resource_metadata("https://resource.example/.well-known/oauth-protected-resource"; http=mock_http)
    @test prm.resource == "https://api.example.com"
    @test prm.authorization_servers == ["https://id.example.com"]

    issuer = select_authorization_server(prm)
    @test issuer == "https://id.example.com"

    metadata = fetch_authorization_server_metadata(issuer; http=mock_http)
    @test metadata.authorization_endpoint == "https://id.example.com/auth"
end

@testset "PKCE utilities" begin
    verifier = generate_pkce_verifier()
    @test OAuth.PKCE_VERIFIER_MIN <= length(verifier.verifier) <= OAuth.PKCE_VERIFIER_MAX
    challenge = pkce_challenge(verifier)
    @test !isempty(challenge)
    bad = "short"
    @test_throws ArgumentError pkce_challenge(bad)
end

@testset "Authorization flow helpers" begin
    prm_doc = Dict(
        "authorization_servers" => ["https://id.example.org"],
    )
    oas_doc = Dict(
        "issuer" => "https://id.example.org",
        "authorization_endpoint" => "https://id.example.org/authorize",
        "token_endpoint" => "https://id.example.org/token",
        "code_challenge_methods_supported" => ["S256"],
    )
    token_doc = Dict(
        "access_token" => "token123",
        "token_type" => "Bearer",
        "expires_in" => 60,
    )
    responses = Dict(
        "https://prm.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.example.org/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_doc)),
        "https://id.example.org/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    mock_http = (
        get = (url; kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )

    config = PublicClientConfig(client_id="client", redirect_uri="https://app.example/callback", scopes=["openid", "profile"])
    session = start_pkce_authorization("https://prm.example/.well-known/oauth-protected-resource", config; http=mock_http, open_browser=false, start_listener=false)
    @test occursin("response_type=code", session.authorization_url)
    @test session.verifier isa PKCEVerifier
    @test session.listener === nothing
    @test session.redirect_uri == "https://app.example/callback"

    metadata = session.authorization_server
    token = exchange_code_for_token(metadata, session.client_config, "code123", session.verifier; http=mock_http)
    @test token.access_token == "token123"
    @test token.token_type == "Bearer"
    @test token.expires_at !== nothing

    session2 = start_pkce_authorization_from_issuer(
        "https://id.example.org",
        config;
        http=mock_http,
        open_browser=false,
        start_listener=false,
        extra_authorize_params=Dict("audience" => "https://api.example.com"),
    )
    @test session2.listener === nothing
    @test session2.resource === nothing
    @test occursin("audience", session2.authorization_url)
end

@testset "Client credentials flow" begin
    metadata_doc = Dict(
        "issuer" => "https://id.m2m",
        "token_endpoint" => "https://id.m2m/token",
    )
    token_doc = Dict(
        "access_token" => "machine-token",
        "token_type" => "Bearer",
        "expires_in" => 120,
        "scope" => "scope1 scope2",
    )
    get_responses = Dict(
        "https://id.m2m/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(metadata_doc)),
    )
    post_calls = Ref{Tuple{HTTP.Headers,String}}()
    mock_http_basic = (
        get = (url; kwargs...) -> begin
            response = get(get_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.m2m/token"
            headers isa HTTP.Headers || error("Expected HTTP.Headers")
            post_calls[] = (headers, body)
            return HTTP.Response(200, JSON.json(token_doc))
        end,
    )

    config_basic = ConfidentialClientConfig(
        client_id = "machine",
        client_secret = "secret",
        scopes = ["scope1", "scope2"],
    )
    result_basic = request_client_credentials_token_from_issuer(
        "https://id.m2m",
        config_basic;
        http=mock_http_basic,
        extra_token_params=Dict("audience" => "https://api.example.com"),
    )
    @test result_basic.token.access_token == "machine-token"
    headers, body = post_calls[]
    auth_header = HTTP.header(headers, "Authorization")
    expected_basic = "Basic " * Base64.base64encode("machine:secret")
    @test auth_header == expected_basic
    params = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?$body")))
    @test params["grant_type"] == "client_credentials"
    @test params["scope"] == "scope1 scope2"
    @test params["audience"] == "https://api.example.com"
    @test !haskey(params, "client_secret")
    @test !haskey(params, "client_id")
    @test occursin("scope1+scope2", body)

    prm_doc = Dict(
        "authorization_servers" => ["https://id.service"],
    )
    auth_server_doc = Dict(
        "issuer" => "https://id.service",
        "token_endpoint" => "https://id.service/token",
    )
    token_doc2 = Dict(
        "access_token" => "post-token",
        "token_type" => "Bearer",
        "expires_in" => 90,
    )
    responses_get2 = Dict(
        "https://resource.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.service/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(auth_server_doc)),
    )
    post_calls2 = Ref{Tuple{HTTP.Headers,String}}()
    mock_http_post = (
        get = (url; kwargs...) -> begin
            response = get(responses_get2, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.service/token"
            headers isa HTTP.Headers || error("Expected HTTP.Headers")
            post_calls2[] = (headers, body)
            return HTTP.Response(200, JSON.json(token_doc2))
        end,
    )

    config_post = ConfidentialClientConfig(
        client_id = "device",
        client_secret = "device-secret",
        scopes = String[],
        additional_parameters = Dict("resource" => "https://api.service"),
        token_endpoint_auth_method = :client_secret_post,
    )

    result_post = request_client_credentials_token(
        "https://resource.example/.well-known/oauth-protected-resource",
        config_post;
        http=mock_http_post,
        extra_token_params=Dict("audience" => "https://api.service"),
    )
    @test result_post.token.access_token == "post-token"
    @test result_post.resource.authorization_servers == ["https://id.service"]
    headers2, body2 = post_calls2[]
    @test HTTP.header(headers2, "Authorization") == ""
    params2 = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?$body2")))
    @test params2["grant_type"] == "client_credentials"
    @test params2["client_id"] == "device"
    @test params2["client_secret"] == "device-secret"
    @test params2["resource"] == "https://api.service"
    @test params2["audience"] == "https://api.service"
    @test !haskey(params2, "scope")

    token_doc3 = Dict(
        "access_token" => "encoded-token",
        "token_type" => "Bearer",
    )
    post_calls3 = Ref{Tuple{HTTP.Headers,String}}()
    encoded_metadata_doc = Dict(
        "issuer" => "https://id.encoded",
        "token_endpoint" => "https://id.encoded/token",
        "token_endpoint_auth_methods_supported" => ["client_secret_basic"],
    )
    mock_http_basic_encoded = (
        get = (url; kwargs...) -> begin
            @test url == "https://id.encoded/.well-known/oauth-authorization-server"
            return HTTP.Response(200, JSON.json(encoded_metadata_doc))
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.encoded/token"
            headers isa HTTP.Headers || error("Expected HTTP.Headers")
            post_calls3[] = (headers, body)
            return HTTP.Response(200, JSON.json(token_doc3))
        end,
    )

    config_basic_encoded = ConfidentialClientConfig(
        client_id = "machine:id",
        client_secret = "s ec@ret",
        scopes = String[],
    )
    result_encoded = request_client_credentials_token_from_issuer(
        "https://id.encoded",
        config_basic_encoded;
        http=mock_http_basic_encoded,
    )
    @test result_encoded.token.access_token == "encoded-token"
    headers3, body3 = post_calls3[]
    auth_header3 = HTTP.header(headers3, "Authorization")
    function form_escape_test(str)
        return replace(HTTP.escapeuri(str), "%20" => "+")
    end
    expected_credentials = string(form_escape_test("machine:id"), ":", form_escape_test("s ec@ret"))
    expected_header = "Basic " * Base64.base64encode(expected_credentials)
    @test auth_header3 == expected_header
    @test body3 == "grant_type=client_credentials"
end

function free_port()
    server = Sockets.listen(Sockets.InetAddr(Sockets.IPv4("127.0.0.1"), 0))
    sockname = Sockets.getsockname(server)
    port = sockname isa Tuple ? last(sockname) : sockname.port
    close(server)
    return port
end

@testset "Loopback listener flow" begin
    prm_doc = Dict("authorization_servers" => ["https://id.example.org"])
    oas_doc = Dict(
        "issuer" => "https://id.example.org",
        "authorization_endpoint" => "https://id.example.org/authorize",
        "token_endpoint" => "https://id.example.org/token",
        "code_challenge_methods_supported" => ["S256"],
    )
    token_doc = Dict("access_token" => "token123", "token_type" => "Bearer", "expires_in" => 60)
    responses = Dict(
        "https://prm.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.example.org/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_doc)),
        "https://id.example.org/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    mock_http = (
        get = (url; kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )
    port = free_port()
    config = PublicClientConfig(client_id="client", scopes=["openid"])
    session = start_pkce_authorization(
        "https://prm.example/.well-known/oauth-protected-resource",
        config;
        http=mock_http,
        open_browser=false,
        verbose=false,
        state="teststate",
        start_listener=true,
        listener_port=port,
    )
    @test session.listener !== nothing
    redirect_url = "http://$(DEFAULT_LOOPBACK_HOST):$(port)$(DEFAULT_LOOPBACK_PATH)"
    @test session.redirect_uri == redirect_url
    @async begin
        sleep(0.1)
        HTTP.get("http://$(DEFAULT_LOOPBACK_HOST):$(port)$(DEFAULT_LOOPBACK_PATH)?code=abc123&state=$(session.state)")
    end
    callback = wait_for_authorization_code(session; timeout=5)
    @test callback.code == "abc123"
    @test callback.state == session.state
    token = exchange_code_for_token(session.authorization_server, session.client_config, callback.code, session.verifier; http=mock_http)
    @test token.access_token == "token123"
end

@testset "Complete PKCE authorization" begin
    prm_doc = Dict("authorization_servers" => ["https://id.example.io"])
    oas_doc = Dict(
        "issuer" => "https://id.example.io",
        "authorization_endpoint" => "https://id.example.io/authorize",
        "token_endpoint" => "https://id.example.io/token",
        "code_challenge_methods_supported" => ["S256"],
    )
    token_doc = Dict("access_token" => "tokenXYZ", "token_type" => "Bearer", "expires_in" => 90)
    responses = Dict(
        "https://prm.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.example.io/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_doc)),
        "https://id.example.io/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    mock_http = (
        get = (url; kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )
    port = free_port()
    config = PublicClientConfig(client_id="clientX", scopes=["openid"])
    state_value = "fixedstate"
    task = @async begin
        complete_pkce_authorization(
            "https://prm.example/.well-known/oauth-protected-resource",
            config;
            http=mock_http,
            state=state_value,
            open_browser=false,
            verbose=false,
            start_listener=true,
            listener_port=port,
            timeout=5,
        )
    end
    sleep(0.2)
    HTTP.get("http://$(DEFAULT_LOOPBACK_HOST):$(port)$(DEFAULT_LOOPBACK_PATH)?code=xyz789&state=$(state_value)")
    result = fetch(task)
    @test result.token.access_token == "tokenXYZ"
    @test result.callback.code == "xyz789"

    port2 = free_port()
    state2 = "state2"
    task2 = @async begin
        complete_pkce_authorization_from_issuer(
            "https://id.example.io",
            config;
            http=mock_http,
            state=state2,
            open_browser=false,
            verbose=false,
            start_listener=true,
            listener_port=port2,
            timeout=5,
        )
    end
    sleep(0.2)
    HTTP.get("http://$(DEFAULT_LOOPBACK_HOST):$(port2)$(DEFAULT_LOOPBACK_PATH)?code=uvw000&state=$(state2)")
    result2 = fetch(task2)
    @test result2.token.access_token == "tokenXYZ"
    @test result2.callback.code == "uvw000"
end
