using Test
using OAuth
using HTTP
using JSON
using Sockets
using Base64
using Random
using Dates
using SHA

fixtures_path(parts...) = joinpath(@__DIR__, "fixtures", parts...)

fixture_string(name) = read(fixtures_path(name), String)

function decode_segment(segment)
    padding = (4 - length(segment) % 4) % 4
    padded = segment * repeat("=", padding)
    return Base64.base64decode(replace(replace(padded, '-' => '+'), '_' => '/'))
end

@testset "Authorization & Token endpoints" begin
    rng_verifier = repeat("a", OAuth.PKCE_VERIFIER_MIN)
    challenge = OAuth.pkce_challenge(rng_verifier)
    code_store = InMemoryAuthorizationCodeStore()
    encode_pairs(dict) = join((string(HTTP.escapeuri(String(k)), "=", HTTP.escapeuri(String(v))) for (k, v) in dict), '&')
    redirect_resolver = (_req, _client_id, redirect_uri) -> begin
        redirect_uri === nothing && throw(OAuthError(:invalid_request, "redirect_uri required"))
        return redirect_uri
    end
    consent_handler = (_req, ctx::AuthorizationRequestContext) -> begin
        grant_authorization("user-9001";
            scope=ctx.scope,
            resource=ctx.resource,
            authorization_details=ctx.authorization_details,
            extra_params=Dict("approved" => "yes"),
            extra_claims=Dict("username" => "user@example.com"))
    end
    auth_config = AuthorizationEndpointConfig(code_store=code_store, redirect_uri_resolver=redirect_resolver, consent_handler=consent_handler)
    query = Dict(
        "response_type" => "code",
        "client_id" => "client-app",
        "redirect_uri" => "https://app.example/callback",
        "scope" => "read write",
        "state" => "xyz",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "resource" => "https://api.example",
        "authorization_details" => "{\"type\":\"payment\"}",
    )
    authorize_url = "/authorize?" * encode_pairs(query)
    auth_request = HTTP.Request("GET", authorize_url)
    auth_handler = build_authorization_endpoint(auth_config)
    auth_response = auth_handler(auth_request)
    @test auth_response.status == 302
    @test HTTP.header(auth_response.headers, "Cache-Control") == "no-store"
    location = HTTP.header(auth_response.headers, "Location")
    parsed = HTTP.URI(location)
    response_params = Dict{String,String}(HTTP.URIs.queryparams(parsed))
    @test response_params["state"] == "xyz"
    @test response_params["approved"] == "yes"
    code = response_params["code"]
    issued_record = consume_authorization_code!(code_store, code)
    @test issued_record !== nothing
    @test issued_record.scope == ["read", "write"]
    @test issued_record.resource == ["https://api.example"]
    @test issued_record.authorization_details["type"] == "payment"
    @test issued_record.extra_claims["username"] == "user@example.com"
    store_authorization_code!(code_store, issued_record)
    rsa_pem = fixture_string("rsa_private.pem")
    issuer = JWTAccessTokenIssuer(
        issuer = "https://id.example.com",
        audience = ["https://api.example"],
        private_key = rsa_pem,
    )
    client_authenticator = (_req, params::Dict{String,String}) -> begin
        cid = get(params, "client_id", nothing)
        cid === nothing && throw(OAuthError(:invalid_client, "client_id is required"))
        return TokenEndpointClient(cid; public=true)
    end
    token_config = TokenEndpointConfig(
        code_store = code_store,
        token_issuer = issuer,
        client_authenticator = client_authenticator,
        token_store = InMemoryTokenStore(),
    )
    body = Dict(
        "grant_type" => "authorization_code",
        "client_id" => "client-app",
        "redirect_uri" => issued_record.redirect_uri,
        "code" => code,
        "code_verifier" => rng_verifier,
    )
    token_body = encode_pairs(body)
    token_request = HTTP.Request("POST", "/token", ["Content-Type" => "application/x-www-form-urlencoded"], token_body)
    token_handler = build_token_endpoint(token_config)
    token_response = token_handler(token_request)
    @test token_response.status == 200
    @test HTTP.header(token_response.headers, "Cache-Control") == "no-store"
    token_doc = JSON.parse(String(token_response.body))
    @test token_doc["token_type"] == "Bearer"
    @test token_doc["resource"] == ["https://api.example"]
    @test token_doc["authorization_details"]["type"] == "payment"
end

@testset "Secure randomness helpers" begin
    rng_a = MersenneTwister(1234)
    rng_b = MersenneTwister(1234)
    bytes = OAuth.secure_random_bytes(16; rng=rng_a)
    expected = rand(rng_b, UInt8, 16)
    @test bytes == expected
    @test_throws ArgumentError OAuth.secure_random_bytes(0)

    seed_rng = MersenneTwister(42)
    token = OAuth.random_state(rng=seed_rng, bytes=24)
    expected_rng = MersenneTwister(42)
    expected_token = OAuth.base64url(rand(expected_rng, UInt8, 24))
    @test token == expected_token

    function pkce_expected(bytes, rng_seed)
        source = MersenneTwister(rng_seed)
        verifier = ""
        while !(OAuth.PKCE_VERIFIER_MIN <= length(verifier) <= OAuth.PKCE_VERIFIER_MAX)
            candidate = OAuth.secure_random_bytes(bytes; rng=source)
            verifier = OAuth.base64url(candidate)
        end
        return verifier
    end
    rng_seed = 77
    verifier = OAuth.generate_pkce_verifier(rng=MersenneTwister(rng_seed), bytes=48)
    @test verifier.verifier == pkce_expected(48, rng_seed)
end

@testset "TokenResponse parsing" begin
    issued = DateTime(2024, 1, 1, 0, 0, 0)
    data = Dict(
        "access_token" => "token",
        "token_type" => "Bearer",
        "expires_in" => 3600.5,
        "refresh_token" => "refresh123",
        "authorization_details" => Any[Dict("type" => "payment")],
        "resource" => ["https://resource.example"],
        "issued_token_type" => "urn:ietf:params:oauth:token-type:access_token",
        "custom_field" => 42,
    )
    response = TokenResponse(JSON.parse(JSON.json(data)); issued_at=issued)
    @test response.expires_at == issued + Dates.Second(3600)
    @test response.refresh_token == "refresh123"
    @test response.authorization_details isa Vector
    @test response.resource == ["https://resource.example"]
    @test response.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"
    @test response.extra["custom_field"] == 42
end

@testset "File-based refresh token store" begin
    mktempdir() do dir
        path = joinpath(dir, "refresh.json")
        store = FileBasedRefreshTokenStore(path; permissions=nothing)
        config = PublicClientConfig(client_id="desktop-app")
        @test load_refresh_token(store, config) === nothing
        save_refresh_token!(store, config, "refresh-123")
        @test load_refresh_token(store, config) == "refresh-123"
        doc = JSON.parse(read(path, String))
        @test doc["version"] == 1
        @test doc["encoding"] == "base64"
        @test String(Base64.base64decode(String(doc["token"]))) == "refresh-123"
        save_refresh_token!(store, config, "second-token")
        @test load_refresh_token(store, config) == "second-token"
        clear_refresh_token!(store, config)
        @test !ispath(path)
    end

    mktempdir() do dir
        nested = joinpath(dir, "tokens", "refresh.json")
        store = FileBasedRefreshTokenStore(nested; permissions=nothing)
        config = PublicClientConfig(client_id="nested-app")
        save_refresh_token!(store, config, "nested-token")
        @test isfile(nested)
    end

    mktempdir() do dir
        path = joinpath(dir, "legacy-token")
        open(path, "w") do io
            write(io, "legacy\n")
        end
        store = FileBasedRefreshTokenStore(path; permissions=nothing)
        config = PublicClientConfig(client_id="legacy-app")
        @test load_refresh_token(store, config) == "legacy"
    end

    mktempdir() do dir
        path = joinpath(dir, "refresh.json")
        lock_path = joinpath(dir, "locks", "refresh.pid")
        store = FileBasedRefreshTokenStore(path; permissions=nothing, lock_path=lock_path, stale_age=0)
        config = PublicClientConfig(client_id="locked-app")
        save_refresh_token!(store, config, "locked-token")
        @test load_refresh_token(store, config) == "locked-token"
        @test !ispath(lock_path)
    end
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
    @test_throws OAuthError ProtectedResourceConfig(authorization_servers=["http://id.invalid"])
    @test_throws OAuthError AuthorizationServerConfig(issuer="https://issuer.example", token_endpoint="http://token.invalid")

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
    insecure_oas = Dict(
        "issuer" => "https://id.good",
        "authorization_endpoint" => "https://id.good/authorize",
        "token_endpoint" => "https://id.good/token",
        "jwks_uri" => "http://id.good/jwks",
        "revocation_endpoint" => "https://id.good/revoke",
        "introspection_endpoint" => "https://id.good/introspect",
        "mtls_endpoint_aliases" => Dict(
            "token_endpoint" => "http://id.good/mtls/token",
        ),
    )
    insecure_responses = Dict(
        "https://id.good/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(insecure_oas)),
        "https://id.good/.well-known/openid-configuration" => HTTP.Response(404, ""),
    )
    insecure_mock = (
        get = (url; kwargs...) -> begin
            response = get(insecure_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
    )
    expect_oauth_error(() -> fetch_authorization_server_metadata("https://id.good"; http=insecure_mock), :insecure_endpoint)

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
    config_plain = PublicClientConfig(client_id="client", redirect_uri="https://app.example/callback", allow_plain_pkce=true)
    session_plain = OAuth.prepare_pkce_session(
        make_auth_meta(pkce_plain_doc),
        nothing,
        config_plain;
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
    )
    @test occursin("code_challenge_method=plain", session_plain.authorization_url)
    @test occursin("code_challenge=$(session_plain.verifier.verifier)", session_plain.authorization_url)

    insecure_doc = Dict(
        "issuer" => "https://id.secure",
        "authorization_endpoint" => "https://id.secure/authorize",
        "token_endpoint" => "https://id.secure/token",
        "code_challenge_methods_supported" => ["S256"],
        "grant_types_supported" => ["authorization_code"],
    )
    insecure_config = PublicClientConfig(client_id="client", redirect_uri="http://app.example/callback")
    expect_oauth_error(() -> OAuth.prepare_pkce_session(
        make_auth_meta(insecure_doc),
        nothing,
        insecure_config;
        state=nothing,
        verifier=nothing,
        open_browser=false,
        wait=false,
        browser_command=nothing,
        extra_authorize_params=Dict{String,String}(),
        verbose=false,
        redirect_uri="http://app.example/callback",
        start_listener=false,
        listener_host=DEFAULT_LOOPBACK_HOST,
        listener_port=DEFAULT_LOOPBACK_PORT,
        listener_path=DEFAULT_LOOPBACK_PATH,
    ), :insecure_endpoint)

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

@testset "Metadata parsing" begin
    prm_doc = Dict(
        "resource" => "https://api.meta",
        "authorization_servers" => ["https://id.meta"],
        "scopes_supported" => ["read", "write"],
        "resource_documentation" => "https://docs.meta",
        "resource_registration_endpoint" => "https://id.meta/register",
    )
    prm = ProtectedResourceMetadata(JSON.parse(JSON.json(prm_doc)))
    @test prm.resource == "https://api.meta"
    @test prm.scopes_supported == ["read", "write"]
    @test prm.resource_documentation == "https://docs.meta"
    @test prm.resource_registration_endpoint == "https://id.meta/register"
    as_doc = Dict(
        "issuer" => "https://id.meta",
        "authorization_endpoint" => "https://id.meta/authorize",
        "token_endpoint" => "https://id.meta/token",
        "device_authorization_endpoint" => "https://id.meta/device",
        "jwks_uri" => "https://id.meta/jwks",
        "scopes_supported" => ["openid"],
        "response_types_supported" => ["code"],
        "grant_types_supported" => ["authorization_code"],
        "code_challenge_methods_supported" => ["S256"],
        "token_endpoint_auth_methods_supported" => ["client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported" => ["RS256"],
        "introspection_endpoint" => "https://id.meta/introspect",
        "revocation_endpoint" => "https://id.meta/revoke",
        "pushed_authorization_request_endpoint" => "https://id.meta/par",
        "backchannel_authentication_endpoint" => "https://id.meta/ciba",
        "end_session_endpoint" => "https://id.meta/logout",
        "mtls_endpoint_aliases" => Dict(
            "token_endpoint" => "https://mtls.id.meta/token",
        ),
        "authorization_response_iss_parameter_supported" => true,
    )
    metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(as_doc)))
    @test metadata.scopes_supported == ["openid"]
    @test metadata.introspection_endpoint == "https://id.meta/introspect"
    @test metadata.revocation_endpoint == "https://id.meta/revoke"
    @test metadata.pushed_authorization_request_endpoint == "https://id.meta/par"
    @test metadata.backchannel_authentication_endpoint == "https://id.meta/ciba"
    @test metadata.end_session_endpoint == "https://id.meta/logout"
    @test metadata.authorization_response_iss_parameter_supported
    @test metadata.mtls_endpoint_aliases["token_endpoint"] == "https://mtls.id.meta/token"
    context = OAuthDiscoveryContext(metadata, prm)
    @test context.scopes_supported == ["read", "write"]
    @test context.jwks_uri == "https://id.meta/jwks"
    @test context.introspection_endpoint == "https://id.meta/introspect"
end

@testset "Private key JWT and DPoP" begin
    metadata_doc = Dict(
        "issuer" => "https://id.jwt",
        "token_endpoint" => "https://id.jwt/token",
        "token_endpoint_auth_methods_supported" => ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported" => ["RS256"],
        "grant_types_supported" => ["client_credentials"],
    )
    attempts = Ref(0)
    requests = Tuple{HTTP.Headers,String}[]
    proof_payloads = Vector{Dict{String,Any}}()
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.jwt/token"
            headers isa HTTP.Headers || error("Expected HTTP.Headers")
            attempts[] += 1
            push!(requests, (headers, body))
            dpop_header = HTTP.header(headers, "DPoP")
            parts = split(dpop_header, '.')
            push!(proof_payloads, JSON.parse(String(decode_segment(parts[2]))))
            if attempts[] == 1
                response_headers = HTTP.Headers(["DPoP-Nonce" => "retry-nonce"])
                err_body = JSON.json(Dict("error" => "use_dpop_nonce"))
                return HTTP.Response(400, response_headers, err_body)
            else
                response_headers = HTTP.Headers(["DPoP-Nonce" => "nonce123"])
                return HTTP.Response(200, response_headers, JSON.json(token_doc))
            end
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
    @test attempts[] == 2
    @test !haskey(proof_payloads[1], "nonce")
    @test proof_payloads[2]["nonce"] == "retry-nonce"
    headers, body = requests[end]
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

@testset "DPoP resource requests" begin
    rsa_pem = fixture_string("rsa_private.pem")
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
    config = PublicClientConfig(client_id="client", redirect_uri="https://app.example/callback", dpop=dpop)
    token_doc = Dict(
        "access_token" => "api-token-123",
        "token_type" => "DPoP",
    )
    token = TokenResponse(JSON.parse(JSON.json(token_doc)))
    attempts = Ref(0)
    mock_http = (
        request = (method, url; headers=nothing, body="", kwargs...) -> begin
            attempts[] += 1
            headers isa HTTP.Headers || error("Expected headers")
            auth_header = HTTP.header(headers, "Authorization")
            @test auth_header == "DPoP api-token-123"
            dpop_header = HTTP.header(headers, "DPoP")
            @test !isempty(dpop_header)
            parts = split(dpop_header, '.')
            claims = JSON.parse(String(decode_segment(parts[2])))
            expected_ath = OAuth.base64url(SHA.sha256(codeunits("api-token-123")))
            @test claims["ath"] == expected_ath
            if attempts[] == 1
                headers_resp = HTTP.Headers(["WWW-Authenticate" => "DPoP realm=\"api\", error=\"use_dpop_nonce\"", "DPoP-Nonce" => "nonce-required"])
                return HTTP.Response(401, headers_resp, "")
            else
                @test claims["nonce"] == "nonce-required"
                return HTTP.Response(200, HTTP.Headers(), "")
            end
        end,
    )
    resp = oauth_request(mock_http, "GET", "https://api.example.com/data"; token=token, config=config)
    @test resp.status == 200
    @test attempts[] == 2
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

@testset "PAR and JAR" begin
    resource_doc = Dict(
        "authorization_servers" => ["https://id.par"],
        "resource" => "https://api.par",
    )
    auth_doc = Dict(
        "issuer" => "https://id.par",
        "authorization_endpoint" => "https://id.par/authorize",
        "token_endpoint" => "https://id.par/token",
        "code_challenge_methods_supported" => ["S256"],
        "grant_types_supported" => ["authorization_code"],
        "pushed_authorization_request_endpoint" => "https://id.par/par",
        "request_parameter_supported" => true,
        "request_uri_parameter_supported" => true,
        "require_pushed_authorization_requests" => true,
        "request_object_signing_alg_values_supported" => ["RS256"],
    )
    resource_meta = ProtectedResourceMetadata(JSON.parse(JSON.json(resource_doc)))
    auth_meta = AuthorizationServerMetadata(JSON.parse(JSON.json(auth_doc)))
    rsa_pem = fixture_string("rsa_private.pem")
    signer = RequestObjectSigner(private_key=rsa_pem, alg=:RS256, kid="req-kid")
    config = PublicClientConfig(
        client_id = "public-client",
        redirect_uri = "https://app.example/callback",
        request_object_signer = signer,
        use_par = false,
    )
    verifier = PKCEVerifier(repeat("b", OAuth.PKCE_VERIFIER_MIN))
    captures = Vector{Vector{Pair{String,String}}}()
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.par/par"
            pairs = Pair{String,String}[]
            for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?$body"))
                push!(pairs, String(k) => String(v))
            end
            push!(captures, pairs)
            response = Dict("request_uri" => "urn:ietf:params:oauth:request_uri:abc123", "expires_in" => 90)
            return HTTP.Response(201, HTTP.Headers(), JSON.json(response))
        end,
    )
    session = OAuth.prepare_pkce_session(
        auth_meta,
        resource_meta,
        config;
        state = "fixed-state",
        verifier = verifier,
        open_browser = false,
        wait = false,
        browser_command = nothing,
        extra_authorize_params = Dict{String,String}(),
        verbose = false,
        redirect_uri = config.redirect_uri,
        start_listener = false,
        listener_host = OAuth.DEFAULT_LOOPBACK_HOST,
        listener_port = OAuth.DEFAULT_LOOPBACK_PORT,
        listener_path = OAuth.DEFAULT_LOOPBACK_PATH,
        discovery_context = OAuth.OAuthDiscoveryContext(auth_meta, resource_meta),
        http = mock_http,
    )
    @test occursin("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc123", session.authorization_url)
    @test session.client_config.resources == ["https://api.par"]
    @test length(captures) == 1
    sent = Dict(captures[1])
    @test haskey(sent, "client_id")
    @test haskey(sent, "request")
    @test !haskey(sent, "redirect_uri")
    jwt = sent["request"]
    parts = split(jwt, '.')
    payload = JSON.parse(String(decode_segment(parts[2])))
    @test payload["redirect_uri"] == "https://app.example/callback"
    @test payload["resource"] == ["https://api.par"]
    @test payload["state"] == "fixed-state"
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
        "expires_in" => 60.0,
        "refresh_token" => "refresh-abc",
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

    store = OAuth.InMemoryRefreshTokenStore()
    config = PublicClientConfig(client_id="client", redirect_uri="https://app.example/callback", scopes=["openid", "profile"], refresh_token_store=store)
    session = start_pkce_authorization("https://prm.example/.well-known/oauth-protected-resource", config; http=mock_http, open_browser=false, start_listener=false)
    @test occursin("response_type=code", session.authorization_url)
    @test session.verifier isa PKCEVerifier
    @test session.listener === nothing
    @test session.redirect_uri == "https://app.example/callback"
    @test session.discovery !== nothing
    @test session.discovery.authorization_server.issuer == "https://id.example.org"

    metadata = session.authorization_server
    token = exchange_code_for_token(metadata, session.client_config, "code123", session.verifier; http=mock_http)
    @test token.access_token == "token123"
    @test token.token_type == "Bearer"
    @test token.expires_at !== nothing
    @test OAuth.load_refresh_token(config) == "refresh-abc"

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
    @test session2.discovery !== nothing
    @test session2.discovery.authorization_server.issuer == "https://id.example.org"

    prm_scoped = Dict(
        "authorization_servers" => ["https://id.example.org"],
        "scopes_supported" => ["resource.read"],
    )
    oas_scoped = Dict(
        "issuer" => "https://id.example.org",
        "authorization_endpoint" => "https://id.example.org/authorize",
        "token_endpoint" => "https://id.example.org/token",
        "code_challenge_methods_supported" => ["S256"],
    )
    scoped_responses = Dict(
        "https://scoped.example/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_scoped)),
        "https://id.example.org/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_scoped)),
    )
    mock_scoped = (
        get = (url; kwargs...) -> begin
            response = get(scoped_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(scoped_responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )
    config_scopeless = PublicClientConfig(client_id="client-scope", redirect_uri="https://app.example/callback", scopes=String[])
    session_scoped = start_pkce_authorization("https://scoped.example/.well-known/oauth-protected-resource", config_scopeless; http=mock_scoped, open_browser=false, start_listener=false)
    @test session_scoped.client_config.scopes == ["resource.read"]
    @test occursin("scope=resource.read", session_scoped.authorization_url)
    @test session_scoped.discovery !== nothing
    @test session_scoped.discovery.scopes_supported == ["resource.read"]
end

@testset "Resource propagation" begin
    metadata_doc = Dict(
        "issuer" => "https://id.resource",
        "token_endpoint" => "https://id.resource/token",
        "device_authorization_endpoint" => "https://id.resource/device",
        "code_challenge_methods_supported" => ["S256"],
    )
    metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(metadata_doc)))
    auth_details = Any[Dict("type" => "payment", "actions" => ["initiate"])]
    config = PublicClientConfig(
        client_id = "resource-client",
        redirect_uri = "https://app.example/callback",
        resources = ["https://api.primary"],
        authorization_details = auth_details,
    )
    verifier = PKCEVerifier(repeat("c", OAuth.PKCE_VERIFIER_MIN))
    bodies = Vector{Vector{Pair{String,String}}}()
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            pairs = Pair{String,String}[]
            for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?$body"))
                push!(pairs, String(k) => String(v))
            end
            push!(bodies, pairs)
            resp_headers = HTTP.Headers(["DPoP-Nonce" => "next-nonce"])
            token_doc = Dict("access_token" => "abc", "token_type" => "Bearer")
            return HTTP.Response(200, resp_headers, JSON.json(token_doc))
        end,
    )
    _ = exchange_code_for_token(metadata, config, "code-123", verifier; http=mock_http)
    params = Dict(bodies[end])
    details_param = HTTP.unescapeuri(params["authorization_details"])
    @test occursin("payment", details_param)
    resource_values = [pair.second for pair in bodies[end] if pair.first == "resource"]
    @test resource_values == ["https://api.primary"]
    override_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            pairs = Pair{String,String}[]
            for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?$body"))
                push!(pairs, String(k) => String(v))
            end
            push!(bodies, pairs)
            token_doc = Dict("access_token" => "def", "token_type" => "Bearer")
            return HTTP.Response(200, HTTP.Headers(), JSON.json(token_doc))
        end,
    )
    _ = exchange_code_for_token(metadata, config, "code-override", verifier; http=override_http, extra_params=Dict("resource" => "https://override"))
    override_values = [pair.second for pair in bodies[end] if pair.first == "resource"]
    @test override_values == ["https://override"]
    client_config = ConfidentialClientConfig(client_id="machine", client_secret="secret", scopes=["scope"], resources=String[])
    resource_doc = Dict("authorization_servers" => ["https://id.resource"], "resource" => "https://api.secondary")
    resource_meta = ProtectedResourceMetadata(JSON.parse(JSON.json(resource_doc)))
    cc_bodies = Vector{Vector{Pair{String,String}}}()
    cc_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            pairs = Pair{String,String}[]
            for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?$body"))
                push!(pairs, String(k) => String(v))
            end
            push!(cc_bodies, pairs)
            token_doc = Dict("access_token" => "ghi", "token_type" => "Bearer")
            return HTTP.Response(200, HTTP.Headers(), JSON.json(token_doc))
        end,
    )
    _ = request_client_credentials_token(metadata, client_config; http=cc_http, resource_metadata=resource_meta)
    cc_resources = [pair.second for pair in cc_bodies[end] if pair.first == "resource"]
    @test cc_resources == ["https://api.secondary"]
    device_bodies = Vector{Vector{Pair{String,String}}}()
    device_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            pairs = Pair{String,String}[]
            for (k, v) in HTTP.URIs.queryparams(HTTP.URI("?$body"))
                push!(pairs, String(k) => String(v))
            end
            push!(device_bodies, pairs)
            response = Dict(
                "device_code" => "device123",
                "user_code" => "ABCD",
                "verification_uri" => "https://verify.example",
                "expires_in" => 600,
            )
            return HTTP.Response(200, HTTP.Headers(), JSON.json(response))
        end,
    )
    device_config = PublicClientConfig(client_id="device-client", resources=String[])
    device = start_device_authorization(metadata, device_config; http=device_http, resource_metadata=resource_meta)
    @test device.device_code == "device123"
    device_resources = [pair.second for pair in device_bodies[end] if pair.first == "resource"]
    @test device_resources == ["https://api.secondary"]
end

@testset "Metadata discovery helpers" begin
    prm_doc = Dict(
        "authorization_servers" => ["https://id.discovery"],
        "scopes_supported" => ["read:all"],
    )
    oas_doc = Dict(
        "issuer" => "https://id.discovery",
        "authorization_endpoint" => "https://id.discovery/authorize",
        "token_endpoint" => "https://id.discovery/token",
        "jwks_uri" => "https://id.discovery/jwks",
        "introspection_endpoint" => "https://id.discovery/introspect",
        "revocation_endpoint" => "https://id.discovery/revoke",
        "scopes_supported" => ["read:all"],
        "code_challenge_methods_supported" => ["S256"],
    )
    responses = Dict(
        "https://resource.discovery/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_doc)),
        "https://id.discovery/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(oas_doc)),
        "https://id.discovery/.well-known/openid-configuration" => HTTP.Response(404, ""),
    )
    mock_http = (
        get = (url; kwargs...) -> begin
            response = get(responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
    )
    ctx = OAuth.discover_oauth_metadata("https://resource.discovery/.well-known/oauth-protected-resource"; http=mock_http)
    @test ctx.resource !== nothing
    @test ctx.resource.authorization_servers == ["https://id.discovery"]
    @test ctx.scopes_supported == ["read:all"]
    @test ctx.jwks_uri == "https://id.discovery/jwks"
    @test ctx.introspection_endpoint == "https://id.discovery/introspect"
    ctx2 = OAuth.discover_oauth_metadata_from_issuer("https://id.discovery"; http=mock_http)
    @test ctx2.resource === nothing
    @test ctx2.authorization_server.issuer == "https://id.discovery"
    @test ctx2.scopes_supported == ["read:all"]
end

@testset "PKCE refresh tokens" begin
    metadata_doc = Dict(
        "issuer" => "https://id.refresh",
        "token_endpoint" => "https://id.refresh/token",
    )
    auth_meta = AuthorizationServerMetadata(JSON.parse(JSON.json(metadata_doc)))
    store = OAuth.InMemoryRefreshTokenStore()
    config = PublicClientConfig(client_id="client-refresh", redirect_uri="https://app.example/callback", refresh_token_store=store)
    OAuth.save_refresh_token!(config, "refresh-old")
    token_doc = Dict(
        "access_token" => "refreshed-token",
        "token_type" => "Bearer",
        "expires_in" => 180.75,
        "refresh_token" => "refresh-new",
    )
    captured = Ref{String}()
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.refresh/token"
            captured[] = body
            return HTTP.Response(200, JSON.json(token_doc))
        end,
    )
    token = OAuth.refresh_pkce_token(auth_meta, config; http=mock_http)
    params = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?" * captured[])))
    @test params["grant_type"] == "refresh_token"
    @test params["refresh_token"] == "refresh-old"
    @test token.access_token == "refreshed-token"
    @test OAuth.load_refresh_token(config) == "refresh-new"

    meta_responses = Dict(
        "https://id.refresh/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(metadata_doc)),
        "https://id.refresh/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    mock_http_meta = (
        get = (url; kwargs...) -> begin
            response = get(meta_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(meta_responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )
    result_meta = OAuth.refresh_pkce_token_from_issuer("https://id.refresh", config; http=mock_http_meta)
    @test result_meta.token.access_token == "refreshed-token"
    @test result_meta.discovery.authorization_server.issuer == "https://id.refresh"

    prm_refresh = Dict("authorization_servers" => ["https://id.refresh"], "scopes_supported" => ["offline_access"])
    resource_responses = Dict(
        "https://api.refresh/.well-known/oauth-protected-resource" => HTTP.Response(200, JSON.json(prm_refresh)),
        "https://id.refresh/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(metadata_doc)),
        "https://id.refresh/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    mock_http_resource = (
        get = (url; kwargs...) -> begin
            response = get(resource_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            response = get(resource_responses, url, nothing)
            response === nothing && error("Unexpected POST for $url")
            return response
        end,
    )
    result_resource = OAuth.refresh_pkce_token("https://api.refresh/.well-known/oauth-protected-resource", config; http=mock_http_resource)
    @test result_resource.token.access_token == "refreshed-token"
    @test result_resource.discovery.scopes_supported == ["offline_access"]

    store2 = OAuth.InMemoryRefreshTokenStore()
    config2 = PublicClientConfig(client_id="client-refresh", redirect_uri="https://app.example/callback", refresh_token_store=store2)
    OAuth.save_refresh_token!(config2, "stale-refresh")
    mock_http_fail = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.refresh/token"
            error_doc = Dict("error" => "invalid_grant", "error_description" => "token expired")
            return HTTP.Response(400, JSON.json(error_doc))
        end,
    )
    err = try
        OAuth.refresh_pkce_token(auth_meta, config2; http=mock_http_fail)
        nothing
    catch e
        e
    end
    @test err isa OAuthError
    err isa OAuthError && @test err.code == :invalid_grant
    @test OAuth.load_refresh_token(config2) === nothing
end

@testset "Client credentials flow" begin
    metadata_doc = Dict(
        "issuer" => "https://id.m2m",
        "token_endpoint" => "https://id.m2m/token",
        "scopes_supported" => ["default.scope"],
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
    @test result_basic.discovery.authorization_server.issuer == "https://id.m2m"
    @test result_basic.discovery.scopes_supported == ["default.scope"]
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
        "scopes_supported" => ["resource.read"],
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
    @test params2["scope"] == "resource.read"
    @test result_post.discovery.resource !== nothing
    @test result_post.discovery.scopes_supported == ["resource.read"]

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

    jwt_metadata_doc = Dict(
        "issuer" => "https://id.jwt",
        "token_endpoint" => "https://id.jwt/token",
        "token_endpoint_auth_methods_supported" => ["client_secret_jwt"],
        "token_endpoint_auth_signing_alg_values_supported" => ["HS384"],
    )
    jwt_responses = Dict(
        "https://id.jwt/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(jwt_metadata_doc)),
        "https://id.jwt/token" => HTTP.Response(200, JSON.json(token_doc)),
    )
    captured_jwt = Ref{String}()
    mock_http_jwt = (
        get = (url; kwargs...) -> begin
            response = get(jwt_responses, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.jwt/token"
            captured_jwt[] = body
            return HTTP.Response(200, JSON.json(token_doc))
        end,
    )
    jwt_auth = OAuth.ClientSecretJWTAuth("super-secret"; alg=:HS384)
    config_jwt = ConfidentialClientConfig(client_id="jwt-client", credential=jwt_auth, scopes=["scope-jwt"])
    result_jwt = request_client_credentials_token_from_issuer(
        "https://id.jwt",
        config_jwt;
        http=mock_http_jwt,
    )
    @test result_jwt.token.access_token == "machine-token"
    params_jwt = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?" * captured_jwt[])))
    @test params_jwt["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    @test params_jwt["scope"] == "scope-jwt"
    assertion = params_jwt["client_assertion"]
    segments = split(assertion, '.')
    @test length(segments) == 3
    header_doc = JSON.parse(String(decode_segment(segments[1])))
    payload_doc = JSON.parse(String(decode_segment(segments[2])))
    @test header_doc["alg"] == "HS384"
    @test payload_doc["iss"] == "jwt-client"
    @test payload_doc["sub"] == "jwt-client"

    tls_metadata_doc = Dict(
        "issuer" => "https://id.mtls",
        "token_endpoint" => "https://id.mtls/token",
        "token_endpoint_auth_methods_supported" => ["self_signed_tls_client_auth"],
    )
    tls_metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(tls_metadata_doc)))
    tls_body = Ref{String}()
    tls_http = (
        post = (url; headers=nothing, body="", sslconfig=nothing, kwargs...) -> begin
            @test url == "https://id.mtls/token"
            @test sslconfig == :mtls
            tls_body[] = body
            return HTTP.Response(200, JSON.json(token_doc))
        end,
    )
    tls_config = ConfidentialClientConfig(
        client_id = "mtls-client",
        credential = TLSClientAuth(:mtls; method=:self_signed_tls_client_auth),
        scopes = ["api.read"],
    )
    tls_token = request_client_credentials_token(tls_metadata, tls_config; http=tls_http)
    @test tls_token.access_token == "machine-token"
    tls_params = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?" * tls_body[])))
    @test tls_params["client_id"] == "mtls-client"
end

@testset "Device authorization flow" begin
    metadata_doc = Dict(
        "issuer" => "https://id.device",
        "token_endpoint" => "https://id.device/token",
        "device_authorization_endpoint" => "https://id.device/device",
        "scopes_supported" => ["user.read"],
    )
    metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(metadata_doc)))
    device_body = Ref{String}()
    mock_device_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test url == "https://id.device/device"
            device_body[] = body
            response_doc = Dict(
                "device_code" => "dev-code",
                "user_code" => "ABCD-EFGH",
                "verification_uri" => "https://verify.example",
                "expires_in" => 600,
                "interval" => 0,
            )
            return HTTP.Response(200, JSON.json(response_doc))
        end,
    )
    public_config = PublicClientConfig(client_id="device-app", scopes=["user.read"])
    device = start_device_authorization(metadata, public_config; http=mock_device_http)
    @test device.device_code == "dev-code"
    params = Dict{String,String}(HTTP.URIs.queryparams(HTTP.URI("?" * device_body[])))
    @test params["client_id"] == "device-app"
    @test params["scope"] == "user.read"

    poll_calls = Ref(0)
    poll_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            poll_calls[] += 1
            if poll_calls[] == 1
                return HTTP.Response(400, JSON.json(Dict("error" => "authorization_pending")))
            elseif poll_calls[] == 2
                return HTTP.Response(400, JSON.json(Dict("error" => "slow_down")))
            else
                response_headers = HTTP.Headers(["DPoP-Nonce" => "nonce-value"])
                token_doc = Dict(
                    "access_token" => "device-token",
                    "token_type" => "Bearer",
                    "refresh_token" => "device-refresh",
                )
                return HTTP.Response(200, response_headers, JSON.json(token_doc))
            end
        end,
    )
    sleeps = Float64[]
    store = InMemoryRefreshTokenStore()
    poll_config = PublicClientConfig(client_id="device-app", refresh_token_store=store)
    token = poll_device_authorization_token(metadata, poll_config, device; http=poll_http, sleep_function = x -> push!(sleeps, x))
    @test token.access_token == "device-token"
    @test OAuth.load_refresh_token(poll_config) == "device-refresh"
    @test sleeps == [1.0, 6.0]

    conf_headers = Ref{String}()
    mock_conf_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            conf_headers[] = HTTP.header(headers, "Authorization")
            response_doc = Dict(
                "device_code" => "conf-code",
                "user_code" => "JKLM-NOPQ",
                "verification_uri" => "https://verify.example",
                "expires_in" => 600,
                "interval" => 0,
            )
            return HTTP.Response(200, JSON.json(response_doc))
        end,
    )
    conf_config = ConfidentialClientConfig(client_id="device-conf", client_secret="topsecret")
    conf_device = start_device_authorization(metadata, conf_config; http=mock_conf_http)
    @test conf_device.user_code == "JKLM-NOPQ"
    @test startswith(conf_headers[], "Basic ")

    poll_conf_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            @test startswith(HTTP.header(headers, "Authorization"), "Basic ")
            token_doc = Dict("access_token" => "conf-token", "token_type" => "Bearer")
            return HTTP.Response(200, JSON.json(token_doc))
        end,
    )
    conf_device_doc = Dict(
        "device_code" => "conf-code",
        "user_code" => "JKLM-NOPQ",
        "verification_uri" => "https://verify.example",
        "expires_in" => 600,
        "interval" => 0,
    )
    conf_device_resp = DeviceAuthorizationResponse(JSON.parse(JSON.json(conf_device_doc)); issued_at=Dates.now(UTC))
    conf_token = poll_device_authorization_token(metadata, conf_config, conf_device_resp; http=poll_conf_http, sleep_function = _ -> nothing)
    @test conf_token.access_token == "conf-token"
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
    @test result.discovery.authorization_server.issuer == "https://id.example.io"
    @test result.session.discovery !== nothing

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
    @test result2.discovery.authorization_server.issuer == "https://id.example.io"
end

@testset "Server helpers" begin
    prm_config = ProtectedResourceConfig(
        resource = "https://api.example.com",
        authorization_servers = ["https://id.example.com"],
        scopes_supported = ["openid", "profile"],
    )
    prm_router = HTTP.Router()
    prm_handler = register_protected_resource_metadata!(prm_router, prm_config)
    prm_response = prm_handler(HTTP.Request("GET", prm_config.path))
    prm_doc = JSON.parse(String(prm_response.body))
    @test prm_doc["authorization_servers"] == ["https://id.example.com"]

    as_config = AuthorizationServerConfig(
        issuer = "https://id.example.com",
        authorization_endpoint = "https://id.example.com/auth",
        token_endpoint = "https://id.example.com/token",
        jwks_uri = "https://id.example.com/jwks.json",
        grant_types_supported = ["authorization_code", "client_credentials"],
        scopes_supported = ["openid"],
        pushed_authorization_request_endpoint = "https://id.example.com/par",
        mtls_endpoint_aliases = Dict("token_endpoint" => "https://mtls.id.example.com/token"),
        authorization_response_iss_parameter_supported = true,
    )
    as_router = HTTP.Router()
    as_handler = register_authorization_server_metadata!(as_router, as_config)
    as_response = as_handler(HTTP.Request("GET", as_config.path))
    as_doc = JSON.parse(String(as_response.body))
    @test as_doc["issuer"] == "https://id.example.com"
    @test as_doc["pushed_authorization_request_endpoint"] == "https://id.example.com/par"
    @test as_doc["mtls_endpoint_aliases"]["token_endpoint"] == "https://mtls.id.example.com/token"
    @test as_doc["authorization_response_iss_parameter_supported"] == true
    @test as_doc["grant_types_supported"] == ["authorization_code", "client_credentials"]

    rsa_pem = fixture_string("rsa_private.pem")
    store = InMemoryTokenStore()
    issuer = JWTAccessTokenIssuer(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        private_key = rsa_pem,
        kid = "kid-1",
    )
    issued = issue_access_token(
        issuer;
        subject = "user-123",
        client_id = "client-xyz",
        scope = ["read", "write"],
        store = store,
    )
    @test !isempty(issued.token)
    constrained = issue_access_token(
        issuer;
        subject = "user-123",
        scope = ["read"],
        confirmation_jkt = "thumbprint-demo",
    )
    @test haskey(constrained.claims, "cnf")
    @test constrained.claims["cnf"]["jkt"] == "thumbprint-demo"
    jwk = public_jwk(issuer)
    @test jwk["kid"] == "kid-1"
    jwks = Dict("keys" => [jwk])
    validator = TokenValidationConfig(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        jwks = jwks,
    )
    claims = validate_jwt_access_token(issued.token, validator; required_scopes = ["read"])
    @test claims.subject == "user-123"
    @test "write" in claims.scope
    bad_use = deepcopy(jwk)
    bad_use["use"] = "enc"
    @test_throws ArgumentError TokenValidationConfig(issuer="https://id.example.com", audience=["https://api.example.com"], jwks=Dict("keys" => [bad_use]))
    bad_ops = deepcopy(jwk)
    bad_ops["key_ops"] = ["sign"]
    @test_throws ArgumentError TokenValidationConfig(issuer="https://id.example.com", audience=["https://api.example.com"], jwks=Dict("keys" => [bad_ops]))

    middleware = protected_resource_middleware(
        req -> begin
            req.context[:handled] = true
            HTTP.Response(200, "ok")
        end,
        validator;
        resource_metadata_url = "https://api.example.com/.well-known/oauth-protected-resource",
        required_scopes = ["read"],
    )
    req_missing = HTTP.Request("GET", "/resource")
    resp_missing = middleware(req_missing)
    @test resp_missing.status == 401
    header_missing = HTTP.header(resp_missing.headers, "WWW-Authenticate")
    @test occursin("resource_metadata", header_missing)
    @test occursin("error=\"invalid_token\"", header_missing)

    req_ok = HTTP.Request("GET", "/resource", ["Authorization" => "Bearer $(issued.token)"], "")
    resp_ok = middleware(req_ok)
    @test resp_ok.status == 200
    @test req_ok.context[:oauth_token].client_id == "client-xyz"
    @test req_ok.context[:oauth_token].confirmation_jkt === nothing

    jwks_router = HTTP.Router()
    jwks_handler = register_jwks_endpoint!(jwks_router, [jwk])
    jwks_response = jwks_handler(HTTP.Request("GET", DEFAULT_JWKS_PATH))
    jwks_doc = JSON.parse(String(jwks_response.body))
    @test length(jwks_doc["keys"]) == 1

    introspect = build_introspection_handler(store)
    body = "token=$(issued.token)"
    req_introspect = HTTP.Request("POST", "/introspect", ["Content-Type" => "application/x-www-form-urlencoded"], body)
    resp_introspect = introspect(req_introspect)
    active_doc = JSON.parse(String(resp_introspect.body))
    @test active_doc["active"] == true
    @test active_doc["client_id"] == "client-xyz"
    @test HTTP.header(resp_introspect.headers, "Cache-Control") == "no-store"
    @test HTTP.header(resp_introspect.headers, "Pragma") == "no-cache"
    bad_hint_req = HTTP.Request("POST", "/introspect", ["Content-Type" => "application/x-www-form-urlencoded"], "token=$(issued.token)&token_type_hint=refresh_token")
    bad_hint_resp = introspect(bad_hint_req)
    @test bad_hint_resp.status == 400
    bad_hint_doc = JSON.parse(String(bad_hint_resp.body))
    @test bad_hint_doc["error"] == "unsupported_token_type"

    revoke = build_revocation_handler(store)
    req_revoke = HTTP.Request("POST", "/revoke", ["Content-Type" => "application/x-www-form-urlencoded"], body)
    resp_revoke = revoke(req_revoke)
    @test resp_revoke.status == 200
    @test HTTP.header(resp_revoke.headers, "Cache-Control") == "no-store"
    @test HTTP.header(resp_revoke.headers, "Pragma") == "no-cache"
    bad_revoke = HTTP.Request("POST", "/revoke", ["Content-Type" => "application/x-www-form-urlencoded"], "token=$(issued.token)&token_type_hint=refresh_token")
    bad_revoke_resp = revoke(bad_revoke)
    @test bad_revoke_resp.status == 400
    @test JSON.parse(String(bad_revoke_resp.body))["error"] == "unsupported_token_type"

    resp_inactive = introspect(req_introspect)
    inactive_doc = JSON.parse(String(resp_inactive.body))
    @test inactive_doc["active"] == false
    @test HTTP.header(resp_inactive.headers, "Cache-Control") == "no-store"

    basic_auth = BasicCredentialsAuthenticator(credentials = Dict("client" => "secret"))
    introspect_auth = build_introspection_handler(store; authenticator = basic_auth)
    resp_unauth = introspect_auth(req_introspect)
    @test resp_unauth.status == 401
    basic_header = "Basic " * Base64.base64encode("client:secret")
    req_authd = HTTP.Request("POST", "/introspect", ["Authorization" => basic_header], body)
    resp_authd = introspect_auth(req_authd)
    @test resp_authd.status == 200

    dpop_client = DPoPAuth(
        private_key = fixture_string("ec_private.pem"),
        public_jwk = Dict(
            "kty" => "EC",
            "crv" => "P-256",
            "x" => "cp-fRlYuifWF9f3bsGBq3t5xueGOdsZ0vFSQRqrdJ2Y",
            "y" => "5iaMGjmGzt5OiwUyK6GaMcMIm-IUrO5YbB0MxouBbew",
        ),
    )
    dpop_token = issue_access_token(
        issuer;
        subject = "user-123",
        scope = ["read"],
        confirmation_jkt = OAuth.dpop_thumbprint(dpop_client),
    )
    dpop_claims = validate_jwt_access_token(dpop_token.token, validator)
    @test dpop_claims.confirmation_jkt == OAuth.dpop_thumbprint(dpop_client)
    resource_url = "https://api.example.com/.well-known/oauth-protected-resource"
    dpop_middleware = protected_resource_middleware(
        req -> begin
            req.context[:dpop] = true
            HTTP.Response(200, "ok")
        end,
        validator;
        resource_metadata_url = resource_url,
        required_scopes = ["read"],
    )
    missing_proof_req = HTTP.Request("GET", "/resource", ["Authorization" => "DPoP $(dpop_token.token)"], "")
    resp_missing = dpop_middleware(missing_proof_req)
    @test resp_missing.status == 401
    now_time = Dates.now(UTC)
    proof = OAuth.create_dpop_proof(dpop_client, "GET", "https://api.example.com/resource", now_time; access_token=dpop_token.token)
    req_dpop = HTTP.Request("GET", "/resource", ["Authorization" => "DPoP $(dpop_token.token)", "DPoP" => proof], "")
    resp_dpop = dpop_middleware(req_dpop)
    @test resp_dpop.status == 200
    @test req_dpop.context[:dpop]
    replay_resp = dpop_middleware(req_dpop)
    @test replay_resp.status == 401
    constrained_only = protected_resource_middleware(
        _ -> HTTP.Response(200, "ok"),
        validator;
        resource_metadata_url = resource_url,
        sender_constrained_only = true,
    )
    bearer_req = HTTP.Request("GET", "/resource", ["Authorization" => "Bearer $(issued.token)"], "")
    resp_constrained = constrained_only(bearer_req)
    @test resp_constrained.status == 401

    pss256_issuer = JWTAccessTokenIssuer(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        private_key = rsa_pem,
        alg = :PS256,
        kid = "pss256",
    )
    pss256_token = issue_access_token(pss256_issuer; subject = "pss256")
    pss256_validator = TokenValidationConfig(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        jwks = Dict("keys" => [public_jwk(pss256_issuer)]),
    )
    pss_claims = validate_jwt_access_token(pss256_token.token, pss256_validator)
    @test pss_claims.subject == "pss256"

    @test_throws ArgumentError JWTAccessTokenIssuer(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        private_key = rsa_pem,
        alg = :PS384,
        kid = "pss384",
    )

    seed = Vector{UInt8}(1:32)
    secret, _pub = OAuth.ed25519_seed_keypair(seed)
    ed_issuer = JWTAccessTokenIssuer(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        private_key = secret,
        alg = :EdDSA,
        kid = "ed-kid",
    )
    ed_token = issue_access_token(ed_issuer; subject = "ed-user")
    ed_jwk = public_jwk(ed_issuer)
    @test ed_jwk["kty"] == "OKP"
    ed_validator = TokenValidationConfig(
        issuer = "https://id.example.com",
        audience = ["https://api.example.com"],
        jwks = Dict("keys" => [ed_jwk]),
    )
    ed_claims = validate_jwt_access_token(ed_token.token, ed_validator)
    @test ed_claims.subject == "ed-user"
end

@testset "Dynamic client registration" begin
    metadata_doc = Dict(
        "issuer" => "https://id.register",
        "registration_endpoint" => "https://id.register/register",
    )
    metadata = AuthorizationServerMetadata(JSON.parse(JSON.json(metadata_doc)))
    recorded_post = Ref{Any}(nothing)
    recorded_put = Ref{Any}(nothing)
    recorded_delete = Ref{Any}(nothing)
    mock_http = (
        post = (url; headers=nothing, body="", kwargs...) -> begin
            recorded_post[] = (url, headers, body)
            response = Dict(
                "client_id" => "generated",
                "registration_access_token" => "reg-token",
                "client_configuration_endpoint" => "https://id.register/register/generated",
            )
            return HTTP.Response(201, HTTP.Headers(), JSON.json(response))
        end,
        put = (url; headers=nothing, body="", kwargs...) -> begin
            recorded_put[] = (url, headers, body)
            response = Dict("client_id" => "generated", "client_name" => "Updated App")
            return HTTP.Response(200, HTTP.Headers(), JSON.json(response))
        end,
        delete = (url; headers=nothing, kwargs...) -> begin
            recorded_delete[] = (url, headers)
            return HTTP.Response(204, HTTP.Headers(), "")
        end,
    )
    client = register_dynamic_client(metadata, Dict("redirect_uris" => ["https://app.example/callback"]); http=mock_http, initial_access_token="seed-token")
    @test client["client_id"] == "generated"
    post_call = recorded_post[]
    @test post_call[1] == "https://id.register/register"
    @test HTTP.header(post_call[2], "Authorization") == "Bearer seed-token"
    @test occursin("redirect_uris", post_call[3])
    updated = update_dynamic_client("https://id.register/register/generated", Dict("client_name" => "Updated App"); http=mock_http, registration_access_token="reg-token")
    @test updated["client_name"] == "Updated App"
    put_call = recorded_put[]
    @test put_call[1] == "https://id.register/register/generated"
    @test HTTP.header(put_call[2], "Authorization") == "Bearer reg-token"
    delete_dynamic_client("https://id.register/register/generated"; http=mock_http, registration_access_token="reg-token")
    delete_call = recorded_delete[]
    @test delete_call[1] == "https://id.register/register/generated"
    @test HTTP.header(delete_call[2], "Authorization") == "Bearer reg-token"
    issuer_calls = Dict(
        "https://id.register/.well-known/oauth-authorization-server" => HTTP.Response(200, JSON.json(metadata_doc)),
        "https://id.register/.well-known/openid-configuration" => HTTP.Response(404, ""),
    )
    issuer_post = Ref{Any}(nothing)
    mock_http_issuer = (
        get = (url; kwargs...) -> begin
            response = get(issuer_calls, url, nothing)
            response === nothing && error("Unexpected GET for $url")
            return response
        end,
        post = (url; headers=nothing, body="", kwargs...) -> begin
            issuer_post[] = (url, headers, body)
            resp = Dict("client_id" => "issuer-client")
            return HTTP.Response(201, HTTP.Headers(), JSON.json(resp))
        end,
    )
    result = register_dynamic_client_from_issuer("https://id.register", Dict("client_name" => "Issuer App"); http=mock_http_issuer, initial_access_token="issuer-token")
    @test result.client["client_id"] == "issuer-client"
    issuer_call = issuer_post[]
    @test issuer_call[1] == "https://id.register/register"
    @test HTTP.header(issuer_call[2], "Authorization") == "Bearer issuer-token"
end
