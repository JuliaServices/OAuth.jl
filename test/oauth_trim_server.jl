using OAuth

const TRIM_PRIVATE_KEY_DER = OAuth.decode_pem(
    read(joinpath(@__DIR__, "fixtures", "rsa_private.pem"), String),
)

function _trim_server_assert(condition::Bool, message::AbstractString)::Nothing
    condition || error(message)
    return nothing
end

function _trim_claims()::Dict{String,Any}
    claims = Dict{String,Any}()
    claims["iss"] = "https://issuer.example"
    claims["aud"] = "https://api.example"
    claims["sub"] = "user-42"
    claims["scope"] = "solar:read solar:write"
    return claims
end

function _trim_token_store()::Nothing
    now = OAuth.Dates.DateTime(2026, 8, 9, 12, 0, 0)
    issued = OAuth.IssuedAccessToken(
        "trim-access-token",
        _trim_claims(),
        ["solar:read", "solar:write"],
        now,
        now + OAuth.Dates.Minute(10),
        "soleil",
        "user-42",
        nothing,
    )
    store = OAuth.InMemoryTokenStore()
    OAuth.store_access_token!(store, issued; now=now)
    record = OAuth.lookup_access_token(store, issued.token)
    record isa OAuth.AccessTokenRecord || error("stored access token")
    _trim_server_assert(record.subject == "user-42", "stored subject")
    _trim_server_assert(record.scope == ["solar:read", "solar:write"], "stored scope")
    _trim_server_assert(OAuth.revoke_access_token!(store, issued.token), "token revocation")
    _trim_server_assert(OAuth.lookup_access_token(store, issued.token) === nothing,
                        "revoked token lookup")
    return nothing
end

function _trim_authorization_code_store()::Nothing
    now = OAuth.Dates.DateTime(2026, 8, 9, 12, 0, 0)
    record = OAuth.AuthorizationCodeRecord(
        "code-1",
        "soleil",
        "https://client.example/callback",
        ["solar:read"],
        "user-42",
        "challenge",
        "S256",
        now,
        now + OAuth.Dates.Minute(5),
        nothing,
        ["https://api.example"],
        Dict{String,Any}(),
    )
    store = OAuth.InMemoryAuthorizationCodeStore()
    OAuth.store_authorization_code!(store, record; now=now)
    consumed = OAuth.consume_authorization_code!(store, record.code)
    consumed isa OAuth.AuthorizationCodeRecord || error("stored authorization code")
    _trim_server_assert(consumed.subject == "user-42", "authorization code subject")
    _trim_server_assert(OAuth.consume_authorization_code!(store, record.code) === nothing,
                        "authorization code single use")
    return nothing
end

function _trim_rsa_signing()::Nothing
    public_jwk = Dict{String,Any}()
    public_jwk["kty"] = "RSA"
    public_jwk["n"] = "trim-modulus"
    public_jwk["e"] = "AQAB"
    public_jwk["alg"] = "RS256"
    public_jwk["use"] = "sig"
    public_jwk["kid"] = "trim-key"
    issuer = OAuth.JWTAccessTokenIssuer(
        issuer="https://issuer.example",
        audience=["https://api.example"],
        private_key=TRIM_PRIVATE_KEY_DER,
        alg=:RS256,
        kid="trim-key",
        expires_in=600,
        public_jwk=public_jwk,
    )
    signer = issuer.signer
    signer isa OAuth.RSASigner || error("expected RSA signer")
    signature = OAuth.sign_jws(signer, :RS256, Vector{UInt8}(codeunits("trim-input")))
    _trim_server_assert(!isempty(signature), "RSA signature")
    jwk = OAuth.public_jwk(issuer)
    key_id = jwk["kid"]
    key_id isa String && key_id == "trim-key" || error("public JWK key id")
    return nothing
end

function _trim_token_service()::Nothing
    now = OAuth.Dates.DateTime(2026, 8, 9, 12, 0, 0)
    stores = OAuth.AuthorizationServerStores(OAuth.AbstractStores.MemoryStore())
    issuer = OAuth.JWTAccessTokenIssuer(
        issuer="https://issuer.example",
        audience=["https://api.example"],
        private_key=TRIM_PRIVATE_KEY_DER,
        alg=:RS256,
        kid="trim-key",
        expires_in=600,
    )
    service = OAuth.TokenService(
        stores;
        issuer,
        refresh_token_ttl_seconds=3600,
    )
    refresh_token, family_id = OAuth._new_refresh_family_token()
    grant = OAuth.RefreshTokenGrantRecord(
        refresh_token,
        "soleil",
        "user-42",
        ["solar:read", "solar:write"],
        String[],
        nothing,
        Dict{String,Any}(),
        now,
        now + OAuth.Dates.Hour(1),
    )
    OAuth._store_refresh_family!(service, family_id, grant; now)
    _trim_server_assert(
        OAuth.lookup_refresh_token_grant(service, refresh_token) !== nothing,
        "service refresh-token lookup",
    )

    successor_token, successor, granted_scope, _ = OAuth._rotate_refresh_family!(
        service,
        refresh_token,
        "soleil",
        ["solar:read"],
        now + OAuth.Dates.Minute(5),
    )
    _trim_server_assert(
        granted_scope == ["solar:read"],
        "service scope narrowing",
    )
    _trim_server_assert(
        successor.expires_at == grant.expires_at,
        "service absolute refresh expiry",
    )
    _trim_server_assert(
        OAuth.lookup_refresh_token_grant(service, successor_token) !== nothing,
        "service refresh-token rotation",
    )

    replay_rejected = false
    try
        OAuth._rotate_refresh_family!(
            service,
            refresh_token,
            "soleil",
            nothing,
            now + OAuth.Dates.Minute(6),
        )
    catch error
        error isa OAuth.OAuthError || rethrow()
        replay_rejected = error.code == :invalid_grant
    end
    _trim_server_assert(replay_rejected, "service refresh-token replay")
    _trim_server_assert(
        OAuth.lookup_refresh_token_grant(service, successor_token) === nothing,
        "service refresh family revocation",
    )
    return nothing
end

function run_oauth_trim_server()::Nothing
    _trim_rsa_signing()
    _trim_token_store()
    _trim_authorization_code_store()
    _trim_token_service()
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_oauth_trim_server()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
