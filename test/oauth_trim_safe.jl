using OAuth

function _trim_assert(condition::Bool, msg::AbstractString)::Nothing
    condition || error(msg)
    return nothing
end

# base64url is on the token-handling path, so keep its round trip trim-clean
function _trim_base64()::Nothing
    for n in 0:8
        bytes = UInt8[UInt8((i * 37 + n) % 256) for i in 1:n]
        encoded = OAuth.base64url(bytes)
        _trim_assert(OAuth.base64urldecode(encoded) == bytes, "base64url round trip")
    end
    _trim_assert(OAuth.base64url(UInt8[]) == "", "base64url empty")
    _trim_assert(OAuth.base64urldecode("aGVsbG8") == Vector{UInt8}(codeunits("hello")), "base64url decode")
    _trim_assert(OAuth.base64urldecode("aGVsbG8=") == Vector{UInt8}(codeunits("hello")), "base64url padded decode")
    return nothing
end

function _trim_pkce()::Nothing
    verifier = generate_pkce_verifier()
    challenge = pkce_challenge(verifier)
    _trim_assert(!isempty(challenge), "pkce challenge")
    _trim_assert(challenge == pkce_challenge(verifier), "pkce challenge is deterministic")
    _trim_assert(length(verifier.verifier) >= 43, "pkce verifier length")
    return nothing
end

function _trim_secure_compare()::Nothing
    _trim_assert(OAuth.secure_compare("abc", "abc"), "secure_compare equal")
    _trim_assert(!OAuth.secure_compare("abc", "abd"), "secure_compare differing")
    _trim_assert(!OAuth.secure_compare("abc", "abcd"), "secure_compare length")
    _trim_assert(OAuth.secure_compare(UInt8[1, 2, 3], UInt8[1, 2, 3]), "secure_compare bytes")
    return nothing
end

function _trim_thumbprint()::Nothing
    # the RFC 7638 worked example
    jwk = Dict{String,String}(
        "kty" => "RSA",
        "e" => "AQAB",
        "n" => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    )
    _trim_assert(OAuth.jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "rfc 7638 thumbprint")
    # optional members must not change the digest
    decorated = Dict{String,String}(jwk)
    decorated["kid"] = "2011-04-29"
    decorated["alg"] = "RS256"
    decorated["use"] = "sig"
    _trim_assert(OAuth.jwk_thumbprint(decorated) == OAuth.jwk_thumbprint(jwk), "thumbprint ignores optional members")
    _trim_assert(!OAuth.jwk_has_private_material(jwk), "no private material")
    return nothing
end

function run_oauth_trim_sample()::Nothing
    _trim_base64()
    _trim_pkce()
    _trim_secure_compare()
    _trim_thumbprint()
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_oauth_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
