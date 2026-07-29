const PKCE_VERIFIER_MIN = 43
const PKCE_VERIFIER_MAX = 128

"""
    generate_pkce_verifier(; rng=RandomDevice(), bytes=32) -> PKCEVerifier

Builds a cryptographically strong PKCE code verifier string.  Internally we
generate random bytes, base64url encode them, and re-roll until the length
lands within the S256-friendly 43–128 character window.  You can inject a
custom RNG (for deterministic tests) or request more entropy via `bytes`.

# Examples
```julia
julia> verifier = generate_pkce_verifier()
PKCEVerifier(\"Qnaz2EG3...\" )

julia> verifier.verifier |> length
64
```
"""
function generate_pkce_verifier(; rng=nothing, bytes=32)
    bytes > 0 || throw(ArgumentError("bytes must be positive"))
    verifier = ""
    source = rng === nothing ? RandomDevice() : rng
    while !within_pkce_length(verifier)
        seed = secure_random_bytes(bytes; rng=source)
        verifier = base64url(seed)
    end
    return PKCEVerifier(verifier)
end

function within_pkce_length(verifier)
    len = ncodeunits(verifier)
    return PKCE_VERIFIER_MIN <= len <= PKCE_VERIFIER_MAX
end

function valid_pkce_value(value::AbstractString)
    within_pkce_length(value) || return false
    return all(codeunits(value)) do byte
        (UInt8('A') <= byte <= UInt8('Z')) ||
        (UInt8('a') <= byte <= UInt8('z')) ||
        (UInt8('0') <= byte <= UInt8('9')) ||
        byte in (UInt8('-'), UInt8('.'), UInt8('_'), UInt8('~'))
    end
end

pkce_challenge(input::PKCEVerifier) = pkce_challenge(input.verifier)

"""
    pkce_challenge(verifier) -> String

Derives the PKCE code challenge a client must send to the authorization
server.  The helper accepts either a raw verifier string or a
[`PKCEVerifier`](@ref) object.  It validates that the verifier length is
legal, hashes the value with SHA-256, and returns the base64url-encoded
digest without padding.

# Examples
```julia
julia> verifier = generate_pkce_verifier();

julia> challenge = pkce_challenge(verifier)
\"dn7jX5BvgmWRABcH9cUg4aFbyvNAkSHNXqHLpXhXMB4\"
```
"""
function pkce_challenge(verifier::AbstractString)
    valid_pkce_value(verifier) || throw(ArgumentError("Invalid PKCE verifier"))
    digest = SHA.sha256(codeunits(verifier))
    return base64url(digest)
end
