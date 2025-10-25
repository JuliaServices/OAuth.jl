const PKCE_VERIFIER_MIN = 43
const PKCE_VERIFIER_MAX = 128

function generate_pkce_verifier(; rng=Random.GLOBAL_RNG, bytes=32)
    bytes > 0 || throw(ArgumentError("bytes must be positive"))
    verifier = ""
    while !within_pkce_length(verifier)
        seed = rand(rng, UInt8, bytes)
        verifier = base64url(seed)
    end
    return PKCEVerifier(verifier)
end

function within_pkce_length(verifier)
    len = ncodeunits(verifier)
    return PKCE_VERIFIER_MIN <= len <= PKCE_VERIFIER_MAX
end

pkce_challenge(input::PKCEVerifier) = pkce_challenge(input.verifier)

function pkce_challenge(verifier::AbstractString)
    within_pkce_length(String(verifier)) || throw(ArgumentError("Invalid PKCE verifier length"))
    digest = SHA.sha256(codeunits(verifier))
    return base64url(digest)
end
