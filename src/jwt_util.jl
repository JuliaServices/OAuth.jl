# Internal utilities for JOSE/JWT handling, backed by JWTs.jl's OpenSSL layer.
#
# Key handles are `JWTs.OpenSSLKey` EVP_PKEY wrappers and all signing/verifying
# goes through JWTs' EVP helpers, so OAuth and JWTs agree byte-for-byte on JOSE
# semantics (PSS parameters, ECDSA DER<->JOSE conversion, EdDSA raw keys). The
# only crypto this file implements directly is key *loading* for formats JWTs
# does not read: DER private keys, raw EC scalars, raw Ed25519 seeds, and
# public-coordinate extraction for JWK publishing.

const LIBCRYPTO = OpenSSL_jll.libcrypto

const ED25519_PUBLIC_KEY_BYTES = 32
const ED25519_SECRET_KEY_BYTES = 64
const ED25519_SIGNATURE_BYTES = 64
const ED25519_SEED_BYTES = 32

# Stable OpenSSL object NIDs for EVP_PKEY_get_base_id checks.
const NID_RSA_ENCRYPTION = Cint(6)
const NID_X9_62_EC = Cint(408)

"""
    JWTSigner

Internal marker type for things that can sign JSON Web Tokens (RSA, EC, or
EdDSA).  End users usually interact with these via higher-level helpers
such as [`RequestObjectSigner`](@ref).
"""
abstract type JWTSigner end

"""
    RSASigner

Wraps an OpenSSL RSA key handle and knows which algorithms it supports.
Construct instances via [`rsa_signer_from_bytes`](@ref).
"""
struct RSASigner <: JWTSigner
    key::JWTs.OpenSSLKey
end

"""
    ECSigner

Encapsulates an EC key loaded from PEM/DER bytes together with the curve
(`:P256` or `:P384`).  Build via [`ecc_signer_from_bytes`](@ref).
"""
struct ECSigner <: JWTSigner
    key::JWTs.OpenSSLKey
    curve::Symbol        # :P256 or :P384
end

"""
    EdDSASigner

Holds an Ed25519 key handle together with the raw 32-byte public key for JWK
publishing.  Construct with [`eddsa_signer_from_bytes`](@ref).
"""
struct EdDSASigner <: JWTSigner
    key::JWTs.OpenSSLKey
    public::Vector{UInt8}
end

"""
    JWTVerifier

Marker type for verification handles that correspond to `JWTSigner`
counterparts.
"""
abstract type JWTVerifier end

"""Verifier for RSA JWTs created via [`rsa_verifier_from_der`](@ref)."""
struct RSAVerifier <: JWTVerifier
    key::JWTs.OpenSSLKey
end

"""Verifier for `ES256`/`ES384` signatures built from public coordinates."""
struct ECVerifier <: JWTVerifier
    key::JWTs.OpenSSLKey
    curve::Symbol
end

"""Verifier for `EdDSA` signatures built from a raw 32-byte public key."""
struct EdDSAVerifier <: JWTVerifier
    key::JWTs.OpenSSLKey
    public::Vector{UInt8}
end

const SUPPORTED_RSA_ALGS = Set([:RS256, :PS256])
const SUPPORTED_EC_ALGS = Set([:ES256, :ES384])
const SUPPORTED_OKP_ALGS = Set([:EDDSA])

signer_supports_alg(::RSASigner, alg::Symbol) = alg in SUPPORTED_RSA_ALGS
signer_supports_alg(signer::ECSigner, alg::Symbol) =
    (signer.curve === :P256 && alg === :ES256) ||
    (signer.curve === :P384 && alg === :ES384)
signer_supports_alg(::EdDSASigner, alg::Symbol) = alg in SUPPORTED_OKP_ALGS

# OAuth normalizes algorithm symbols to uppercase; JWTs speaks RFC 7518 names.
jose_alg_name(alg::Symbol) = alg === :EDDSA ? "EdDSA" : String(alg)

jose_curve_name(curve::Symbol) =
    curve === :P256 ? "P-256" :
    curve === :P384 ? "P-384" :
    error("Unsupported EC curve: $curve")

function decode_pem(data::AbstractString)
    io = IOBuffer()
    for line in eachline(IOBuffer(data))
        stripped = strip(line)
        startswith(stripped, "-----") && continue
        isempty(stripped) && continue
        write(io, stripped)
    end
    encoded = String(take!(io))
    close(io)
    return base64urldecode(encoded)
end

normalize_key_bytes(data::AbstractString) = decode_pem(data)
normalize_key_bytes(data::Vector{UInt8}) = copy(data)
normalize_key_bytes(data::Base.CodeUnits{UInt8, String}) = normalize_key_bytes(String(data))

# ── key loading ─────────────────────────────────────────────────────────────

"""
    load_der_private_key(bytes) -> JWTs.OpenSSLKey | nothing

Reads a DER-encoded private key: traditional formats (PKCS#1 RSA, SEC1 EC)
via `d2i_AutoPrivateKey`, then unencrypted PKCS#8 via `d2i_PKCS8_PRIV_KEY_INFO`.
Returns `nothing` when OpenSSL cannot parse the bytes as either.
"""
function load_der_private_key(bytes::Vector{UInt8})
    JWTs.clear_openssl_errors()
    GC.@preserve bytes begin
        pp = Ref{Ptr{UInt8}}(pointer(bytes))
        pkey = ccall(
            (:d2i_AutoPrivateKey, LIBCRYPTO),
            Ptr{Cvoid},
            (Ptr{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            C_NULL,
            pp,
            Clong(length(bytes)),
        )
        pkey != C_NULL && return JWTs.OpenSSLKey(pkey)

        JWTs.clear_openssl_errors()
        pp[] = pointer(bytes)
        p8info = ccall(
            (:d2i_PKCS8_PRIV_KEY_INFO, LIBCRYPTO),
            Ptr{Cvoid},
            (Ptr{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            C_NULL,
            pp,
            Clong(length(bytes)),
        )
        p8info == C_NULL && return nothing
        pkey = ccall((:EVP_PKCS82PKEY, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), p8info)
        ccall((:PKCS8_PRIV_KEY_INFO_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), p8info)
        pkey == C_NULL && return nothing
        return JWTs.OpenSSLKey(pkey)
    end
end

function evp_key_base_id(key::JWTs.OpenSSLKey)
    return GC.@preserve key ccall((:EVP_PKEY_get_base_id, LIBCRYPTO), Cint, (Ptr{Cvoid},), key.ptr)
end

"""
    rsa_signer_from_bytes(data) -> RSASigner

Accepts DER or PEM-encoded PKCS#8/PKCS#1 private keys and returns an
`RSASigner`.  The helper tries PKCS#8 first, then PKCS#1, and throws a
helpful error if parsing fails.
"""
function rsa_signer_from_bytes(raw)
    bytes = normalize_key_bytes(raw)
    key = load_der_private_key(bytes)
    key === nothing && error("Failed to load RSA private key (expected PKCS#8 or PKCS#1 DER/PEM)")
    evp_key_base_id(key) == NID_RSA_ENCRYPTION || error("Failed to load RSA private key (expected PKCS#8 or PKCS#1 DER/PEM)")
    return RSASigner(key)
end

"""
    ecc_signer_from_bytes(data, curve::Symbol) -> ECSigner

Loads an EC private key for the provided curve (`:P256` or `:P384`) and
returns an `ECSigner` ready for JWT signing.
"""
function ecc_signer_from_bytes(raw, curve::Symbol)
    crv = jose_curve_name(curve)
    bytes = normalize_key_bytes(raw)
    key = load_der_private_key(bytes)
    if key !== nothing && evp_key_base_id(key) != NID_X9_62_EC
        key = nothing
    end
    if key === nothing
        key = ec_key_from_raw_scalar(bytes, crv)
    end
    key === nothing && error("Failed to load EC private key for curve $(curve)")
    return ECSigner(key, curve)
end

# Raw-scalar fallback: a bare big-endian private scalar for the named curve
# (the same acceptance the previous aws-c-cal backend provided). The public
# point is recomputed from the scalar.
function ec_key_from_raw_scalar(bytes::Vector{UInt8}, crv::AbstractString)
    field_bytes = crv == "P-256" ? 32 : 48
    length(bytes) == field_bytes || return nothing
    priv = Ptr{Cvoid}(C_NULL)
    ec_key = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        priv = JWTs.bn_from_bytes(bytes, "BN_bin2bn(EC scalar)")
        ec_key = ccall((:EC_KEY_new_by_curve_name, LIBCRYPTO), Ptr{Cvoid}, (Cint,), JWTs.ec_group_nid(crv))
        JWTs.require_openssl_nonnull(ec_key, "EC_KEY_new_by_curve_name")
        JWTs.require_openssl_ok(
            ccall((:EC_KEY_set_private_key, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, priv),
            "EC_KEY_set_private_key",
        )
        group = ccall((:EC_KEY_get0_group, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        JWTs.require_openssl_nonnull(group, "EC_KEY_get0_group")
        point = ccall((:EC_POINT_new, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), group)
        JWTs.require_openssl_nonnull(point, "EC_POINT_new")
        JWTs.require_openssl_ok(
            ccall(
                (:EC_POINT_mul, LIBCRYPTO),
                Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                group,
                point,
                priv,
                C_NULL,
                C_NULL,
                C_NULL,
            ),
            "EC_POINT_mul",
        )
        JWTs.require_openssl_ok(
            ccall((:EC_KEY_set_public_key, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, point),
            "EC_KEY_set_public_key",
        )
        pkey = ccall((:EVP_PKEY_new, LIBCRYPTO), Ptr{Cvoid}, ())
        JWTs.require_openssl_nonnull(pkey, "EVP_PKEY_new")
        JWTs.require_openssl_ok(
            ccall((:EVP_PKEY_set1_EC_KEY, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key),
            "EVP_PKEY_set1_EC_KEY",
        )
        key = JWTs.OpenSSLKey(pkey)
        pkey = C_NULL
        return key
    catch
        return nothing
    finally
        JWTs.free_evp_pkey!(pkey)
        JWTs.free_ec_point!(point)
        JWTs.free_ec_key!(ec_key)
        JWTs.free_bn!(priv)
    end
end

function ed25519_key_from_seed(seed::Vector{UInt8})
    length(seed) == ED25519_SEED_BYTES || error("Ed25519 seeds must be $(ED25519_SEED_BYTES) bytes")
    pkey = GC.@preserve seed ccall(
        (:EVP_PKEY_new_raw_private_key, LIBCRYPTO),
        Ptr{Cvoid},
        (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        JWTs.ed25519_pkey_id(),
        C_NULL,
        pointer(seed),
        Csize_t(length(seed)),
    )
    return JWTs.OpenSSLKey(pkey)
end

function ed25519_public_from_key(key::JWTs.OpenSSLKey)
    public = Vector{UInt8}(undef, ED25519_PUBLIC_KEY_BYTES)
    len = Ref{Csize_t}(length(public))
    ret = GC.@preserve key public ccall(
        (:EVP_PKEY_get_raw_public_key, LIBCRYPTO),
        Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}),
        key.ptr,
        pointer(public),
        len,
    )
    JWTs.require_openssl_ok(ret, "EVP_PKEY_get_raw_public_key")
    len[] == ED25519_PUBLIC_KEY_BYTES || error("Unexpected Ed25519 public key length")
    return public
end

"""
    ed25519_seed_keypair(seed) -> (secret::Vector{UInt8}, public::Vector{UInt8})

Derives an Ed25519 keypair from a 32-byte seed. The secret is returned in the
conventional 64-byte form (seed followed by the public key).
"""
function ed25519_seed_keypair(seed::Vector{UInt8})
    public = ed25519_public_from_key(ed25519_key_from_seed(seed))
    return vcat(seed, public), public
end

"""
    eddsa_signer_from_bytes(data) -> EdDSASigner

Accepts either a 64-byte Ed25519 private key or a 32-byte seed and returns
an `EdDSASigner`.
"""
function eddsa_signer_from_bytes(raw)
    bytes = normalize_key_bytes(raw)
    seed = if length(bytes) == ED25519_SECRET_KEY_BYTES
        # libsodium-format secret key: seed followed by the public key
        bytes[1:ED25519_SEED_BYTES]
    elseif length(bytes) == ED25519_SEED_BYTES
        bytes
    else
        error("Unsupported Ed25519 key length ($(length(bytes)))")
    end
    key = ed25519_key_from_seed(seed)
    return EdDSASigner(key, ed25519_public_from_key(key))
end

"""
    generate_ed25519_keypair(; rng=RandomDevice()) -> (secret::Vector{UInt8}, public::Vector{UInt8})

Generates a new Ed25519 keypair suitable for JWT signing. Returns a 64-byte secret
key and a 32-byte public key. The secret key can be used directly with
[`eddsa_signer_from_bytes`](@ref) or [`JWTAccessTokenIssuer`](@ref).

# Examples
```julia
secret, public = generate_ed25519_keypair()
signer = eddsa_signer_from_bytes(secret)
```
"""
function generate_ed25519_keypair(; rng=Random.RandomDevice())
    return ed25519_seed_keypair(rand(rng, UInt8, ED25519_SEED_BYTES))
end

# ── signing and verifying ───────────────────────────────────────────────────

# JWTs' EVP helpers take the JWS signing input as a String.
signing_input_string(signing_input::Vector{UInt8}) = String(copy(signing_input))

function sign_jws(signer::RSASigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_RSA_ALGS || error("Unsupported RSA JWT alg $(alg)")
    return JWTs.evp_digest_sign(signer.key, jose_alg_name(alg), signing_input_string(signing_input))
end

function sign_jws(signer::ECSigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_EC_ALGS || error("Unsupported EC JWT alg $(alg)")
    return JWTs.sign_ec(signer.key, jose_alg_name(alg), signing_input_string(signing_input))
end

function sign_jws(signer::EdDSASigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_OKP_ALGS || error("Unsupported OKP alg $(alg)")
    return JWTs.sign_okp(signer.key, jose_alg_name(alg), signing_input_string(signing_input))
end

function verify_jws(verifier::RSAVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_RSA_ALGS || error("Unsupported RSA JWT alg $(alg)")
    return JWTs.evp_digest_verify(verifier.key, jose_alg_name(alg), signing_input_string(signing_input), signature)
end

function verify_jws(verifier::ECVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_EC_ALGS || error("Unsupported EC JWT alg $(alg)")
    return JWTs.verify_ec(verifier.key, jose_alg_name(alg), signing_input_string(signing_input), signature)
end

function verify_jws(verifier::EdDSAVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_OKP_ALGS || error("Unsupported OKP alg $(alg)")
    length(signature) == ED25519_SIGNATURE_BYTES || return false
    return JWTs.verify_okp(verifier.key, jose_alg_name(alg), signing_input_string(signing_input), signature)
end

# ── DER helpers (pure Julia) ────────────────────────────────────────────────

function read_der_length(der::Vector{UInt8}, idx::Int)
    length_byte = der[idx]
    if length_byte & 0x80 == 0
        return length_byte, 1
    end
    bytes = length_byte & 0x7f
    len = 0
    for i in 0:bytes-1
        len = (len << 8) | der[idx + 1 + i]
    end
    return len, 1 + bytes
end

function parse_der_integer(der::Vector{UInt8}, idx::Int)
    der[idx] == 0x02 || error("Invalid DER signature (expected integer)")
    idx += 1
    len, consumed = read_der_length(der, idx)
    idx += consumed
    value = der[idx:idx + len - 1]
    idx += len
    while !isempty(value) && value[1] == 0x00
        value = value[2:end]
    end
    return value, idx
end

function base64urlencode(data)
    if data isa AbstractVector{UInt8}
        return base64url(data)
    elseif data isa AbstractString
        return base64url(Vector{UInt8}(codeunits(data)))
    else
        return base64url(Vector{UInt8}(collect(data)))
    end
end

# RFC 7638 thumbprint members are all strings, so this path needs no dynamic JSON
# encoding. Keeping it concretely typed also keeps it resolvable under `--trim=safe`.
function json_quote(s::String)
    out = IOBuffer()
    write(out, '"')
    for b in codeunits(s)
        if b == UInt8('"')
            write(out, "\\\"")
        elseif b == UInt8('\\')
            write(out, "\\\\")
        elseif b < 0x20
            write(out, "\\u", string(b; base=16, pad=4))
        else
            write(out, b)
        end
    end
    write(out, '"')
    return String(take!(out))
end

function canonical_json(obj::Dict{String,String})
    ordered = sort(collect(keys(obj)))
    parts = Vector{String}(undef, length(ordered))
    for (i, key) in enumerate(ordered)
        parts[i] = string(json_quote(key), ":", json_quote(obj[key]))
    end
    return "{" * join(parts, ",") * "}"
end

function canonical_json(obj::Dict{String,Any})
    ordered = sort(collect(keys(obj)))
    parts = Vector{String}(undef, length(ordered))
    for (i, key) in enumerate(ordered)
        value = obj[key]
        parts[i] = string(JSON.json(key), ":", JSON.json(value))
    end
    return "{" * join(parts, ",") * "}"
end

# RFC 7638 Section 3.2: the thumbprint is computed over *only* the required members
# for the key type, so optional members (kid, alg, use, x5c, ...) and any private key
# material must not influence the result.
const JWK_THUMBPRINT_MEMBERS = Dict(
    "RSA" => ["e", "kty", "n"],
    "EC" => ["crv", "kty", "x", "y"],
    "OKP" => ["crv", "kty", "x"],
    "OCT" => ["k", "kty"],
)

"""
    jwk_thumbprint(jwk) -> String

Compute the RFC 7638 JWK SHA-256 thumbprint, base64url encoded. Only the required
members for the key type participate in the digest, so a JWK carrying extra members
such as `kid`, `alg`, or `use` yields the same thumbprint as its bare counterpart.
"""
# The concretely-typed method carries the logic; Dict{String,Any} inputs (what JSON
# parsing yields) are normalised into it first, which keeps this resolvable under
# `--trim=safe` - a JWK's required members are strings by definition.
function jwk_thumbprint(jwk::Dict{String,String})
    kty_value = get(jwk, "kty", "")
    isempty(kty_value) && throw(ArgumentError("JWK is missing the required kty member"))
    members = get(JWK_THUMBPRINT_MEMBERS, uppercase(kty_value), nothing)
    members === nothing && throw(ArgumentError("Unsupported JWK kty for thumbprint: $(kty_value)"))
    required = Dict{String,String}()
    for member in members
        if member == "kty"
            required[member] = kty_value
            continue
        end
        value = get(jwk, member, "")
        isempty(value) && throw(ArgumentError("JWK is missing required member $(member) for kty=$(kty_value)"))
        required[member] = value
    end
    canonical = canonical_json(required)
    digest = SHA.sha256(codeunits(canonical))
    return base64urlencode(digest)
end

function jwk_thumbprint(jwk::AbstractDict)
    normalized = Dict{String,String}()
    for (k, v) in jwk
        k isa AbstractString || continue
        v isa AbstractString || continue
        normalized[String(k)] = String(v)
    end
    haskey(normalized, "kty") || throw(ArgumentError("JWK is missing the required kty member"))
    return jwk_thumbprint(normalized)
end

# RFC 9449 Section 4.3: a DPoP proof's `jwk` header must carry only public key material.
const JWK_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")

jwk_has_private_material(jwk::Dict{String,String}) = any(member -> haskey(jwk, member), JWK_PRIVATE_MEMBERS)
jwk_has_private_material(jwk::AbstractDict) = any(member -> haskey(jwk, member), JWK_PRIVATE_MEMBERS)

"""
    JOSEHeader(; typ="JWT", alg, kid=nothing)

The JOSE header of a signed token. A fixed shape (RFC 7515 §4.1: `typ`, `alg`,
`kid`), so it serializes through a typed JSON write; `kid` is omitted when
absent.
"""
Base.@kwdef struct JOSEHeader
    typ::String = "JWT"
    alg::String = ""
    kid::Union{Nothing,String} = nothing
end

joseheader_json(h::JOSEHeader) = JSON.json(h; omit_null=true)

# `header` is a `JOSEHeader` (typed write) or a `Dict{String,Any}` for callers
# that need extra members; `payload` is likewise the open claim set or an
# application-declared claims struct (see `AuthorizationServerStores(...;
# claims=...)`), whose JSON write is then fully typed.
function build_jws_compact(header::JOSEHeader, payload, signer::JWTSigner, alg::Symbol)
    return _build_jws(
        joseheader_json(JOSEHeader(header.typ, jose_alg_name(alg), header.kid)),
        payload,
        signer,
        alg,
    )
end

function build_jws_compact(header::Dict{String,Any}, payload, signer::JWTSigner, alg::Symbol)
    header["alg"] = jose_alg_name(alg)
    return _build_jws(JSON.json(header), payload, signer, alg)
end

function _build_jws(header_json::String, payload, signer::JWTSigner, alg::Symbol)
    payload_json = JSON.json(payload)
    encoded_header = base64urlencode(header_json)
    encoded_payload = base64urlencode(payload_json)
    signing_input = Vector{UInt8}(codeunits(string(encoded_header, ".", encoded_payload)))
    signature = sign_jws(signer, alg, signing_input)
    encoded_signature = base64urlencode(signature)
    return string(encoded_header, ".", encoded_payload, ".", encoded_signature)
end

function decode_jwt_segment(segment::AbstractString, name::AbstractString)
    return try
        base64urldecode(segment)
    catch
        throw(OAuthError(:invalid_token, "JWT $(name) segment is not valid base64url"))
    end
end

function decode_jwt_json_segment(segment::AbstractString, name::AbstractString)
    bytes = decode_jwt_segment(segment, name)
    parsed = try
        JSON.parse(String(bytes))
    catch
        throw(OAuthError(:invalid_token, "JWT $(name) segment is not valid JSON"))
    end
    parsed isa AbstractDict || throw(OAuthError(:invalid_token, "JWT $(name) segment must be a JSON object"))
    return parsed
end

# Decodes a compact JWS. Every malformed-input path raises `OAuthError(:invalid_token, ...)`
# so that callers (notably `protected_resource_middleware`) can answer with 401 instead of
# letting an attacker-supplied token surface as an unhandled 500.
function decode_compact_jwt(token::AbstractString)
    parts = split(String(token), '.')
    length(parts) == 3 || throw(OAuthError(:invalid_token, "JWT must contain three segments"))
    header = decode_jwt_json_segment(parts[1], "header")
    payload = decode_jwt_json_segment(parts[2], "payload")
    signature = decode_jwt_segment(parts[3], "signature")
    signing_input = Vector{UInt8}(codeunits(string(parts[1], ".", parts[2])))
    return header, payload, signature, signing_input
end

"""
    eddsa_verifier_from_bytes(data) -> EdDSAVerifier

Normalizes any vector-like input to a 32-byte Ed25519 public key and
returns an `EdDSAVerifier`.
"""
function eddsa_verifier_from_bytes(raw)
    bytes = Vector{UInt8}(raw)
    length(bytes) == ED25519_PUBLIC_KEY_BYTES || error("Ed25519 public keys must be $(ED25519_PUBLIC_KEY_BYTES) bytes")
    return EdDSAVerifier(JWTs.okp_public_key("Ed25519", bytes), bytes)
end

"""
    rsa_verifier_from_der(der_bytes) -> RSAVerifier

Creates an RSA verification handle from DER-encoded PKCS#1 public key
bytes.
"""
function rsa_verifier_from_der(der::Vector{UInt8})
    idx = 1
    der[idx] == 0x30 || error("Failed to load RSA public key from DER bytes")
    idx += 1
    _, consumed = read_der_length(der, idx)
    idx += consumed
    modulus, idx = parse_der_integer(der, idx)
    exponent, _ = parse_der_integer(der, idx)
    return RSAVerifier(JWTs.rsa_public_key(modulus, exponent))
end

"""
    rsa_verifier_from_components(modulus, exponent) -> RSAVerifier

Convenience helper that builds the verification handle directly from
big-endian modulus/exponent values.
"""
function rsa_verifier_from_components(modulus::Vector{UInt8}, exponent::Vector{UInt8})
    return RSAVerifier(JWTs.rsa_public_key(modulus, exponent))
end

"""
    ecc_public_coordinates(signer::ECSigner) -> (x::Vector{UInt8}, y::Vector{UInt8})

Extracts the affine coordinates for the signer’s public key so you can
publish a JWK or construct a verifier.
"""
function ecc_public_coordinates(signer::ECSigner)
    expected = signer.curve == :P256 ? 32 : 48
    # OSSL_PKEY_PARAM_PUB_KEY yields the encoded public point; for a named
    # curve this is the uncompressed form 0x04 || x || y.
    needed = Ref{Csize_t}(0)
    key = signer.key
    ret = GC.@preserve key ccall(
        (:EVP_PKEY_get_octet_string_param, LIBCRYPTO),
        Cint,
        (Ptr{Cvoid}, Cstring, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
        key.ptr,
        "pub",
        Ptr{UInt8}(C_NULL),
        Csize_t(0),
        needed,
    )
    ret == 1 || error("EC key pair does not expose public key coordinates; provide an explicit public_jwk")
    point = Vector{UInt8}(undef, Int(needed[]))
    ret = GC.@preserve key point ccall(
        (:EVP_PKEY_get_octet_string_param, LIBCRYPTO),
        Cint,
        (Ptr{Cvoid}, Cstring, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
        key.ptr,
        "pub",
        pointer(point),
        Csize_t(length(point)),
        needed,
    )
    ret == 1 || error("EC key pair does not expose public key coordinates; provide an explicit public_jwk")
    (length(point) == 1 + 2 * expected && point[1] == 0x04) ||
        error("Unexpected EC public key coordinate length for curve $(signer.curve): got $(length(point)) encoded bytes, expected $(1 + 2 * expected)")
    x = point[2:1 + expected]
    y = point[2 + expected:end]
    return x, y
end

"""
    ecc_verifier_from_coordinates(x, y, curve) -> ECVerifier

Builds an `ECVerifier` from the raw affine coordinates of a public key.
"""
function ecc_verifier_from_coordinates(x::Vector{UInt8}, y::Vector{UInt8}, curve::Symbol)
    return ECVerifier(JWTs.ec_public_key(jose_curve_name(curve), x, y), curve)
end

function parse_rsa_pkcs1_private_key(bytes::Vector{UInt8})
    idx = 1
    bytes[idx] == 0x30 || error("Invalid RSA private key (expected sequence)")
    idx += 1
    _, consumed = read_der_length(bytes, idx)
    idx += consumed
    _, idx = parse_der_integer(bytes, idx) # version
    modulus, idx = parse_der_integer(bytes, idx)
    exponent, _ = parse_der_integer(bytes, idx)
    return modulus, exponent
end

function unwrap_pkcs8_private_key(bytes::Vector{UInt8})
    idx = 1
    bytes[idx] == 0x30 || error("Invalid PKCS#8 key (expected sequence)")
    idx += 1
    _, consumed = read_der_length(bytes, idx)
    idx += consumed
    _, idx = parse_der_integer(bytes, idx) # version
    bytes[idx] == 0x30 || error("Invalid PKCS#8 algorithm identifier")
    idx += 1
    alg_len, alg_consumed = read_der_length(bytes, idx)
    idx += alg_consumed + alg_len
    bytes[idx] == 0x04 || error("PKCS#8 private key must be an octet string")
    idx += 1
    key_len, consumed = read_der_length(bytes, idx)
    idx += consumed
    return copy(bytes[idx:idx + key_len - 1])
end

"""
    rsa_public_components(signer::RSASigner) -> (modulus, exponent)

Big-endian modulus and public exponent read from the loaded key itself, so a
JWK can be derived from a signer built without the PEM bytes at hand.
"""
function rsa_public_components(signer::RSASigner)
    key = signer.key
    n = _evp_bn_param(key, "n")
    e = _evp_bn_param(key, "e")
    return n, e
end

function _evp_bn_param(key::JWTs.OpenSSLKey, name::String)
    bn_ref = Ref{Ptr{Cvoid}}(C_NULL)
    ok = GC.@preserve key ccall(
        (:EVP_PKEY_get_bn_param, LIBCRYPTO),
        Cint,
        (Ptr{Cvoid}, Cstring, Ref{Ptr{Cvoid}}),
        key.ptr, name, bn_ref,
    )
    JWTs.require_openssl_ok(ok, "EVP_PKEY_get_bn_param($name)")
    bn = bn_ref[]
    JWTs.require_openssl_nonnull(bn, "EVP_PKEY_get_bn_param($name)")
    try
        nbytes = Int(ccall((:BN_num_bits, LIBCRYPTO), Cint, (Ptr{Cvoid},), bn) + 7) ÷ 8
        nbytes > 0 || error("EVP_PKEY_get_bn_param($name) returned an empty integer")
        out = Vector{UInt8}(undef, nbytes)
        written = GC.@preserve out ccall((:BN_bn2bin, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ptr{UInt8}), bn, pointer(out))
        Int(written) == nbytes || error(
            "BN_bn2bin($name) wrote $(Int(written)) bytes; expected $nbytes")
        return out
    finally
        JWTs.free_bn!(bn)
    end
end

function rsa_public_components_from_private_bytes(raw)
    bytes = normalize_key_bytes(raw)
    try
        return parse_rsa_pkcs1_private_key(bytes)
    catch
        pkcs1 = unwrap_pkcs8_private_key(bytes)
        return parse_rsa_pkcs1_private_key(pkcs1)
    end
end

"""
    generate_rsa_private_key(; bits=2048) -> String

Generates a new RSA private key in PEM format using OpenSSL. Returns the key as a
PEM-encoded string suitable for use with [`rsa_signer_from_bytes`](@ref) or
[`JWTAccessTokenIssuer`](@ref).

# Arguments
- `bits`: RSA key size in bits (default: 2048). Common values are 2048, 3072, or 4096.

# Examples
```julia
private_key = generate_rsa_private_key(bits=2048)
issuer = JWTAccessTokenIssuer(
    issuer="https://example.com",
    audience=["https://api.example.com"],
    private_key=private_key,
    alg=:RS256
)
```

"""
function generate_rsa_private_key(; bits::Integer=2048)
    bits > 0 || error("RSA key size must be positive")
    ctx = ccall((:EVP_PKEY_CTX_new_id, LIBCRYPTO), Ptr{Cvoid}, (Cint, Ptr{Cvoid}), NID_RSA_ENCRYPTION, C_NULL)
    JWTs.require_openssl_nonnull(ctx, "EVP_PKEY_CTX_new_id(RSA)")
    try
        JWTs.require_openssl_ok(
            ccall((:EVP_PKEY_keygen_init, LIBCRYPTO), Cint, (Ptr{Cvoid},), ctx),
            "EVP_PKEY_keygen_init",
        )
        JWTs.require_openssl_ok(
            ccall((:EVP_PKEY_CTX_set_rsa_keygen_bits, LIBCRYPTO), Cint, (Ptr{Cvoid}, Cint), ctx, Cint(bits)),
            "EVP_PKEY_CTX_set_rsa_keygen_bits",
        )
        return keygen_pem(ctx)
    finally
        ccall((:EVP_PKEY_CTX_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ctx)
    end
end

"""
    generate_ec_private_key(; curve=:P256) -> String

Generates a new EC private key in PEM format using OpenSSL. Returns the key as a
PEM-encoded string suitable for use with [`ecc_signer_from_bytes`](@ref) or
[`JWTAccessTokenIssuer`](@ref).

# Arguments
- `curve`: EC curve name (default: `:P256`). Supported values are `:P256` or `:P384`.

# Examples
```julia
private_key = generate_ec_private_key(curve=:P256)
issuer = JWTAccessTokenIssuer(
    issuer="https://example.com",
    audience=["https://api.example.com"],
    private_key=private_key,
    alg=:ES256
)
```

"""
function generate_ec_private_key(; curve::Symbol=:P256)
    crv = jose_curve_name(curve)
    ctx = ccall((:EVP_PKEY_CTX_new_id, LIBCRYPTO), Ptr{Cvoid}, (Cint, Ptr{Cvoid}), NID_X9_62_EC, C_NULL)
    JWTs.require_openssl_nonnull(ctx, "EVP_PKEY_CTX_new_id(EC)")
    try
        JWTs.require_openssl_ok(
            ccall((:EVP_PKEY_keygen_init, LIBCRYPTO), Cint, (Ptr{Cvoid},), ctx),
            "EVP_PKEY_keygen_init",
        )
        JWTs.require_openssl_ok(
            ccall((:EVP_PKEY_CTX_set_ec_paramgen_curve_nid, LIBCRYPTO), Cint, (Ptr{Cvoid}, Cint), ctx, JWTs.ec_group_nid(crv)),
            "EVP_PKEY_CTX_set_ec_paramgen_curve_nid",
        )
        return keygen_pem(ctx)
    finally
        ccall((:EVP_PKEY_CTX_free, LIBCRYPTO), Cvoid, (Ptr{Cvoid},), ctx)
    end
end

# Finish a configured keygen context and PEM-encode the key (unencrypted
# PKCS#8, the same form `openssl genpkey` emits).
function keygen_pem(ctx::Ptr{Cvoid})
    pkey_ref = Ref{Ptr{Cvoid}}(C_NULL)
    JWTs.require_openssl_ok(
        ccall((:EVP_PKEY_keygen, LIBCRYPTO), Cint, (Ptr{Cvoid}, Ref{Ptr{Cvoid}}), ctx, pkey_ref),
        "EVP_PKEY_keygen",
    )
    pkey = pkey_ref[]
    bio = Ptr{Cvoid}(C_NULL)
    try
        method = ccall((:BIO_s_mem, LIBCRYPTO), Ptr{Cvoid}, ())
        bio = ccall((:BIO_new, LIBCRYPTO), Ptr{Cvoid}, (Ptr{Cvoid},), method)
        JWTs.require_openssl_nonnull(bio, "BIO_new")
        JWTs.require_openssl_ok(
            ccall(
                (:PEM_write_bio_PKCS8PrivateKey, LIBCRYPTO),
                Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Cvoid}, Ptr{Cvoid}),
                bio, pkey, C_NULL, C_NULL, Cint(0), C_NULL, C_NULL,
            ),
            "PEM_write_bio_PKCS8PrivateKey",
        )
        data_ref = Ref{Ptr{UInt8}}(C_NULL)
        len = ccall((:BIO_ctrl, LIBCRYPTO), Clong, (Ptr{Cvoid}, Cint, Clong, Ref{Ptr{UInt8}}), bio, 3, 0, data_ref) # BIO_CTRL_INFO
        (len > 0 && data_ref[] != C_NULL) || throw(JWTs.openssl_error("BIO_ctrl(BIO_CTRL_INFO)"))
        return unsafe_string(data_ref[], len)
    finally
        JWTs.free_bio!(bio)
        JWTs.free_evp_pkey!(pkey)
    end
end
