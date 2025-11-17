# Internal utilities for JOSE/JWT handling with LibAwsCal backing.

using libsodium_jll

const AwsCommon = LibAwsCal.LibAwsCommon
const LIBSODIUM = libsodium_jll.libsodium
const ED25519_PUBLIC_KEY_BYTES = 32
const ED25519_SECRET_KEY_BYTES = 64
const ED25519_SIGNATURE_BYTES = 64
const ED25519_SEED_BYTES = 32

abstract type JWTSigner end

mutable struct RSAKeyHandle
    ptr::Ptr{aws_rsa_key_pair}
    function RSAKeyHandle(ptr::Ptr{aws_rsa_key_pair})
        ptr == C_NULL && error("RSA key pointer must not be null")
        handle = new(ptr)
        finalizer(handle) do h
            if h.ptr != C_NULL
                aws_rsa_key_pair_release(h.ptr)
                h.ptr = Ptr{aws_rsa_key_pair}(C_NULL)
            end
        end
        return handle
    end
end

mutable struct ECCKeyHandle
    ptr::Ptr{aws_ecc_key_pair}
    function ECCKeyHandle(ptr::Ptr{aws_ecc_key_pair})
        ptr == C_NULL && error("EC key pointer must not be null")
        handle = new(ptr)
        finalizer(handle) do h
            if h.ptr != C_NULL
                aws_ecc_key_pair_release(h.ptr)
                h.ptr = Ptr{aws_ecc_key_pair}(C_NULL)
            end
        end
        return handle
    end
end

struct RSASigner <: JWTSigner
    key::RSAKeyHandle
end

struct ECSigner <: JWTSigner
    key::ECCKeyHandle
    curve::Symbol        # :P256 or :P384
end

struct EdDSASigner <: JWTSigner
    secret::Vector{UInt8}
    public::Vector{UInt8}
end

abstract type JWTVerifier end

struct RSAVerifier <: JWTVerifier
    key::RSAKeyHandle
end

struct ECVerifier <: JWTVerifier
    key::ECCKeyHandle
    curve::Symbol
end

struct EdDSAVerifier <: JWTVerifier
    public::Vector{UInt8}
end

const SUPPORTED_RSA_ALGS = Set([:RS256, :PS256])
const SUPPORTED_EC_ALGS = Set([:ES256, :ES384])
const SUPPORTED_OKP_ALGS = Set([:EDDSA])

function rsa_signature_algorithm(alg::Symbol)
    if alg == :RS256
        return AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256
    elseif alg == :PS256
        return AWS_CAL_RSA_SIGNATURE_PSS_SHA256
    else
        error("Unsupported RSA signature algorithm $(alg)")
    end
end

function rsa_digest(alg::Symbol, signing_input::Vector{UInt8})
    if alg in (:RS256, :PS256)
        return SHA.sha256(signing_input)
    else
        error("Unsupported RSA digest for $(alg)")
    end
end

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
    return Base64.base64decode(encoded)
end

normalize_key_bytes(data::AbstractString) = decode_pem(data)
normalize_key_bytes(data::Vector{UInt8}) = copy(data)
normalize_key_bytes(data::Base.CodeUnits{UInt8, String}) = normalize_key_bytes(String(data))

const SODIUM_INITIALIZED = Base.RefValue(false)

function ensure_sodium_initialized()
    if !SODIUM_INITIALIZED[]
        result = ccall((:sodium_init, LIBSODIUM), Cint, ())
        result < 0 && error("sodium_init failed with code $(result)")
        SODIUM_INITIALIZED[] = true
    end
end

function ed25519_seed_keypair(seed::Vector{UInt8})
    ensure_sodium_initialized()
    length(seed) == ED25519_SEED_BYTES || error("Ed25519 seeds must be $(ED25519_SEED_BYTES) bytes")
    public = Vector{UInt8}(undef, ED25519_PUBLIC_KEY_BYTES)
    secret = Vector{UInt8}(undef, ED25519_SECRET_KEY_BYTES)
    GC.@preserve seed public secret begin
        result = ccall(
            (:crypto_sign_ed25519_seed_keypair, LIBSODIUM),
            Cint,
            (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
            pointer(public),
            pointer(secret),
            pointer(seed),
        )
        result == 0 || error("Unable to derive Ed25519 keypair from seed")
    end
    return secret, public
end

function ed25519_public_from_secret(secret::Vector{UInt8})
    ensure_sodium_initialized()
    length(secret) == ED25519_SECRET_KEY_BYTES || error("Ed25519 secret keys must be $(ED25519_SECRET_KEY_BYTES) bytes")
    public = Vector{UInt8}(undef, ED25519_PUBLIC_KEY_BYTES)
    GC.@preserve secret public begin
        result = ccall(
            (:crypto_sign_ed25519_sk_to_pk, LIBSODIUM),
            Cint,
            (Ptr{UInt8}, Ptr{UInt8}),
            pointer(public),
            pointer(secret),
        )
        result == 0 || error("Unable to derive Ed25519 public key from secret key")
    end
    return public
end

function rsa_signer_from_bytes(raw)
    bytes = normalize_key_bytes(raw)
    alloc = default_aws_allocator()
    key_ptr = Ptr{aws_rsa_key_pair}(C_NULL)
    GC.@preserve bytes begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(bytes)), length(bytes))
        key_ptr = aws_rsa_key_pair_new_from_private_key_pkcs8(alloc, cursor)
        if key_ptr == C_NULL
            key_ptr = aws_rsa_key_pair_new_from_private_key_pkcs1(alloc, cursor)
        end
    end
    key_ptr == C_NULL && error("Failed to load RSA private key (expected PKCS#8 or PKCS#1 DER/PEM)")
    return RSASigner(RSAKeyHandle(key_ptr))
end

function ecc_signer_from_bytes(raw, curve::Symbol)
    bytes = normalize_key_bytes(raw)
    alloc = default_aws_allocator()
    curve_id = curve == :P256 ? AWS_CAL_ECDSA_P256 :
               curve == :P384 ? AWS_CAL_ECDSA_P384 :
               error("Unsupported EC curve: $curve")
    key_ptr = Ptr{aws_ecc_key_pair}(C_NULL)
    GC.@preserve bytes begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(bytes)), length(bytes))
        cursor_ref = Ref(cursor)
        key_ptr = aws_ecc_key_pair_new_from_asn1(alloc, cursor_ref)
        if key_ptr == C_NULL
            key_ptr = aws_ecc_key_pair_new_from_private_key(alloc, curve_id, cursor_ref)
        end
    end
    key_ptr == C_NULL && error("Failed to load EC private key for curve $(curve)")
    return ECSigner(ECCKeyHandle(key_ptr), curve)
end

function eddsa_signer_from_bytes(raw)
    bytes = normalize_key_bytes(raw)
    if length(bytes) == ED25519_SECRET_KEY_BYTES
        secret = bytes
        public = ed25519_public_from_secret(secret)
        return EdDSASigner(secret, public)
    elseif length(bytes) == ED25519_SEED_BYTES
        secret, public = ed25519_seed_keypair(bytes)
        return EdDSASigner(secret, public)
    else
        error("Unsupported Ed25519 key length ($(length(bytes)))")
    end
end

function allocate_byte_buf(capacity::Integer)
    buf = Ref(AwsCommon.aws_byte_buf(0, Ptr{UInt8}(C_NULL), 0, Ptr{AwsCommon.aws_allocator}(C_NULL)))
    res = AwsCommon.aws_byte_buf_init(buf, default_aws_allocator(), capacity)
    res == 0 || error("aws_byte_buf_init failed with code $res")
    return buf
end

function take_byte_buf(buf::Ref{AwsCommon.aws_byte_buf})
    len = buf[].len
    ptr = buf[].buffer
    data = unsafe_wrap(Vector{UInt8}, ptr, len; own=false)
    copy_data = Vector{UInt8}(data)
    AwsCommon.aws_byte_buf_clean_up(buf)
    return copy_data
end

function sign_jws(signer::RSASigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_RSA_ALGS || error("Unsupported RSA JWT alg $(alg)")
    digest = rsa_digest(alg, signing_input)
    algorithm = rsa_signature_algorithm(alg)
    sig_buf = allocate_byte_buf(Int(aws_rsa_key_pair_signature_length(signer.key.ptr)))
    GC.@preserve digest begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(digest)), length(digest))
        result = aws_rsa_key_pair_sign_message(
            signer.key.ptr,
            algorithm,
            cursor,
            sig_buf,
        )
        result == 0 || begin
            AwsCommon.aws_byte_buf_clean_up(sig_buf)
            error("RSA signing failed with code $(result)")
        end
    end
    return take_byte_buf(sig_buf)
end

function sign_jws(signer::ECSigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_EC_ALGS || error("Unsupported EC JWT alg $(alg)")
    digest = algorithm_digest(alg, signing_input)
    sig_capacity = Int(aws_ecc_key_pair_signature_length(signer.key.ptr))
    sig_buf = allocate_byte_buf(sig_capacity)
    GC.@preserve digest begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(digest)), length(digest))
        cursor_ref = Ref(cursor)
        result = aws_ecc_key_pair_sign_message(
            signer.key.ptr,
            cursor_ref,
            sig_buf,
        )
        result == 0 || begin
            AwsCommon.aws_byte_buf_clean_up(sig_buf)
            error("EC signing failed with code $(result)")
        end
    end
    der_signature = take_byte_buf(sig_buf)
    size = signer.curve == :P256 ? 32 : 48
    return der_to_jws_signature(der_signature, size)
end

function sign_jws(signer::EdDSASigner, alg::Symbol, signing_input::Vector{UInt8})
    alg in SUPPORTED_OKP_ALGS || error("Unsupported OKP alg $(alg)")
    ensure_sodium_initialized()
    signature = Vector{UInt8}(undef, ED25519_SIGNATURE_BYTES)
    sig_len = Ref{Csize_t}(0)
    secret = signer.secret
    GC.@preserve signature signing_input secret begin
        result = ccall(
            (:crypto_sign_ed25519_detached, LIBSODIUM),
            Cint,
            (Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
            pointer(signature),
            sig_len,
            pointer(signing_input),
            Culonglong(length(signing_input)),
            pointer(secret),
        )
        result == 0 || error("Ed25519 signing failed (code $(result))")
    end
    sig_len[] == ED25519_SIGNATURE_BYTES || error("Incorrect Ed25519 signature length")
    return signature
end

function verify_jws(verifier::RSAVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_RSA_ALGS || error("Unsupported RSA JWT alg $(alg)")
    digest = rsa_digest(alg, signing_input)
    algorithm = rsa_signature_algorithm(alg)
    GC.@preserve digest signature begin
        digest_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(digest)), length(digest))
        sig_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(signature)), length(signature))
        result = aws_rsa_key_pair_verify_signature(
            verifier.key.ptr,
            algorithm,
            digest_cursor,
            sig_cursor,
        )
        return result == 0
    end
end

function verify_jws(verifier::ECVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_EC_ALGS || error("Unsupported EC JWT alg $(alg)")
    digest = algorithm_digest(alg, signing_input)
    coord = verifier.curve == :P256 ? 32 : 48
    der_signature = jws_to_der_signature(signature, coord)
    GC.@preserve digest der_signature begin
        digest_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(digest)), length(digest))
        der_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(der_signature)), length(der_signature))
        cursor_ref = Ref(digest_cursor)
        sig_ref = Ref(der_cursor)
        result = aws_ecc_key_pair_verify_signature(
            verifier.key.ptr,
            cursor_ref,
            sig_ref,
        )
        return result == 0
    end
end

function verify_jws(verifier::EdDSAVerifier, alg::Symbol, signing_input::Vector{UInt8}, signature::Vector{UInt8})
    alg in SUPPORTED_OKP_ALGS || error("Unsupported OKP alg $(alg)")
    length(signature) == ED25519_SIGNATURE_BYTES || return false
    ensure_sodium_initialized()
    public = verifier.public
    GC.@preserve signature signing_input public begin
        result = ccall(
            (:crypto_sign_ed25519_verify_detached, LIBSODIUM),
            Cint,
            (Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
            pointer(signature),
            pointer(signing_input),
            Culonglong(length(signing_input)),
            pointer(public),
        )
        return result == 0
    end
end


function algorithm_digest(alg::Symbol, input::Vector{UInt8})
    if alg in (:ES256, :RS256)
        return SHA.sha256(input)
    elseif alg == :ES384
        return SHA.sha384(input)
    else
        error("Unsupported digest for alg $(alg)")
    end
end

function der_to_jws_signature(der::Vector{UInt8}, coordinate_size::Int)
    length(der) >= 8 || error("Invalid DER signature (too short)")
    idx = 1
    der[idx] == 0x30 || error("Invalid DER signature (expected sequence)")
    idx += 1
    total_len, consumed = read_der_length(der, idx)
    idx += consumed
    end_idx = idx + total_len - 1
    r, idx = parse_der_integer(der, idx)
    s, idx = parse_der_integer(der, idx)
    idx - 1 == end_idx || error("Invalid DER signature length")
    (length(r) <= coordinate_size && length(s) <= coordinate_size) || error("Invalid DER signature integer length")
    r_bytes = lpad_bytes(r, coordinate_size)
    s_bytes = lpad_bytes(s, coordinate_size)
    return vcat(r_bytes, s_bytes)
end

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

function lpad_bytes(bytes::Vector{UInt8}, size::Int)
    length(bytes) <= size || error("Cannot left pad bytes larger than size")
    if length(bytes) == size
        return bytes
    end
    padded = Vector{UInt8}(undef, size)
    fill!(padded, 0x00)
    copyto!(padded, size - length(bytes) + 1, bytes, 1, length(bytes))
    return padded
end

function strip_leading_zeros(bytes::Vector{UInt8})
    idx = findfirst(b -> b != 0x00, bytes)
    if idx === nothing
        return UInt8[0x00]
    elseif idx == 1
        return copy(bytes)
    else
        return bytes[idx:end]
    end
end

function encode_der_length(len::Integer)
    len < 0 && error("DER length cannot be negative")
    if len < 0x80
        return UInt8[len]
    end
    buf = UInt8[]
    value = len
    while value > 0
        pushfirst!(buf, value & 0xff)
        value >>= 8
    end
    pushfirst!(buf, 0x80 | length(buf))
    return buf
end

function encode_der_integer(bytes::Vector{UInt8})
    stripped = strip_leading_zeros(bytes)
    if stripped[1] & 0x80 != 0
        stripped = vcat(UInt8[0x00], stripped)
    end
    len_bytes = encode_der_length(length(stripped))
    return vcat(UInt8[0x02], len_bytes, stripped)
end

function encode_der_sequence(parts::Vector{Vector{UInt8}})
    total_len = sum(length, parts)
    len_bytes = encode_der_length(total_len)
    buffer = Vector{UInt8}(undef, 1 + length(len_bytes) + total_len)
    buffer[1] = 0x30
    copyto!(buffer, 2, len_bytes, 1, length(len_bytes))
    offset = 1 + length(len_bytes)
    for part in parts
        copyto!(buffer, offset + 1, part, 1, length(part))
        offset += length(part)
    end
    return buffer
end

function jws_to_der_signature(signature::Vector{UInt8}, coordinate_size::Int)
    expected = coordinate_size * 2
    length(signature) == expected || error("Invalid JWS signature length for curve size $(coordinate_size)")
    r = signature[1:coordinate_size]
    s = signature[coordinate_size+1:end]
    r_der = encode_der_integer(r)
    s_der = encode_der_integer(s)
    return encode_der_sequence([r_der, s_der])
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

function canonical_json(obj::Dict{String,Any})
    ordered = sort(collect(keys(obj)))
    parts = Vector{String}(undef, length(ordered))
    for (i, key) in enumerate(ordered)
        value = obj[key]
        parts[i] = string("\"", key, "\":", JSON.json(value))
    end
    return "{" * join(parts, ",") * "}"
end

function jwk_thumbprint(jwk::Dict{String,Any})
    canonical = canonical_json(jwk)
    digest = SHA.sha256(codeunits(canonical))
    return base64urlencode(digest)
end

function build_jws_compact(header::Dict{String,Any}, payload::Dict{String,Any}, signer::JWTSigner, alg::Symbol)
    header["alg"] = String(alg)
    header_json = JSON.json(header)
    payload_json = JSON.json(payload)
    encoded_header = base64urlencode(header_json)
    encoded_payload = base64urlencode(payload_json)
    signing_input = Vector{UInt8}(codeunits(string(encoded_header, ".", encoded_payload)))
    signature = sign_jws(signer, alg, signing_input)
    encoded_signature = base64urlencode(signature)
    return string(encoded_header, ".", encoded_payload, ".", encoded_signature)
end

function decode_compact_jwt(token::AbstractString)
    parts = split(String(token), '.')
    length(parts) == 3 || throw(OAuthError(:invalid_token, "JWT must contain three segments"))
    header = JSON.parse(String(base64urldecode(parts[1])))
    payload = JSON.parse(String(base64urldecode(parts[2])))
    signature = base64urldecode(parts[3])
    signing_input = Vector{UInt8}(codeunits(string(parts[1], ".", parts[2])))
    return header, payload, signature, signing_input
end

function eddsa_verifier_from_bytes(raw)
    ensure_sodium_initialized()
    bytes = Vector{UInt8}(raw)
    length(bytes) == ED25519_PUBLIC_KEY_BYTES || error("Ed25519 public keys must be $(ED25519_PUBLIC_KEY_BYTES) bytes")
    return EdDSAVerifier(bytes)
end

function rsa_verifier_from_der(der::Vector{UInt8})
    alloc = default_aws_allocator()
    key_ptr = Ptr{aws_rsa_key_pair}(C_NULL)
    GC.@preserve der begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(der)), length(der))
        key_ptr = aws_rsa_key_pair_new_from_public_key_pkcs1(alloc, cursor)
    end
    key_ptr == C_NULL && error("Failed to load RSA public key from DER bytes")
    return RSAVerifier(RSAKeyHandle(key_ptr))
end

function rsa_verifier_from_components(modulus::Vector{UInt8}, exponent::Vector{UInt8})
    der = encode_der_sequence([encode_der_integer(modulus), encode_der_integer(exponent)])
    return rsa_verifier_from_der(der)
end

function ecc_public_coordinates(signer::ECSigner)
    x_ref = Ref(AwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL)))
    y_ref = Ref(AwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL)))
    result = aws_ecc_key_pair_get_public_key(signer.key.ptr, x_ref, y_ref)
    result == 0 || error("aws_ecc_key_pair_get_public_key failed with code $(result)")
    x_bytes = unsafe_wrap(Vector{UInt8}, x_ref[].ptr, x_ref[].len; own=false)
    y_bytes = unsafe_wrap(Vector{UInt8}, y_ref[].ptr, y_ref[].len; own=false)
    return copy(x_bytes), copy(y_bytes)
end

function ecc_verifier_from_coordinates(x::Vector{UInt8}, y::Vector{UInt8}, curve::Symbol)
    alloc = default_aws_allocator()
    curve_id = curve == :P256 ? AWS_CAL_ECDSA_P256 :
               curve == :P384 ? AWS_CAL_ECDSA_P384 :
               error("Unsupported EC curve $(curve)")
    key_ptr = Ptr{aws_ecc_key_pair}(C_NULL)
    GC.@preserve x y begin
        x_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(x)), length(x))
        y_cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(y)), length(y))
        key_ptr = aws_ecc_key_pair_new_from_public_key(alloc, curve_id, Ref(x_cursor), Ref(y_cursor))
    end
    key_ptr == C_NULL && error("Failed to load EC public key")
    return ECVerifier(ECCKeyHandle(key_ptr), curve)
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

function rsa_public_components_from_private_bytes(raw)
    bytes = normalize_key_bytes(raw)
    try
        return parse_rsa_pkcs1_private_key(bytes)
    catch
        pkcs1 = unwrap_pkcs8_private_key(bytes)
        return parse_rsa_pkcs1_private_key(pkcs1)
    end
end
