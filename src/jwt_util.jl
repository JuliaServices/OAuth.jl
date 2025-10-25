# Internal utilities for JOSE/JWT handling with LibAwsCal backing.

const AwsCommon = LibAwsCal.LibAwsCommon

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

const SUPPORTED_RSA_ALGS = Set([:RS256])
const SUPPORTED_EC_ALGS = Set([:ES256, :ES384])

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
    digest = SHA.sha256(signing_input)
    sig_buf = allocate_byte_buf(Int(aws_rsa_key_pair_signature_length(signer.key.ptr)))
    GC.@preserve digest begin
        cursor = AwsCommon.aws_byte_cursor_from_array(Ptr{Cvoid}(pointer(digest)), length(digest))
        result = aws_rsa_key_pair_sign_message(
            signer.key.ptr,
            AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256,
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
