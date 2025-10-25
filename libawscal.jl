using CEnum

"""
    aws_cal_errors

Documentation not found.
"""
@cenum aws_cal_errors::UInt32 begin
    AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED = 7168
    AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT = 7169
    AWS_ERROR_CAL_INVALID_KEY_LENGTH_FOR_ALGORITHM = 7170
    AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER = 7171
    AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED = 7172
    AWS_ERROR_CAL_MISMATCHED_DER_TYPE = 7173
    AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM = 7174
    AWS_ERROR_CAL_BUFFER_TOO_LARGE_FOR_ALGORITHM = 7175
    AWS_ERROR_CAL_INVALID_CIPHER_MATERIAL_SIZE_FOR_ALGORITHM = 7176
    AWS_ERROR_CAL_DER_UNSUPPORTED_NEGATIVE_INT = 7177
    AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT = 7178
    AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED = 7179
    AWS_ERROR_CAL_END_RANGE = 8191
end

"""
    aws_cal_log_subject

Documentation not found.
"""
@cenum aws_cal_log_subject::UInt32 begin
    AWS_LS_CAL_GENERAL = 7168
    AWS_LS_CAL_ECC = 7169
    AWS_LS_CAL_HASH = 7170
    AWS_LS_CAL_HMAC = 7171
    AWS_LS_CAL_DER = 7172
    AWS_LS_CAL_LIBCRYPTO_RESOLVE = 7173
    AWS_LS_CAL_RSA = 7174
    AWS_LS_CAL_ED25519 = 7175
    AWS_LS_CAL_LAST = 8191
end

"""
    aws_cal_library_init(allocator)

Documentation not found.
### Prototype
```c
void aws_cal_library_init(struct aws_allocator *allocator);
```
"""
function aws_cal_library_init(allocator)
    ccall((:aws_cal_library_init, libaws_c_cal), Cvoid, (Ptr{aws_allocator},), allocator)
end

"""
    aws_cal_library_clean_up()

Documentation not found.
### Prototype
```c
void aws_cal_library_clean_up(void);
```
"""
function aws_cal_library_clean_up()
    ccall((:aws_cal_library_clean_up, libaws_c_cal), Cvoid, ())
end

"""
    aws_cal_thread_clean_up()

Documentation not found.
### Prototype
```c
void aws_cal_thread_clean_up(void);
```
"""
function aws_cal_thread_clean_up()
    ccall((:aws_cal_thread_clean_up, libaws_c_cal), Cvoid, ())
end

"""
    aws_ecc_curve_name

Documentation not found.
"""
@cenum aws_ecc_curve_name::UInt32 begin
    AWS_CAL_ECDSA_P256 = 0
    AWS_CAL_ECDSA_P384 = 1
end

# typedef void aws_ecc_key_pair_destroy_fn ( struct aws_ecc_key_pair * key_pair )
"""
Documentation not found.
"""
const aws_ecc_key_pair_destroy_fn = Cvoid

# typedef int aws_ecc_key_pair_sign_message_fn ( const struct aws_ecc_key_pair * key_pair , const struct aws_byte_cursor * message , struct aws_byte_buf * signature_output )
"""
Documentation not found.
"""
const aws_ecc_key_pair_sign_message_fn = Cvoid

# typedef int aws_ecc_key_pair_derive_public_key_fn ( struct aws_ecc_key_pair * key_pair )
"""
Documentation not found.
"""
const aws_ecc_key_pair_derive_public_key_fn = Cvoid

# typedef int aws_ecc_key_pair_verify_signature_fn ( const struct aws_ecc_key_pair * signer , const struct aws_byte_cursor * message , const struct aws_byte_cursor * signature )
"""
Documentation not found.
"""
const aws_ecc_key_pair_verify_signature_fn = Cvoid

# typedef size_t aws_ecc_key_pair_signature_length_fn ( const struct aws_ecc_key_pair * signer )
"""
Documentation not found.
"""
const aws_ecc_key_pair_signature_length_fn = Cvoid

"""
    aws_ecc_key_pair_vtable

Documentation not found.
"""
struct aws_ecc_key_pair_vtable
    destroy::Ptr{aws_ecc_key_pair_destroy_fn}
    derive_pub_key::Ptr{aws_ecc_key_pair_derive_public_key_fn}
    sign_message::Ptr{aws_ecc_key_pair_sign_message_fn}
    verify_signature::Ptr{aws_ecc_key_pair_verify_signature_fn}
    signature_length::Ptr{aws_ecc_key_pair_signature_length_fn}
end

"""
    aws_ecc_key_pair

Documentation not found.
"""
struct aws_ecc_key_pair
    allocator::Ptr{aws_allocator}
    ref_count::aws_atomic_var
    curve_name::aws_ecc_curve_name
    key_buf::aws_byte_buf
    pub_x::aws_byte_buf
    pub_y::aws_byte_buf
    priv_d::aws_byte_buf
    vtable::Ptr{aws_ecc_key_pair_vtable}
    impl::Ptr{Cvoid}
end

"""
    aws_ecc_key_pair_acquire(key_pair)

Adds one to an ecc key pair's ref count.

### Prototype
```c
void aws_ecc_key_pair_acquire(struct aws_ecc_key_pair *key_pair);
```
"""
function aws_ecc_key_pair_acquire(key_pair)
    ccall((:aws_ecc_key_pair_acquire, libaws_c_cal), Cvoid, (Ptr{aws_ecc_key_pair},), key_pair)
end

"""
    aws_ecc_key_pair_release(key_pair)

Subtracts one from an ecc key pair's ref count. If ref count reaches zero, the key pair is destroyed.

### Prototype
```c
void aws_ecc_key_pair_release(struct aws_ecc_key_pair *key_pair);
```
"""
function aws_ecc_key_pair_release(key_pair)
    ccall((:aws_ecc_key_pair_release, libaws_c_cal), Cvoid, (Ptr{aws_ecc_key_pair},), key_pair)
end

"""
    aws_ecc_key_pair_new_from_private_key(allocator, curve_name, priv_key)

Creates an Elliptic Curve private key that can be used for signing. Returns a new instance of [`aws_ecc_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL. Note: priv\\_key::len must match the appropriate length for the selected curve\\_name.

### Prototype
```c
struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key( struct aws_allocator *allocator, enum aws_ecc_curve_name curve_name, const struct aws_byte_cursor *priv_key);
```
"""
function aws_ecc_key_pair_new_from_private_key(allocator, curve_name, priv_key)
    ccall((:aws_ecc_key_pair_new_from_private_key, libaws_c_cal), Ptr{aws_ecc_key_pair}, (Ptr{aws_allocator}, aws_ecc_curve_name, Ptr{aws_byte_cursor}), allocator, curve_name, priv_key)
end

"""
    aws_ecc_key_pair_new_generate_random(allocator, curve_name)

Creates an Elliptic Curve public/private key pair that can be used for signing and verifying. Returns a new instance of [`aws_ecc_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL. Note: On Apple platforms this function is only supported on MacOS. This is due to usage of SecItemExport, which is only available on MacOS 10.7+ (yes, MacOS only and no other Apple platforms). There are alternatives for ios and other platforms, but they are ugly to use. Hence for now it only supports this call on MacOS.

### Prototype
```c
struct aws_ecc_key_pair *aws_ecc_key_pair_new_generate_random( struct aws_allocator *allocator, enum aws_ecc_curve_name curve_name);
```
"""
function aws_ecc_key_pair_new_generate_random(allocator, curve_name)
    ccall((:aws_ecc_key_pair_new_generate_random, libaws_c_cal), Ptr{aws_ecc_key_pair}, (Ptr{aws_allocator}, aws_ecc_curve_name), allocator, curve_name)
end

"""
    aws_ecc_key_pair_new_from_public_key(allocator, curve_name, public_key_x, public_key_y)

Creates an Elliptic Curve public key that can be used for verifying. Returns a new instance of [`aws_ecc_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL. Note: public\\_key\\_x::len and public\\_key\\_y::len must match the appropriate length for the selected curve\\_name.

### Prototype
```c
struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key( struct aws_allocator *allocator, enum aws_ecc_curve_name curve_name, const struct aws_byte_cursor *public_key_x, const struct aws_byte_cursor *public_key_y);
```
"""
function aws_ecc_key_pair_new_from_public_key(allocator, curve_name, public_key_x, public_key_y)
    ccall((:aws_ecc_key_pair_new_from_public_key, libaws_c_cal), Ptr{aws_ecc_key_pair}, (Ptr{aws_allocator}, aws_ecc_curve_name, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), allocator, curve_name, public_key_x, public_key_y)
end

"""
    aws_ecc_key_pair_new_from_asn1(allocator, encoded_keys)

Creates an Elliptic Curve public/private key pair from a DER encoded key pair. Returns a new instance of [`aws_ecc_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL. Whether or not signing or verification can be perform depends on if encoded\\_keys is a public/private pair or a public key.

### Prototype
```c
struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_asn1( struct aws_allocator *allocator, const struct aws_byte_cursor *encoded_keys);
```
"""
function aws_ecc_key_pair_new_from_asn1(allocator, encoded_keys)
    ccall((:aws_ecc_key_pair_new_from_asn1, libaws_c_cal), Ptr{aws_ecc_key_pair}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}), allocator, encoded_keys)
end

"""
    aws_ecc_key_new_from_hex_coordinates(allocator, curve_name, pub_x_hex_cursor, pub_y_hex_cursor)

Creates an Elliptic curve public key from x and y coordinates encoded as hex strings Returns a new instance of [`aws_ecc_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL.

### Prototype
```c
struct aws_ecc_key_pair *aws_ecc_key_new_from_hex_coordinates( struct aws_allocator *allocator, enum aws_ecc_curve_name curve_name, struct aws_byte_cursor pub_x_hex_cursor, struct aws_byte_cursor pub_y_hex_cursor);
```
"""
function aws_ecc_key_new_from_hex_coordinates(allocator, curve_name, pub_x_hex_cursor, pub_y_hex_cursor)
    ccall((:aws_ecc_key_new_from_hex_coordinates, libaws_c_cal), Ptr{aws_ecc_key_pair}, (Ptr{aws_allocator}, aws_ecc_curve_name, aws_byte_cursor, aws_byte_cursor), allocator, curve_name, pub_x_hex_cursor, pub_y_hex_cursor)
end

"""
    aws_ecc_key_pair_derive_public_key(key_pair)

Derives a public key from the private key if supported by this operating system (not supported on OSX). key\\_pair::pub\\_x and key\\_pair::pub\\_y will be set with the raw key buffers.

### Prototype
```c
int aws_ecc_key_pair_derive_public_key(struct aws_ecc_key_pair *key_pair);
```
"""
function aws_ecc_key_pair_derive_public_key(key_pair)
    ccall((:aws_ecc_key_pair_derive_public_key, libaws_c_cal), Cint, (Ptr{aws_ecc_key_pair},), key_pair)
end

"""
    aws_ecc_curve_name_from_oid(oid, curve_name)

Get the curve name from the oid. OID here is the payload of the DER encoded ASN.1 part (doesn't include type specifier or length. On success, the value of curve\\_name will be set.

### Prototype
```c
int aws_ecc_curve_name_from_oid(struct aws_byte_cursor *oid, enum aws_ecc_curve_name *curve_name);
```
"""
function aws_ecc_curve_name_from_oid(oid, curve_name)
    ccall((:aws_ecc_curve_name_from_oid, libaws_c_cal), Cint, (Ptr{aws_byte_cursor}, Ptr{aws_ecc_curve_name}), oid, curve_name)
end

"""
    aws_ecc_oid_from_curve_name(curve_name, oid)

Get the DER encoded OID from the curve\\_name. The OID in this case will not contain the type or the length specifier.

### Prototype
```c
int aws_ecc_oid_from_curve_name(enum aws_ecc_curve_name curve_name, struct aws_byte_cursor *oid);
```
"""
function aws_ecc_oid_from_curve_name(curve_name, oid)
    ccall((:aws_ecc_oid_from_curve_name, libaws_c_cal), Cint, (aws_ecc_curve_name, Ptr{aws_byte_cursor}), curve_name, oid)
end

"""
    aws_ecc_key_pair_sign_message(key_pair, message, signature)

Uses the key\\_pair's private key to sign message. The output will be in signature. Signature must be large enough to hold the signature. Check [`aws_ecc_key_pair_signature_length`](@ref)() for the appropriate size. Signature will be DER encoded.

It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually something like a SHA256.

### Prototype
```c
int aws_ecc_key_pair_sign_message( const struct aws_ecc_key_pair *key_pair, const struct aws_byte_cursor *message, struct aws_byte_buf *signature);
```
"""
function aws_ecc_key_pair_sign_message(key_pair, message, signature)
    ccall((:aws_ecc_key_pair_sign_message, libaws_c_cal), Cint, (Ptr{aws_ecc_key_pair}, Ptr{aws_byte_cursor}, Ptr{aws_byte_buf}), key_pair, message, signature)
end

"""
    aws_ecc_key_pair_verify_signature(key_pair, message, signature)

Uses the key\\_pair's public key to verify signature of message. Signature should be DER encoded.

It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually something like a SHA256.

returns AWS\\_OP\\_SUCCESS if the signature is valid.

### Prototype
```c
int aws_ecc_key_pair_verify_signature( const struct aws_ecc_key_pair *key_pair, const struct aws_byte_cursor *message, const struct aws_byte_cursor *signature);
```
"""
function aws_ecc_key_pair_verify_signature(key_pair, message, signature)
    ccall((:aws_ecc_key_pair_verify_signature, libaws_c_cal), Cint, (Ptr{aws_ecc_key_pair}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), key_pair, message, signature)
end

"""
    aws_ecc_key_pair_signature_length(key_pair)

Documentation not found.
### Prototype
```c
size_t aws_ecc_key_pair_signature_length(const struct aws_ecc_key_pair *key_pair);
```
"""
function aws_ecc_key_pair_signature_length(key_pair)
    ccall((:aws_ecc_key_pair_signature_length, libaws_c_cal), Csize_t, (Ptr{aws_ecc_key_pair},), key_pair)
end

"""
    aws_ecc_key_pair_get_public_key(key_pair, pub_x, pub_y)

Documentation not found.
### Prototype
```c
void aws_ecc_key_pair_get_public_key( const struct aws_ecc_key_pair *key_pair, struct aws_byte_cursor *pub_x, struct aws_byte_cursor *pub_y);
```
"""
function aws_ecc_key_pair_get_public_key(key_pair, pub_x, pub_y)
    ccall((:aws_ecc_key_pair_get_public_key, libaws_c_cal), Cvoid, (Ptr{aws_ecc_key_pair}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), key_pair, pub_x, pub_y)
end

"""
    aws_ecc_key_pair_get_private_key(key_pair, private_d)

Documentation not found.
### Prototype
```c
void aws_ecc_key_pair_get_private_key( const struct aws_ecc_key_pair *key_pair, struct aws_byte_cursor *private_d);
```
"""
function aws_ecc_key_pair_get_private_key(key_pair, private_d)
    ccall((:aws_ecc_key_pair_get_private_key, libaws_c_cal), Cvoid, (Ptr{aws_ecc_key_pair}, Ptr{aws_byte_cursor}), key_pair, private_d)
end

"""
    aws_ecc_key_coordinate_byte_size_from_curve_name(curve_name)

Documentation not found.
### Prototype
```c
size_t aws_ecc_key_coordinate_byte_size_from_curve_name(enum aws_ecc_curve_name curve_name);
```
"""
function aws_ecc_key_coordinate_byte_size_from_curve_name(curve_name)
    ccall((:aws_ecc_key_coordinate_byte_size_from_curve_name, libaws_c_cal), Csize_t, (aws_ecc_curve_name,), curve_name)
end

"""
Documentation not found.
"""
mutable struct aws_ed25519_key_pair end

"""
    aws_ed25519_key_pair_new_generate(allocator)

Generate new Ed25519 key. Returns a new instance of [`aws_ed25519_key_pair`](@ref) if the key was successfully generated. Otherwise returns NULL. Note: keygen is not supported on all platforms and will return NULL for the key and raise AWS\\_ERROR\\_CAL\\_UNSUPPORTED\\_ALGORITHM. Examples of unsupported cases: - openssl pre 1.1.1 (Note: aws-lc and boringssl both expose the needed functions) - win/mac builds without special flag that forces linking to libcrypto to support this

### Prototype
```c
struct aws_ed25519_key_pair *aws_ed25519_key_pair_new_generate(struct aws_allocator *allocator);
```
"""
function aws_ed25519_key_pair_new_generate(allocator)
    ccall((:aws_ed25519_key_pair_new_generate, libaws_c_cal), Ptr{aws_ed25519_key_pair}, (Ptr{aws_allocator},), allocator)
end

"""
    aws_ed25519_key_pair_acquire(key_pair)

Adds one to an Ed25519 key pair's ref count. Returns key\\_pair pointer.

### Prototype
```c
struct aws_ed25519_key_pair *aws_ed25519_key_pair_acquire(struct aws_ed25519_key_pair *key_pair);
```
"""
function aws_ed25519_key_pair_acquire(key_pair)
    ccall((:aws_ed25519_key_pair_acquire, libaws_c_cal), Ptr{aws_ed25519_key_pair}, (Ptr{aws_ed25519_key_pair},), key_pair)
end

"""
    aws_ed25519_key_pair_release(key_pair)

Subtracts one from an Ed25519 key pair's ref count. If ref count reaches zero, the key pair is destroyed. Always returns NULL.

### Prototype
```c
struct aws_ed25519_key_pair *aws_ed25519_key_pair_release(struct aws_ed25519_key_pair *key_pair);
```
"""
function aws_ed25519_key_pair_release(key_pair)
    ccall((:aws_ed25519_key_pair_release, libaws_c_cal), Ptr{aws_ed25519_key_pair}, (Ptr{aws_ed25519_key_pair},), key_pair)
end

"""
    aws_ed25519_key_export_format

Documentation not found.
"""
@cenum aws_ed25519_key_export_format::UInt32 begin
    AWS_CAL_ED25519_KEY_EXPORT_RAW = 0
    AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64 = 1
end

"""
    aws_ed25519_key_pair_get_public_key(key_pair, format, out)

Documentation not found.
### Prototype
```c
int aws_ed25519_key_pair_get_public_key( const struct aws_ed25519_key_pair *key_pair, enum aws_ed25519_key_export_format format, struct aws_byte_buf *out);
```
"""
function aws_ed25519_key_pair_get_public_key(key_pair, format, out)
    ccall((:aws_ed25519_key_pair_get_public_key, libaws_c_cal), Cint, (Ptr{aws_ed25519_key_pair}, aws_ed25519_key_export_format, Ptr{aws_byte_buf}), key_pair, format, out)
end

"""
    aws_ed25519_key_pair_get_public_key_size(format)

Gets the size of the exported public key.

### Prototype
```c
size_t aws_ed25519_key_pair_get_public_key_size(enum aws_ed25519_key_export_format format);
```
"""
function aws_ed25519_key_pair_get_public_key_size(format)
    ccall((:aws_ed25519_key_pair_get_public_key_size, libaws_c_cal), Csize_t, (aws_ed25519_key_export_format,), format)
end

"""
    aws_ed25519_key_pair_get_private_key(key_pair, format, out)

Documentation not found.
### Prototype
```c
int aws_ed25519_key_pair_get_private_key( const struct aws_ed25519_key_pair *key_pair, enum aws_ed25519_key_export_format format, struct aws_byte_buf *out);
```
"""
function aws_ed25519_key_pair_get_private_key(key_pair, format, out)
    ccall((:aws_ed25519_key_pair_get_private_key, libaws_c_cal), Cint, (Ptr{aws_ed25519_key_pair}, aws_ed25519_key_export_format, Ptr{aws_byte_buf}), key_pair, format, out)
end

"""
    aws_ed25519_key_pair_get_private_key_size(format)

Gets the size of the exported private key.

### Prototype
```c
size_t aws_ed25519_key_pair_get_private_key_size(enum aws_ed25519_key_export_format format);
```
"""
function aws_ed25519_key_pair_get_private_key_size(format)
    ccall((:aws_ed25519_key_pair_get_private_key_size, libaws_c_cal), Csize_t, (aws_ed25519_key_export_format,), format)
end

"""
    aws_hash_vtable

Documentation not found.
"""
struct aws_hash_vtable
    alg_name::Ptr{Cchar}
    provider::Ptr{Cchar}
    destroy::Ptr{Cvoid}
    update::Ptr{Cvoid}
    finalize::Ptr{Cvoid}
end

"""
    aws_hash

Documentation not found.
"""
struct aws_hash
    allocator::Ptr{aws_allocator}
    vtable::Ptr{aws_hash_vtable}
    digest_size::Csize_t
    good::Bool
    impl::Ptr{Cvoid}
end

# typedef struct aws_hash * ( aws_hash_new_fn ) ( struct aws_allocator * allocator )
"""
Documentation not found.
"""
const aws_hash_new_fn = Cvoid

"""
    aws_sha256_new(allocator)

Allocates and initializes a sha256 hash instance.

### Prototype
```c
struct aws_hash *aws_sha256_new(struct aws_allocator *allocator);
```
"""
function aws_sha256_new(allocator)
    ccall((:aws_sha256_new, libaws_c_cal), Ptr{aws_hash}, (Ptr{aws_allocator},), allocator)
end

"""
    aws_sha1_new(allocator)

Allocates and initializes a sha1 hash instance.

### Prototype
```c
struct aws_hash *aws_sha1_new(struct aws_allocator *allocator);
```
"""
function aws_sha1_new(allocator)
    ccall((:aws_sha1_new, libaws_c_cal), Ptr{aws_hash}, (Ptr{aws_allocator},), allocator)
end

"""
    aws_md5_new(allocator)

Allocates and initializes an md5 hash instance.

### Prototype
```c
struct aws_hash *aws_md5_new(struct aws_allocator *allocator);
```
"""
function aws_md5_new(allocator)
    ccall((:aws_md5_new, libaws_c_cal), Ptr{aws_hash}, (Ptr{aws_allocator},), allocator)
end

"""
    aws_hash_destroy(hash)

Cleans up and deallocates hash.

### Prototype
```c
void aws_hash_destroy(struct aws_hash *hash);
```
"""
function aws_hash_destroy(hash)
    ccall((:aws_hash_destroy, libaws_c_cal), Cvoid, (Ptr{aws_hash},), hash)
end

"""
    aws_hash_update(hash, to_hash)

Updates the running hash with to\\_hash. this can be called multiple times.

### Prototype
```c
int aws_hash_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
```
"""
function aws_hash_update(hash, to_hash)
    ccall((:aws_hash_update, libaws_c_cal), Cint, (Ptr{aws_hash}, Ptr{aws_byte_cursor}), hash, to_hash)
end

"""
    aws_hash_finalize(hash, output, truncate_to)

Completes the hash computation and writes the final digest to output. Allocation of output is the caller's responsibility. If you specify truncate\\_to to something other than 0, the output will be truncated to that number of bytes. For example, if you want a SHA256 digest as the first 16 bytes, set truncate\\_to to 16. If you want the full digest size, just set this to 0.

### Prototype
```c
int aws_hash_finalize(struct aws_hash *hash, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_hash_finalize(hash, output, truncate_to)
    ccall((:aws_hash_finalize, libaws_c_cal), Cint, (Ptr{aws_hash}, Ptr{aws_byte_buf}, Csize_t), hash, output, truncate_to)
end

"""
    aws_md5_compute(allocator, input, output, truncate_to)

Computes the md5 hash over input and writes the digest output to 'output'. Use this if you don't need to stream the data you're hashing and you can load the entire input to hash into memory.

### Prototype
```c
int aws_md5_compute( struct aws_allocator *allocator, const struct aws_byte_cursor *input, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_md5_compute(allocator, input, output, truncate_to)
    ccall((:aws_md5_compute, libaws_c_cal), Cint, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_buf}, Csize_t), allocator, input, output, truncate_to)
end

"""
    aws_sha256_compute(allocator, input, output, truncate_to)

Computes the sha256 hash over input and writes the digest output to 'output'. Use this if you don't need to stream the data you're hashing and you can load the entire input to hash into memory. If you specify truncate\\_to to something other than 0, the output will be truncated to that number of bytes. For example, if you want a SHA256 digest as the first 16 bytes, set truncate\\_to to 16. If you want the full digest size, just set this to 0.

### Prototype
```c
int aws_sha256_compute( struct aws_allocator *allocator, const struct aws_byte_cursor *input, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_sha256_compute(allocator, input, output, truncate_to)
    ccall((:aws_sha256_compute, libaws_c_cal), Cint, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_buf}, Csize_t), allocator, input, output, truncate_to)
end

"""
    aws_sha1_compute(allocator, input, output, truncate_to)

Computes the sha1 hash over input and writes the digest output to 'output'. Use this if you don't need to stream the data you're hashing and you can load the entire input to hash into memory. If you specify truncate\\_to to something other than 0, the output will be truncated to that number of bytes. For example, if you want a SHA1 digest as the first 16 bytes, set truncate\\_to to 16. If you want the full digest size, just set this to 0.

### Prototype
```c
int aws_sha1_compute( struct aws_allocator *allocator, const struct aws_byte_cursor *input, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_sha1_compute(allocator, input, output, truncate_to)
    ccall((:aws_sha1_compute, libaws_c_cal), Cint, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_buf}, Csize_t), allocator, input, output, truncate_to)
end

"""
    aws_set_md5_new_fn(fn)

Set the implementation of md5 to use. If you compiled without BYO\\_CRYPTO, you do not need to call this. However, if use this, we will honor it, regardless of compile options. This may be useful for testing purposes. If you did set BYO\\_CRYPTO, and you do not call this function you will segfault.

### Prototype
```c
void aws_set_md5_new_fn(aws_hash_new_fn *fn);
```
"""
function aws_set_md5_new_fn(fn)
    ccall((:aws_set_md5_new_fn, libaws_c_cal), Cvoid, (Ptr{aws_hash_new_fn},), fn)
end

"""
    aws_set_sha256_new_fn(fn)

Set the implementation of sha256 to use. If you compiled without BYO\\_CRYPTO, you do not need to call this. However, if use this, we will honor it, regardless of compile options. This may be useful for testing purposes. If you did set BYO\\_CRYPTO, and you do not call this function you will segfault.

### Prototype
```c
void aws_set_sha256_new_fn(aws_hash_new_fn *fn);
```
"""
function aws_set_sha256_new_fn(fn)
    ccall((:aws_set_sha256_new_fn, libaws_c_cal), Cvoid, (Ptr{aws_hash_new_fn},), fn)
end

"""
    aws_set_sha1_new_fn(fn)

Set the implementation of sha1 to use. If you compiled without BYO\\_CRYPTO, you do not need to call this. However, if use this, we will honor it, regardless of compile options. This may be useful for testing purposes. If you did set BYO\\_CRYPTO, and you do not call this function you will segfault.

### Prototype
```c
void aws_set_sha1_new_fn(aws_hash_new_fn *fn);
```
"""
function aws_set_sha1_new_fn(fn)
    ccall((:aws_set_sha1_new_fn, libaws_c_cal), Cvoid, (Ptr{aws_hash_new_fn},), fn)
end

"""
    aws_hmac_vtable

Documentation not found.
"""
struct aws_hmac_vtable
    alg_name::Ptr{Cchar}
    provider::Ptr{Cchar}
    destroy::Ptr{Cvoid}
    update::Ptr{Cvoid}
    finalize::Ptr{Cvoid}
end

"""
    aws_hmac

Documentation not found.
"""
struct aws_hmac
    allocator::Ptr{aws_allocator}
    vtable::Ptr{aws_hmac_vtable}
    digest_size::Csize_t
    good::Bool
    impl::Ptr{Cvoid}
end

# typedef struct aws_hmac * ( aws_hmac_new_fn ) ( struct aws_allocator * allocator , const struct aws_byte_cursor * secret )
"""
Documentation not found.
"""
const aws_hmac_new_fn = Cvoid

"""
    aws_sha256_hmac_new(allocator, secret)

Allocates and initializes a sha256 hmac instance. Secret is the key to be used for the hmac process.

### Prototype
```c
struct aws_hmac *aws_sha256_hmac_new(struct aws_allocator *allocator, const struct aws_byte_cursor *secret);
```
"""
function aws_sha256_hmac_new(allocator, secret)
    ccall((:aws_sha256_hmac_new, libaws_c_cal), Ptr{aws_hmac}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}), allocator, secret)
end

"""
    aws_hmac_destroy(hmac)

Cleans up and deallocates hmac.

### Prototype
```c
void aws_hmac_destroy(struct aws_hmac *hmac);
```
"""
function aws_hmac_destroy(hmac)
    ccall((:aws_hmac_destroy, libaws_c_cal), Cvoid, (Ptr{aws_hmac},), hmac)
end

"""
    aws_hmac_update(hmac, to_hmac)

Updates the running hmac with to\\_hash. this can be called multiple times.

### Prototype
```c
int aws_hmac_update(struct aws_hmac *hmac, const struct aws_byte_cursor *to_hmac);
```
"""
function aws_hmac_update(hmac, to_hmac)
    ccall((:aws_hmac_update, libaws_c_cal), Cint, (Ptr{aws_hmac}, Ptr{aws_byte_cursor}), hmac, to_hmac)
end

"""
    aws_hmac_finalize(hmac, output, truncate_to)

Completes the hmac computation and writes the final digest to output. Allocation of output is the caller's responsibility. If you specify truncate\\_to to something other than 0, the output will be truncated to that number of bytes. For example if you want a SHA256 digest as the first 16 bytes, set truncate\\_to to 16. If you want the full digest size, just set this to 0.

### Prototype
```c
int aws_hmac_finalize(struct aws_hmac *hmac, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_hmac_finalize(hmac, output, truncate_to)
    ccall((:aws_hmac_finalize, libaws_c_cal), Cint, (Ptr{aws_hmac}, Ptr{aws_byte_buf}, Csize_t), hmac, output, truncate_to)
end

"""
    aws_sha256_hmac_compute(allocator, secret, to_hmac, output, truncate_to)

Computes the sha256 hmac over input and writes the digest output to 'output'. Use this if you don't need to stream the data you're hashing and you can load the entire input to hash into memory. If you specify truncate\\_to to something other than 0, the output will be truncated to that number of bytes. For example if you want a SHA256 HMAC digest as the first 16 bytes, set truncate\\_to to 16. If you want the full digest size, just set this to 0.

### Prototype
```c
int aws_sha256_hmac_compute( struct aws_allocator *allocator, const struct aws_byte_cursor *secret, const struct aws_byte_cursor *to_hmac, struct aws_byte_buf *output, size_t truncate_to);
```
"""
function aws_sha256_hmac_compute(allocator, secret, to_hmac, output, truncate_to)
    ccall((:aws_sha256_hmac_compute, libaws_c_cal), Cint, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}, Ptr{aws_byte_buf}, Csize_t), allocator, secret, to_hmac, output, truncate_to)
end

"""
    aws_set_sha256_hmac_new_fn(fn)

Set the implementation of sha256 hmac to use. If you compiled without BYO\\_CRYPTO, you do not need to call this. However, if use this, we will honor it, regardless of compile options. This may be useful for testing purposes. If you did set BYO\\_CRYPTO, and you do not call this function you will segfault.

### Prototype
```c
void aws_set_sha256_hmac_new_fn(aws_hmac_new_fn *fn);
```
"""
function aws_set_sha256_hmac_new_fn(fn)
    ccall((:aws_set_sha256_hmac_new_fn, libaws_c_cal), Cvoid, (Ptr{aws_hmac_new_fn},), fn)
end

"""
Documentation not found.
"""
mutable struct aws_rsa_key_pair end

"""
    aws_rsa_encryption_algorithm

Documentation not found.
"""
@cenum aws_rsa_encryption_algorithm::UInt32 begin
    AWS_CAL_RSA_ENCRYPTION_PKCS1_5 = 0
    AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 = 1
    AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512 = 2
end

"""
    aws_rsa_signature_algorithm

Documentation not found.
"""
@cenum aws_rsa_signature_algorithm::UInt32 begin
    AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256 = 0
    AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA1 = 1
    AWS_CAL_RSA_SIGNATURE_PSS_SHA256 = 2
end

"""
    __JL_Ctag_19

Documentation not found.
"""
@cenum __JL_Ctag_19::UInt32 begin
    AWS_CAL_RSA_MIN_SUPPORTED_KEY_SIZE_IN_BITS = 1024
    AWS_CAL_RSA_MAX_SUPPORTED_KEY_SIZE_IN_BITS = 4096
end

"""
    aws_rsa_key_pair_new_from_public_key_pkcs1(allocator, key)

Creates an RSA public key from RSAPublicKey as defined in rfc 8017 (aka PKCS1). Returns a new instance of [`aws_rsa_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL.

### Prototype
```c
struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1( struct aws_allocator *allocator, struct aws_byte_cursor key);
```
"""
function aws_rsa_key_pair_new_from_public_key_pkcs1(allocator, key)
    ccall((:aws_rsa_key_pair_new_from_public_key_pkcs1, libaws_c_cal), Ptr{aws_rsa_key_pair}, (Ptr{aws_allocator}, aws_byte_cursor), allocator, key)
end

"""
    aws_rsa_key_pair_new_from_private_key_pkcs1(allocator, key)

Creates an RSA private key from RSAPrivateKey as defined in rfc 8017 (aka PKCS1). Returns a new instance of [`aws_rsa_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL.

### Prototype
```c
struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs1( struct aws_allocator *allocator, struct aws_byte_cursor key);
```
"""
function aws_rsa_key_pair_new_from_private_key_pkcs1(allocator, key)
    ccall((:aws_rsa_key_pair_new_from_private_key_pkcs1, libaws_c_cal), Ptr{aws_rsa_key_pair}, (Ptr{aws_allocator}, aws_byte_cursor), allocator, key)
end

"""
    aws_rsa_key_pair_new_from_private_key_pkcs8(allocator, key)

Creates an RSA private key from PrivateKeyInfo as defined in rfc 5208 (aka PKCS8). Returns a new instance of [`aws_rsa_key_pair`](@ref) if the key was successfully built. Otherwise returns NULL.

### Prototype
```c
struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs8( struct aws_allocator *allocator, struct aws_byte_cursor key);
```
"""
function aws_rsa_key_pair_new_from_private_key_pkcs8(allocator, key)
    ccall((:aws_rsa_key_pair_new_from_private_key_pkcs8, libaws_c_cal), Ptr{aws_rsa_key_pair}, (Ptr{aws_allocator}, aws_byte_cursor), allocator, key)
end

"""
    aws_rsa_key_pair_acquire(key_pair)

Adds one to an RSA key pair's ref count. Returns key\\_pair pointer.

### Prototype
```c
struct aws_rsa_key_pair *aws_rsa_key_pair_acquire(struct aws_rsa_key_pair *key_pair);
```
"""
function aws_rsa_key_pair_acquire(key_pair)
    ccall((:aws_rsa_key_pair_acquire, libaws_c_cal), Ptr{aws_rsa_key_pair}, (Ptr{aws_rsa_key_pair},), key_pair)
end

"""
    aws_rsa_key_pair_release(key_pair)

Subtracts one from an RSA key pair's ref count. If ref count reaches zero, the key pair is destroyed. Always returns NULL.

### Prototype
```c
struct aws_rsa_key_pair *aws_rsa_key_pair_release(struct aws_rsa_key_pair *key_pair);
```
"""
function aws_rsa_key_pair_release(key_pair)
    ccall((:aws_rsa_key_pair_release, libaws_c_cal), Ptr{aws_rsa_key_pair}, (Ptr{aws_rsa_key_pair},), key_pair)
end

"""
    aws_rsa_key_pair_max_encrypt_plaintext_size(key_pair, algorithm)

Max plaintext size that can be encrypted by the key (i.e. max data size supported by the key - bytes needed for padding).

### Prototype
```c
size_t aws_rsa_key_pair_max_encrypt_plaintext_size( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_encryption_algorithm algorithm);
```
"""
function aws_rsa_key_pair_max_encrypt_plaintext_size(key_pair, algorithm)
    ccall((:aws_rsa_key_pair_max_encrypt_plaintext_size, libaws_c_cal), Csize_t, (Ptr{aws_rsa_key_pair}, aws_rsa_encryption_algorithm), key_pair, algorithm)
end

"""
    aws_rsa_key_pair_encrypt(key_pair, algorithm, plaintext, out)

Documentation not found.
### Prototype
```c
int aws_rsa_key_pair_encrypt( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_encryption_algorithm algorithm, struct aws_byte_cursor plaintext, struct aws_byte_buf *out);
```
"""
function aws_rsa_key_pair_encrypt(key_pair, algorithm, plaintext, out)
    ccall((:aws_rsa_key_pair_encrypt, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_encryption_algorithm, aws_byte_cursor, Ptr{aws_byte_buf}), key_pair, algorithm, plaintext, out)
end

"""
    aws_rsa_key_pair_decrypt(key_pair, algorithm, ciphertext, out)

Documentation not found.
### Prototype
```c
int aws_rsa_key_pair_decrypt( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_encryption_algorithm algorithm, struct aws_byte_cursor ciphertext, struct aws_byte_buf *out);
```
"""
function aws_rsa_key_pair_decrypt(key_pair, algorithm, ciphertext, out)
    ccall((:aws_rsa_key_pair_decrypt, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_encryption_algorithm, aws_byte_cursor, Ptr{aws_byte_buf}), key_pair, algorithm, ciphertext, out)
end

"""
    aws_rsa_key_pair_block_length(key_pair)

Documentation not found.
### Prototype
```c
size_t aws_rsa_key_pair_block_length(const struct aws_rsa_key_pair *key_pair);
```
"""
function aws_rsa_key_pair_block_length(key_pair)
    ccall((:aws_rsa_key_pair_block_length, libaws_c_cal), Csize_t, (Ptr{aws_rsa_key_pair},), key_pair)
end

"""
    aws_rsa_key_pair_sign_message(key_pair, algorithm, digest, out)

Uses the key\\_pair's private key to sign message. The output will be in out. out must be large enough to hold the signature. Check [`aws_rsa_key_pair_signature_length`](@ref)() for the appropriate size.

It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually something like a SHA256.

### Prototype
```c
int aws_rsa_key_pair_sign_message( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_signature_algorithm algorithm, struct aws_byte_cursor digest, struct aws_byte_buf *out);
```
"""
function aws_rsa_key_pair_sign_message(key_pair, algorithm, digest, out)
    ccall((:aws_rsa_key_pair_sign_message, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_signature_algorithm, aws_byte_cursor, Ptr{aws_byte_buf}), key_pair, algorithm, digest, out)
end

"""
    aws_rsa_key_pair_verify_signature(key_pair, algorithm, digest, signature)

Uses the key\\_pair's public key to verify signature of message.

It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually something like a SHA256.

returns AWS\\_OP\\_SUCCESS if the signature is valid. raises AWS\\_ERROR\\_CAL\\_SIGNATURE\\_VALIDATION\\_FAILED if signature validation failed

### Prototype
```c
int aws_rsa_key_pair_verify_signature( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_signature_algorithm algorithm, struct aws_byte_cursor digest, struct aws_byte_cursor signature);
```
"""
function aws_rsa_key_pair_verify_signature(key_pair, algorithm, digest, signature)
    ccall((:aws_rsa_key_pair_verify_signature, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_signature_algorithm, aws_byte_cursor, aws_byte_cursor), key_pair, algorithm, digest, signature)
end

"""
    aws_rsa_key_pair_signature_length(key_pair)

Documentation not found.
### Prototype
```c
size_t aws_rsa_key_pair_signature_length(const struct aws_rsa_key_pair *key_pair);
```
"""
function aws_rsa_key_pair_signature_length(key_pair)
    ccall((:aws_rsa_key_pair_signature_length, libaws_c_cal), Csize_t, (Ptr{aws_rsa_key_pair},), key_pair)
end

"""
    aws_rsa_key_export_format

Documentation not found.
"""
@cenum aws_rsa_key_export_format::UInt32 begin
    AWS_CAL_RSA_KEY_EXPORT_PKCS1 = 0
end

"""
    aws_rsa_key_pair_get_public_key(key_pair, format, out)

Documentation not found.
### Prototype
```c
int aws_rsa_key_pair_get_public_key( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_key_export_format format, struct aws_byte_buf *out);
```
"""
function aws_rsa_key_pair_get_public_key(key_pair, format, out)
    ccall((:aws_rsa_key_pair_get_public_key, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_key_export_format, Ptr{aws_byte_buf}), key_pair, format, out)
end

"""
    aws_rsa_key_pair_get_private_key(key_pair, format, out)

Documentation not found.
### Prototype
```c
int aws_rsa_key_pair_get_private_key( const struct aws_rsa_key_pair *key_pair, enum aws_rsa_key_export_format format, struct aws_byte_buf *out);
```
"""
function aws_rsa_key_pair_get_private_key(key_pair, format, out)
    ccall((:aws_rsa_key_pair_get_private_key, libaws_c_cal), Cint, (Ptr{aws_rsa_key_pair}, aws_rsa_key_export_format, Ptr{aws_byte_buf}), key_pair, format, out)
end

"""
Documentation not found.
"""
mutable struct aws_symmetric_cipher end

# typedef struct aws_symmetric_cipher * ( aws_aes_cbc_256_new_fn ) ( struct aws_allocator * allocator , const struct aws_byte_cursor * key , const struct aws_byte_cursor * iv )
"""
Documentation not found.
"""
const aws_aes_cbc_256_new_fn = Cvoid

# typedef struct aws_symmetric_cipher * ( aws_aes_ctr_256_new_fn ) ( struct aws_allocator * allocator , const struct aws_byte_cursor * key , const struct aws_byte_cursor * iv )
"""
Documentation not found.
"""
const aws_aes_ctr_256_new_fn = Cvoid

# typedef struct aws_symmetric_cipher * ( aws_aes_gcm_256_new_fn ) ( struct aws_allocator * allocator , const struct aws_byte_cursor * key , const struct aws_byte_cursor * iv , const struct aws_byte_cursor * aad )
"""
Documentation not found.
"""
const aws_aes_gcm_256_new_fn = Cvoid

# typedef struct aws_symmetric_cipher * ( aws_aes_keywrap_256_new_fn ) ( struct aws_allocator * allocator , const struct aws_byte_cursor * key )
"""
Documentation not found.
"""
const aws_aes_keywrap_256_new_fn = Cvoid

"""
    aws_symmetric_cipher_state

Documentation not found.
"""
@cenum aws_symmetric_cipher_state::UInt32 begin
    AWS_SYMMETRIC_CIPHER_READY = 0
    AWS_SYMMETRIC_CIPHER_FINALIZED = 1
    AWS_SYMMETRIC_CIPHER_ERROR = 2
end

"""
    aws_aes_cbc_256_new(allocator, key, iv)

Creates an instance of AES CBC with 256-bit key. If key and iv are NULL, they will be generated internally. You can get the generated key and iv back by calling:

[`aws_symmetric_cipher_get_key`](@ref)() and [`aws_symmetric_cipher_get_initialization_vector`](@ref)()

respectively.

If they are set, that key and iv will be copied internally and used by the cipher.

Returns NULL on failure. You can check aws\\_last\\_error() to get the error code indicating the failure cause.

### Prototype
```c
struct aws_symmetric_cipher *aws_aes_cbc_256_new( struct aws_allocator *allocator, const struct aws_byte_cursor *key, const struct aws_byte_cursor *iv);
```
"""
function aws_aes_cbc_256_new(allocator, key, iv)
    ccall((:aws_aes_cbc_256_new, libaws_c_cal), Ptr{aws_symmetric_cipher}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), allocator, key, iv)
end

"""
    aws_aes_ctr_256_new(allocator, key, iv)

Creates an instance of AES CTR with 256-bit key. If key and iv are NULL, they will be generated internally. You can get the generated key and iv back by calling:

[`aws_symmetric_cipher_get_key`](@ref)() and [`aws_symmetric_cipher_get_initialization_vector`](@ref)()

respectively.

If they are set, that key and iv will be copied internally and used by the cipher.

Returns NULL on failure. You can check aws\\_last\\_error() to get the error code indicating the failure cause.

### Prototype
```c
struct aws_symmetric_cipher *aws_aes_ctr_256_new( struct aws_allocator *allocator, const struct aws_byte_cursor *key, const struct aws_byte_cursor *iv);
```
"""
function aws_aes_ctr_256_new(allocator, key, iv)
    ccall((:aws_aes_ctr_256_new, libaws_c_cal), Ptr{aws_symmetric_cipher}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), allocator, key, iv)
end

"""
    aws_aes_gcm_256_new(allocator, key, iv, aad)

Creates an instance of AES GCM with 256-bit key. If key, iv are NULL, they will be generated internally. You can get the generated key and iv back by calling:

[`aws_symmetric_cipher_get_key`](@ref)() and [`aws_symmetric_cipher_get_initialization_vector`](@ref)()

respectively.

If aad is set it will be copied and applied to the cipher.

If they are set, that key and iv will be copied internally and used by the cipher.

For decryption purposes tag can be provided via [`aws_symmetric_cipher_set_tag`](@ref) method. Note: for decrypt operations, tag must be provided before first decrypt is called. (this is a windows bcrypt limitations, but for consistency sake same limitation is extended to other platforms) Tag generated during encryption can be retrieved using [`aws_symmetric_cipher_get_tag`](@ref) method after finalize is called.

Returns NULL on failure. You can check aws\\_last\\_error() to get the error code indicating the failure cause.

### Prototype
```c
struct aws_symmetric_cipher *aws_aes_gcm_256_new( struct aws_allocator *allocator, const struct aws_byte_cursor *key, const struct aws_byte_cursor *iv, const struct aws_byte_cursor *aad);
```
"""
function aws_aes_gcm_256_new(allocator, key, iv, aad)
    ccall((:aws_aes_gcm_256_new, libaws_c_cal), Ptr{aws_symmetric_cipher}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}, Ptr{aws_byte_cursor}), allocator, key, iv, aad)
end

"""
    aws_aes_keywrap_256_new(allocator, key)

Creates an instance of AES Keywrap with 256-bit key. If key is NULL, it will be generated internally. You can get the generated key back by calling:

[`aws_symmetric_cipher_get_key`](@ref)()

If key is set, that key will be copied internally and used by the cipher.

Returns NULL on failure. You can check aws\\_last\\_error() to get the error code indicating the failure cause.

### Prototype
```c
struct aws_symmetric_cipher *aws_aes_keywrap_256_new( struct aws_allocator *allocator, const struct aws_byte_cursor *key);
```
"""
function aws_aes_keywrap_256_new(allocator, key)
    ccall((:aws_aes_keywrap_256_new, libaws_c_cal), Ptr{aws_symmetric_cipher}, (Ptr{aws_allocator}, Ptr{aws_byte_cursor}), allocator, key)
end

"""
    aws_symmetric_cipher_destroy(cipher)

Cleans up internal resources and state for cipher and then deallocates it.

### Prototype
```c
void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_destroy(cipher)
    ccall((:aws_symmetric_cipher_destroy, libaws_c_cal), Cvoid, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_encrypt(cipher, to_encrypt, out)

Encrypts the value in to\\_encrypt and writes the encrypted data into out. If out is dynamic it will be expanded. If it is not, and out is not large enough to handle the encrypted output, the call will fail. If you're trying to optimize to use a stack based array or something, make sure it's at least as large as the size of to\\_encrypt + an extra BLOCK to account for padding etc...

returns AWS\\_OP\\_SUCCESS on success. Call aws\\_last\\_error() to determine the failure cause if it returns AWS\\_OP\\_ERR;

### Prototype
```c
int aws_symmetric_cipher_encrypt( struct aws_symmetric_cipher *cipher, struct aws_byte_cursor to_encrypt, struct aws_byte_buf *out);
```
"""
function aws_symmetric_cipher_encrypt(cipher, to_encrypt, out)
    ccall((:aws_symmetric_cipher_encrypt, libaws_c_cal), Cint, (Ptr{aws_symmetric_cipher}, aws_byte_cursor, Ptr{aws_byte_buf}), cipher, to_encrypt, out)
end

"""
    aws_symmetric_cipher_decrypt(cipher, to_decrypt, out)

Decrypts the value in to\\_decrypt and writes the decrypted data into out. If out is dynamic it will be expanded. If it is not, and out is not large enough to handle the decrypted output, the call will fail. If you're trying to optimize to use a stack based array or something, make sure it's at least as large as the size of to\\_decrypt + an extra BLOCK to account for padding etc...

returns AWS\\_OP\\_SUCCESS on success. Call aws\\_last\\_error() to determine the failure cause if it returns AWS\\_OP\\_ERR;

### Prototype
```c
int aws_symmetric_cipher_decrypt( struct aws_symmetric_cipher *cipher, struct aws_byte_cursor to_decrypt, struct aws_byte_buf *out);
```
"""
function aws_symmetric_cipher_decrypt(cipher, to_decrypt, out)
    ccall((:aws_symmetric_cipher_decrypt, libaws_c_cal), Cint, (Ptr{aws_symmetric_cipher}, aws_byte_cursor, Ptr{aws_byte_buf}), cipher, to_decrypt, out)
end

"""
    aws_symmetric_cipher_finalize_encryption(cipher, out)

Encrypts any remaining data that was reserved for final padding, loads GMACs etc... and if there is any writes any remaining encrypted data to out. If out is dynamic it will be expanded. If it is not, and out is not large enough to handle the decrypted output, the call will fail. If you're trying to optimize to use a stack based array or something, make sure it's at least as large as the size of 2 BLOCKs to account for padding etc...

After invoking this function, you MUST call [`aws_symmetric_cipher_reset`](@ref)() before invoking any encrypt/decrypt operations on this cipher again.

returns AWS\\_OP\\_SUCCESS on success. Call aws\\_last\\_error() to determine the failure cause if it returns AWS\\_OP\\_ERR;

### Prototype
```c
int aws_symmetric_cipher_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
```
"""
function aws_symmetric_cipher_finalize_encryption(cipher, out)
    ccall((:aws_symmetric_cipher_finalize_encryption, libaws_c_cal), Cint, (Ptr{aws_symmetric_cipher}, Ptr{aws_byte_buf}), cipher, out)
end

"""
    aws_symmetric_cipher_finalize_decryption(cipher, out)

Decrypts any remaining data that was reserved for final padding, loads GMACs etc... and if there is any writes any remaining decrypted data to out. If out is dynamic it will be expanded. If it is not, and out is not large enough to handle the decrypted output, the call will fail. If you're trying to optimize to use a stack based array or something, make sure it's at least as large as the size of 2 BLOCKs to account for padding etc...

After invoking this function, you MUST call [`aws_symmetric_cipher_reset`](@ref)() before invoking any encrypt/decrypt operations on this cipher again.

returns AWS\\_OP\\_SUCCESS on success. Call aws\\_last\\_error() to determine the failure cause if it returns AWS\\_OP\\_ERR;

### Prototype
```c
int aws_symmetric_cipher_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
```
"""
function aws_symmetric_cipher_finalize_decryption(cipher, out)
    ccall((:aws_symmetric_cipher_finalize_decryption, libaws_c_cal), Cint, (Ptr{aws_symmetric_cipher}, Ptr{aws_byte_buf}), cipher, out)
end

"""
    aws_symmetric_cipher_reset(cipher)

Resets the cipher state for starting a new encrypt or decrypt operation. Note encrypt/decrypt cannot be mixed on the same cipher without a call to reset in between them. However, this leaves the key, iv etc... materials setup for immediate reuse. Note: GCM tag is not preserved between operations. If you intend to do encrypt followed directly by decrypt, make sure to make a copy of tag before reseting the cipher and pass that copy for decryption.

Warning: In most cases it's a really bad idea to reset a cipher and perform another operation using that cipher. Key and IV should not be reused for different operations. Instead of reseting the cipher, destroy the cipher and create new one with a new key/iv pair. Use reset at your own risk, and only after careful consideration.

returns AWS\\_OP\\_SUCCESS on success. Call aws\\_last\\_error() to determine the failure cause if it returns AWS\\_OP\\_ERR;

### Prototype
```c
int aws_symmetric_cipher_reset(struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_reset(cipher)
    ccall((:aws_symmetric_cipher_reset, libaws_c_cal), Cint, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_get_tag(cipher)

Gets the current GMAC tag. If not AES GCM, this function will just return an empty cursor. The memory in this cursor is unsafe as it refers to the internal buffer. This was done because the use case doesn't require fetching these during an encryption or decryption operation and it dramatically simplifies the API. Only use this function between other calls to this API as any function call can alter the value of this tag.

If you need to access it in a different pattern, copy the values to your own buffer first.

### Prototype
```c
struct aws_byte_cursor aws_symmetric_cipher_get_tag(const struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_get_tag(cipher)
    ccall((:aws_symmetric_cipher_get_tag, libaws_c_cal), aws_byte_cursor, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_set_tag(cipher, tag)

Sets the GMAC tag on the cipher. Does nothing for ciphers that do not support tag.

### Prototype
```c
void aws_symmetric_cipher_set_tag(struct aws_symmetric_cipher *cipher, struct aws_byte_cursor tag);
```
"""
function aws_symmetric_cipher_set_tag(cipher, tag)
    ccall((:aws_symmetric_cipher_set_tag, libaws_c_cal), Cvoid, (Ptr{aws_symmetric_cipher}, aws_byte_cursor), cipher, tag)
end

"""
    aws_symmetric_cipher_get_initialization_vector(cipher)

Gets the original initialization vector as a cursor. The memory in this cursor is unsafe as it refers to the internal buffer. This was done because the use case doesn't require fetching these during an encryption or decryption operation and it dramatically simplifies the API.

Unlike some other fields, this value does not change after the inital construction of the cipher.

For some algorithms, such as AES Keywrap, this will return an empty cursor.

### Prototype
```c
struct aws_byte_cursor aws_symmetric_cipher_get_initialization_vector( const struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_get_initialization_vector(cipher)
    ccall((:aws_symmetric_cipher_get_initialization_vector, libaws_c_cal), aws_byte_cursor, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_get_key(cipher)

Gets the original key.

The memory in this cursor is unsafe as it refers to the internal buffer. This was done because the use case doesn't require fetching these during an encryption or decryption operation and it dramatically simplifies the API.

Unlike some other fields, this value does not change after the inital construction of the cipher.

### Prototype
```c
struct aws_byte_cursor aws_symmetric_cipher_get_key(const struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_get_key(cipher)
    ccall((:aws_symmetric_cipher_get_key, libaws_c_cal), aws_byte_cursor, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_is_good(cipher)

Returns true if the state of the cipher is good, and otherwise returns false. Most operations, other than [`aws_symmetric_cipher_reset`](@ref)() will fail if this function is returning false. [`aws_symmetric_cipher_reset`](@ref)() will reset the state to a good state if possible.

### Prototype
```c
bool aws_symmetric_cipher_is_good(const struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_is_good(cipher)
    ccall((:aws_symmetric_cipher_is_good, libaws_c_cal), Bool, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
    aws_symmetric_cipher_get_state(cipher)

Retuns the current state of the cipher. Ther state of the cipher can be ready for use, finalized, or has encountered an error. if the cipher is in a finished or error state, it must be reset before further use.

### Prototype
```c
enum aws_symmetric_cipher_state aws_symmetric_cipher_get_state(const struct aws_symmetric_cipher *cipher);
```
"""
function aws_symmetric_cipher_get_state(cipher)
    ccall((:aws_symmetric_cipher_get_state, libaws_c_cal), aws_symmetric_cipher_state, (Ptr{aws_symmetric_cipher},), cipher)
end

"""
Documentation not found.
"""
const AWS_C_CAL_PACKAGE_ID = 7

"""
Documentation not found.
"""
const AWS_SHA256_LEN = 32

"""
Documentation not found.
"""
const AWS_SHA1_LEN = 20

"""
Documentation not found.
"""
const AWS_MD5_LEN = 16

"""
Documentation not found.
"""
const AWS_SHA256_HMAC_LEN = 32

"""
Documentation not found.
"""
const AWS_AES_256_CIPHER_BLOCK_SIZE = 16

"""
Documentation not found.
"""
const AWS_AES_256_KEY_BIT_LEN = 256

"""
Documentation not found.
"""
const AWS_AES_256_KEY_BYTE_LEN = AWS_AES_256_KEY_BIT_LEN ÷ 8
