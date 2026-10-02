__precompile__()

module OAuth

using HTTP, Nettle

export
oauth_timestamp,
oauth_nonce,
oauth_sign_hmac_sha1,
oauth_signing_key,
oauth_signature_base_string,
oauth_percent_encode_keys!,
oauth_serialize_url_parameters,
encodeURI!,
oauth_body_hash_file,
oauth_body_hash_data,
oauth_body_hash_encode,
oauth_header,
oauth_request_resource

"""
    oauth_timestamp()

Returns current unix timestamp as String.

# Examples
```julia-repl
julia> oauth_timestamp()
"1512235859"
```
"""
function oauth_timestamp()
    "$(round(Int, time()))"
end

"""
    oauth_nonce(length::Int)

Returns a random string of a given length.

# Examples
```julia-repl
julia> oauth_nonce(10)
"aQb2FVkrYi"
```
"""
function oauth_nonce(length::Int)
    randstring(length)
end

"""
    oauth_sign_hmac_sha1(message::String, signingkey::String)

Takes a message and signing key, converts to a SHA-1 digest, then encodes to base64.

# Examples
```jldoctest
julia> oauth_sign_hmac_sha1("foo", "bar")
"hdFVxV7ShqMAvRzxJN4I2H6RTzo="
```
"""
function oauth_sign_hmac_sha1(message::String, signingkey::String)
    base64encode(digest("sha1", signingkey, message))
end

"""
    oauth_signing_key(oauth_consumer_secret::String, oauth_token_secret::String)

Returns a signing key based on a consumer secret and token secret.

# Examples
```jldoctest
julia> oauth_signing_key("foo", "bar")
"foo&bar"
```
"""
function oauth_signing_key(oauth_consumer_secret::String, oauth_token_secret::String)
    "$(oauth_consumer_secret)&$(oauth_token_secret)"
end

"""
    oauth_signature_base_string(httpmethod::String, url::String, parameterstring::String)

Returns encoded HTTP method, url and parameters.

# Examples
```jldoctest
julia> oauth_signature_base_string("POST", "https://julialang.org", "foo&bar")
"POST&https%3A%2F%2Fjulialang.org&foo%26bar"
```
"""
function oauth_signature_base_string(httpmethod::String, url::String, parameterstring::String)
    "$(httpmethod)&$(encodeURI(url))&$(encodeURI(parameterstring))"
end

"""
    oauth_percent_encode_keys!(options::Dict)

Returns dict where keys and values are URL-encoded.

# Examples
```jldoctest
julia> oauth_percent_encode_keys!(Dict("key 1" => "value1", "key    2" => "value 2"))
Dict{String,String} with 2 entries:
  "key%20%20%20%202" => "value%202"
  "key%201"          => "value1"
```
"""
function oauth_percent_encode_keys!(options::Dict)
    #options encoded
    originalkeys = collect(keys(options))

    for key in originalkeys
        key_str = string(key)
        encoded_key = encodeURI(key_str)

        options[encoded_key] = encodeURI(options[key_str])
        if encodeURI(key_str) != key
            delete!(options, key_str)
        end
    end

    options
end

@deprecate(
    oauth_percent_encode_keys(options::Dict),
    oauth_percent_encode_keys!(options::Dict)
)

"""
    oauth_serialize_url_parameters(options::Dict)

Returns query string by concatenating dictionary keys/values.

# Examples
```jldoctest
julia> oauth_serialize_url_parameters(Dict("foo" => "bar", "foo 1" => "hello!"))
"foo=bar&foo 1=hello!"
```
"""
oauth_serialize_url_parameters(options::Dict) = join(
    ["$key=$(options[key])" for key in sort!(collect(keys(options)))],
    "&"
)

# See: https://github.com/randyzwitch/OAuth.jl/issues/3
"""
    encodeURI(s)

Convenience function for `HTTP.escape`.

# Examples
```jldoctest
julia> encodeURI("hello, world!")
"hello%2C%20world%21"
```
"""
encodeURI(s) = HTTP.escape(s)

"""
    encodeURI!(dict_of_parameters::Dict)

Mutates dict_of_parameters using `encodeURI` on strings.

# Examples
```jldoctest
julia> encodeURI!(Dict("iv" => 10, "s" => "value!"))
Dict{String,Any} with 2 entries:
  "iv" => 10
  "s"  => "value%21"
```
"""
function encodeURI!(dict_of_parameters::Dict)
    for (k, v) in dict_of_parameters
        if typeof(v) <: String
            dict_of_parameters[k] = encodeURI(v)
        end
    end
    return dict_of_parameters
end

@deprecate(
    encodeURI(dict_of_parameters::Dict),
    encodeURI!(dict_of_parameters::Dict)
)

"""
    oauth_body_hash_file(filename::String)

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input text file.

# Examples
```jldoctest
julia> oauth_body_hash_file(joinpath(Pkg.dir(), "OAuth/test/auth_body_hash_file.txt"))
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```
"""
function oauth_body_hash_file(filename::String)
    oauth_body_hash_data(readstring(open(filename)))
end

"""
    oauth_body_hash_data(data::String)

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input.

# Examples
```jldoctest
julia> oauth_body_hash_data("Hello, World!")
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```
"""
function oauth_body_hash_data(data::String)
    "oauth_body_hash=$(oauth_body_hash_encode(data))"
end

"""
    oauth_body_hash_encode(data::String)

Convenience function for SHA-1 and base64 encoding.

# Examples
```jldoctest
julia> oauth_body_hash_encode("julialang")
"Lsztg2byou89Y8lBoH3G8v3vjbw="
```
"""
function oauth_body_hash_encode(data::String)
        base64encode(digest("SHA1", data))
end

"""
    function oauth_header(httpmethod, baseurl, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret; oauth_signature_method = "HMAC-SHA1", oauth_version = "1.0")

Builds OAuth header, defaulting to OAuth 1.0. Function assumes `options` has already
been run through `encodeURI!`.

"""
function oauth_header(httpmethod, baseurl, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret; oauth_signature_method = "HMAC-SHA1", oauth_version = "1.0")

    #keys for parameter string
    options["oauth_consumer_key"] = oauth_consumer_key
    options["oauth_nonce"] = oauth_nonce(32)
    options["oauth_signature_method"] = oauth_signature_method
    options["oauth_timestamp"] = oauth_timestamp()
    options["oauth_token"] = oauth_token
    options["oauth_version"] = oauth_version

    #options encoded
    oauth_percent_encode_keys!(options)

    #Create ordered query string
    parameterstring = oauth_serialize_url_parameters(options)

    #Calculate signature_base_string
    signature_base_string = oauth_signature_base_string(uppercase(httpmethod), baseurl, parameterstring)

    #Calculate signing_key
    signing_key = oauth_signing_key(oauth_consumer_secret, oauth_token_secret)

    #Calculate oauth_signature
    oauth_sig = encodeURI(oauth_sign_hmac_sha1(signature_base_string, signing_key))

    return "OAuth oauth_consumer_key=\"$(options["oauth_consumer_key"])\", oauth_nonce=\"$(options["oauth_nonce"])\", oauth_signature=\"$(oauth_sig)\", oauth_signature_method=\"$(options["oauth_signature_method"])\", oauth_timestamp=\"$(options["oauth_timestamp"])\", oauth_token=\"$(options["oauth_token"])\", oauth_version=\"$(options["oauth_version"])\""

end

"""
    oauth_request_resource(endpoint::String, httpmethod::String, options::Dict, oauth_consumer_key::String, oauth_consumer_secret::String, oauth_token::String, oauth_token_secret::String)

Makes `GET` or `POST` call to OAuth API.

"""
function oauth_request_resource(endpoint::String, httpmethod::String, options::Dict, oauth_consumer_key::String, oauth_consumer_secret::String, oauth_token::String, oauth_token_secret::String)
    #Build query string
    query_str = HTTP.escape(options)

    #Build oauth_header
    oauth_header_val = oauth_header(httpmethod, endpoint, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret)

    #Make request
    headers = Dict{String,String}(
            "Content-Type" => "application/x-www-form-urlencoded",
            "Authorization" => oauth_header_val,
            "Accept" => "*/*"
        )

    if uppercase(httpmethod) == "POST"
        return HTTP.post(endpoint, query_str; headers = headers)
    elseif uppercase(httpmethod) == "GET"
        return HTTP.get("$(endpoint)?$query_str"; headers = headers)
    end
end

end
