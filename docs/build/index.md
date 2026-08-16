
<a id='OAuth.jl-Documentation-1'></a>

# OAuth.jl Documentation



- [OAuth.jl Documentation](index.md#OAuth.jl-Documentation-1)
    - [Functions](index.md#Functions-1)
    - [Index](index.md#Index-1)


<a id='Functions-1'></a>

## Functions

<a id='OAuth.encodeURI!-Tuple{Dict}' href='#OAuth.encodeURI!-Tuple{Dict}'>#</a>
**`OAuth.encodeURI!`** &mdash; *Method*.



```
encodeURI!(dict_of_parameters::Dict)
```

Mutates dict_of_parameters using `encodeURI` on strings.

**Examples**

```julia-repl
julia> encodeURI!(Dict("iv" => 10, "s" => "value!"))
Dict{String,Any} with 2 entries:
  "iv" => 10
  "s"  => "value%21"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L162-L174' class='documenter-source'>source</a><br>

<a id='OAuth.encodeURI-Tuple{Any}' href='#OAuth.encodeURI-Tuple{Any}'>#</a>
**`OAuth.encodeURI`** &mdash; *Method*.



```
encodeURI(s)
```

Convenience function for `HTTP.escape`.

**Examples**

```julia-repl
julia> encodeURI("hello, world!")
"hello%2C%20world%21"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L149-L159' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_body_hash_data-Tuple{String}' href='#OAuth.oauth_body_hash_data-Tuple{String}'>#</a>
**`OAuth.oauth_body_hash_data`** &mdash; *Method*.



```
oauth_body_hash_data(data::String)
```

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input.

**Examples**

```julia-repl
julia> oauth_body_hash_data("Hello, World!")
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L204-L214' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_body_hash_encode-Tuple{String}' href='#OAuth.oauth_body_hash_encode-Tuple{String}'>#</a>
**`OAuth.oauth_body_hash_encode`** &mdash; *Method*.



```
oauth_body_hash_encode(data::String)
```

Convenience function for SHA-1 and base64 encoding.

**Examples**

```julia-repl
julia> oauth_body_hash_encode("julialang")
"Lsztg2byou89Y8lBoH3G8v3vjbw="
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L219-L229' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_body_hash_file-Tuple{String}' href='#OAuth.oauth_body_hash_file-Tuple{String}'>#</a>
**`OAuth.oauth_body_hash_file`** &mdash; *Method*.



```
oauth_body_hash_file(filename::String)
```

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input text file.

**Examples**

```julia-repl
julia> oauth_body_hash_file(joinpath(Pkg.dir(), "OAuth/test/auth_body_hash_file.txt"))
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L189-L199' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_header-NTuple{7,Any}' href='#OAuth.oauth_header-NTuple{7,Any}'>#</a>
**`OAuth.oauth_header`** &mdash; *Method*.



```
function oauth_header(httpmethod, baseurl, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret; oauth_signature_method = "HMAC-SHA1", oauth_version = "1.0")
```

Builds OAuth header, defaulting to OAuth 1.0. Function assumes `options` has already been run through `encodeURI!`.


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L234-L240' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_nonce-Tuple{Int64}' href='#OAuth.oauth_nonce-Tuple{Int64}'>#</a>
**`OAuth.oauth_nonce`** &mdash; *Method*.



```
oauth_nonce(length::Int)
```

Returns a random string of a given length.

**Examples**

```julia-repl
julia> oauth_nonce(10)
"aQb2FVkrYi"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L37-L47' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_percent_encode_keys!-Tuple{Dict}' href='#OAuth.oauth_percent_encode_keys!-Tuple{Dict}'>#</a>
**`OAuth.oauth_percent_encode_keys!`** &mdash; *Method*.



```
oauth_percent_encode_keys!(options::Dict)
```

Returns dict where keys and values are URL-encoded.

**Examples**

```julia-repl
julia> oauth_percent_encode_keys!(Dict("key 1" => "value1", "key    2" => "value 2"))
Dict{String,String} with 2 entries:
  "key%20%20%20%202" => "value%202"
  "key%201"          => "value1"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L97-L109' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_request_resource-Tuple{String,String,Dict,String,String,String,String}' href='#OAuth.oauth_request_resource-Tuple{String,String,Dict,String,String,String,String}'>#</a>
**`OAuth.oauth_request_resource`** &mdash; *Method*.



```
oauth_request_resource(endpoint::String, httpmethod::String, options::Dict, oauth_consumer_key::String, oauth_consumer_secret::String, oauth_token::String, oauth_token_secret::String)
```

Makes `GET` or `POST` call to OAuth API.


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L270-L275' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_serialize_url_parameters-Tuple{Dict}' href='#OAuth.oauth_serialize_url_parameters-Tuple{Dict}'>#</a>
**`OAuth.oauth_serialize_url_parameters`** &mdash; *Method*.



```
oauth_serialize_url_parameters(options::Dict)
```

Returns query string by concatenating dictionary keys/values.

**Examples**

```julia-repl
julia> oauth_serialize_url_parameters(Dict("foo" => "bar", "foo 1" => "hello!"))
"foo=bar&foo 1=hello!"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L132-L142' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_sign_hmac_sha1-Tuple{String,String}' href='#OAuth.oauth_sign_hmac_sha1-Tuple{String,String}'>#</a>
**`OAuth.oauth_sign_hmac_sha1`** &mdash; *Method*.



```
oauth_sign_hmac_sha1(message::String, signingkey::String)
```

Takes a message and signing key, converts to a SHA-1 digest, then encodes to base64.

**Examples**

```julia-repl
julia> oauth_sign_hmac_sha1("foo", "bar")
"hdFVxV7ShqMAvRzxJN4I2H6RTzo="
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L52-L62' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_signature_base_string-Tuple{String,String,String}' href='#OAuth.oauth_signature_base_string-Tuple{String,String,String}'>#</a>
**`OAuth.oauth_signature_base_string`** &mdash; *Method*.



```
oauth_signature_base_string(httpmethod::String, url::String, parameterstring::String)
```

Returns encoded HTTP method, url and parameters.

**Examples**

```julia-repl
julia> oauth_signature_base_string("POST", "https://julialang.org", "foo&bar")
"POST&https%3A%2F%2Fjulialang.org&foo%26bar"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L82-L92' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_signing_key-Tuple{String,String}' href='#OAuth.oauth_signing_key-Tuple{String,String}'>#</a>
**`OAuth.oauth_signing_key`** &mdash; *Method*.



```
oauth_signing_key(oauth_consumer_secret::String, oauth_token_secret::String)
```

Returns a signing key based on a consumer secret and token secret.

**Examples**

```julia-repl
julia> oauth_signing_key("foo", "bar")
"foo&bar"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L67-L77' class='documenter-source'>source</a><br>

<a id='OAuth.oauth_timestamp-Tuple{}' href='#OAuth.oauth_timestamp-Tuple{}'>#</a>
**`OAuth.oauth_timestamp`** &mdash; *Method*.



```
oauth_timestamp()
```

Returns current unix timestamp as String.

**Examples**

```julia-repl
julia> oauth_timestamp()
"1512235859"
```


<a target='_blank' href='https://github.com/randyzwitch/OAuth.jl/blob/65ca9f96238994ccf84202b2ac6467e2a34ac7b6/src/OAuth.jl#L22-L32' class='documenter-source'>source</a><br>


<a id='Index-1'></a>

## Index

- [`OAuth.encodeURI`](index.md#OAuth.encodeURI-Tuple{Any})
- [`OAuth.encodeURI!`](index.md#OAuth.encodeURI!-Tuple{Dict})
- [`OAuth.oauth_body_hash_data`](index.md#OAuth.oauth_body_hash_data-Tuple{String})
- [`OAuth.oauth_body_hash_encode`](index.md#OAuth.oauth_body_hash_encode-Tuple{String})
- [`OAuth.oauth_body_hash_file`](index.md#OAuth.oauth_body_hash_file-Tuple{String})
- [`OAuth.oauth_header`](index.md#OAuth.oauth_header-NTuple{7,Any})
- [`OAuth.oauth_nonce`](index.md#OAuth.oauth_nonce-Tuple{Int64})
- [`OAuth.oauth_percent_encode_keys!`](index.md#OAuth.oauth_percent_encode_keys!-Tuple{Dict})
- [`OAuth.oauth_request_resource`](index.md#OAuth.oauth_request_resource-Tuple{String,String,Dict,String,String,String,String})
- [`OAuth.oauth_serialize_url_parameters`](index.md#OAuth.oauth_serialize_url_parameters-Tuple{Dict})
- [`OAuth.oauth_sign_hmac_sha1`](index.md#OAuth.oauth_sign_hmac_sha1-Tuple{String,String})
- [`OAuth.oauth_signature_base_string`](index.md#OAuth.oauth_signature_base_string-Tuple{String,String,String})
- [`OAuth.oauth_signing_key`](index.md#OAuth.oauth_signing_key-Tuple{String,String})
- [`OAuth.oauth_timestamp`](index.md#OAuth.oauth_timestamp-Tuple{})

