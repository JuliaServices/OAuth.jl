"""
    parse_www_authenticate(header::AbstractString) -> Vector{WWWAuthenticateChallenge}

Parses the exact contents of an RFC 7235 `WWW-Authenticate` header into a
structured list of `WWWAuthenticateChallenge` values.  The parser handles a
mix of tokens, quoted strings, extension parameters, and even homespun
servers that stuff extra commas into the header.

# Examples
```julia
julia> header = \"Bearer realm=\\\"example\\\", error=\\\"invalid_token\\\"\" *
                \", DPoP nonce=\\\"abc123\\\"\";

julia> parse_www_authenticate(header)
2-element Vector{WWWAuthenticateChallenge}:
 WWWAuthenticateChallenge(\"Bearer\", nothing, Dict(\"realm\" => \"example\", \"error\" => \"invalid_token\"))
 WWWAuthenticateChallenge(\"DPoP\", nothing, Dict(\"nonce\" => \"abc123\"))
```
"""
function parse_www_authenticate(header::AbstractString)
    challenges = WWWAuthenticateChallenge[]
    idx = firstindex(header)
    stop = lastindex(header)
    while true
        idx = skip_delimiters(header, idx, stop)
        idx > stop && break
        scheme, idx = read_token(header, idx, stop)
        isempty(scheme) && break
        params = Dict{String,String}()
        token = nothing
        seen_param = false
        while true
            idx = skip_spaces(header, idx, stop)
            idx > stop && break
            if header[idx] == ','
                next_idx = Base.nextind(header, idx)
                peek_idx = skip_delimiters(header, next_idx, stop)
                peek_token, after_peek = read_token(header, peek_idx, stop)
                if isempty(peek_token)
                    idx = after_peek
                    continue
                end
                if after_peek <= stop && header[after_peek] == '='
                    idx = peek_idx
                else
                    idx = next_idx
                    break
                end
            end
            key_start = idx
            key, idx = read_token(header, idx, stop)
            isempty(key) && break
            idx = skip_spaces(header, idx, stop)
            if idx <= stop && header[idx] == '='
                idx = Base.nextind(header, idx)
                idx = skip_spaces(header, idx, stop)
                value, idx = read_value(header, idx, stop)
                params[String(key)] = value
                seen_param = true
            else
                if seen_param || token !== nothing
                    idx = key_start
                    break
                end
                token = String(key)
            end
        end
        push!(challenges, WWWAuthenticateChallenge(String(scheme); token=token, params=params))
    end
    return challenges
end

function skip_spaces(str, idx, stop)
    while idx <= stop
        c = str[idx]
        if c == ' ' || c == '\t'
            idx = Base.nextind(str, idx)
        else
            break
        end
    end
    return idx
end

function skip_delimiters(str, idx, stop)
    while idx <= stop
        c = str[idx]
        if c == ' ' || c == '\t' || c == ','
            idx = Base.nextind(str, idx)
        else
            break
        end
    end
    return idx
end

function read_token(str, idx, stop)
    start = idx
    while idx <= stop
        c = str[idx]
        if c == ' ' || c == '\t' || c == '=' || c == ',' || c == '"'
            break
        end
        idx = Base.nextind(str, idx)
    end
    if idx == start
        return "", idx
    end
    last = Base.prevind(str, idx)
    token = String(str[start:last])
    return token, idx
end

function read_value(str, idx, stop)
    idx > stop && return "", idx
    if str[idx] == '"'
        idx = Base.nextind(str, idx)
        buf = IOBuffer()
        escaped = false
        while idx <= stop
            c = str[idx]
            if escaped
                write(buf, c)
                escaped = false
            elseif c == '\\'
                escaped = true
            elseif c == '"'
                idx = Base.nextind(str, idx)
                break
            else
                write(buf, c)
            end
            idx = Base.nextind(str, idx)
        end
        return String(take!(buf)), idx
    else
        start = idx
        while idx <= stop
            c = str[idx]
            if c == ',' || c == ' ' || c == '\t'
                break
            end
            idx = Base.nextind(str, idx)
        end
        if idx == start
            return "", idx
        end
        last = Base.prevind(str, idx)
        return String(str[start:last]), idx
    end
end
