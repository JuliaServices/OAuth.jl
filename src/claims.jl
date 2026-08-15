# A lossless, concretely-typed model of JWT claim values.
#
# `AccessTokenRecord` persists the claims of every issued token, and token
# stores are typically JSON-backed. A `Dict{String,Any}` claim set decodes
# through fully dynamic paths — unusable from a statically compiled
# (`juliac --trim`) server — while any fixed set of named fields would silently
# drop custom claims. `TokenClaim` is the middle path: one concrete node type
# per JSON kind, containers holding further nodes, so any JSON claim value
# round-trips exactly and every read and write is statically dispatched.
#
# Application code that wants plain Julia values calls `claimvalue`
# (node → Any) or `tokenclaim` (Any → node); OAuth's own token-issuing and
# introspection code works on the tree directly.

using StructUtils

"""
    TokenClaim

Abstract supertype of the concrete claim-value nodes: [`ClaimNull`](@ref),
[`ClaimBool`](@ref), [`ClaimNumber`](@ref), [`ClaimString`](@ref),
[`ClaimArray`](@ref) and [`ClaimObject`](@ref). A JWT claim set is a
`Dict{String,TokenClaim}`; convert with [`tokenclaims`](@ref) /
[`claimvalues`](@ref).
"""
abstract type TokenClaim end

"""JSON `null`."""
struct ClaimNull <: TokenClaim end
"""JSON `true`/`false`."""
struct ClaimBool <: TokenClaim
    value::Bool
end
"""A JSON number; integral values are kept as `Int64`, others as `Float64`."""
struct ClaimNumber <: TokenClaim
    value::Union{Int64,Float64}
end
"""A JSON string."""
struct ClaimString <: TokenClaim
    value::String
end
"""A JSON array of claim values."""
struct ClaimArray <: TokenClaim
    items::Vector{TokenClaim}
end
"""A JSON object of claim values."""
struct ClaimObject <: TokenClaim
    members::Dict{String,TokenClaim}
end

"""The closed union of the concrete claim nodes."""
const ClaimNode = Union{ClaimNull,ClaimBool,ClaimNumber,ClaimString,ClaimArray,ClaimObject}
const ClaimScalarNode = Union{ClaimNull,ClaimBool,ClaimNumber,ClaimString}

Base.:(==)(a::ClaimBool, b::ClaimBool) = a.value == b.value
Base.:(==)(a::ClaimNumber, b::ClaimNumber) = a.value == b.value
Base.:(==)(a::ClaimString, b::ClaimString) = a.value == b.value
Base.:(==)(a::ClaimArray, b::ClaimArray) = a.items == b.items
Base.:(==)(a::ClaimObject, b::ClaimObject) = a.members == b.members

# ── Julia value <-> node ────────────────────────────────────────────────────

"""
    tokenclaim(x) -> TokenClaim

Wrap a JSON-representable Julia value as a claim node: `nothing`, `Bool`,
`Int64`/`Int32`/`UInt64`, `Float64`/`Float32`, `String`/`SubString`/`Symbol`,
`Vector{Any}`/`Vector{String}`/`Vector{Int64}`, `Dict{String,Any}`/
`Dict{String,String}`/`Dict{String,TokenClaim}`/`JSON.Object{String,Any}`, or an
existing `TokenClaim`.
Other types raise an `ArgumentError` (convert exotic containers to
`Vector{Any}` / `Dict{String,Any}` first) — the accepted set is deliberately
closed so the conversion stays statically compilable.
"""
# One despecialized method with an explicit type chain (not one method per
# input type): the input comes from a Dict{String,Any} claim set, and a
# multi-method dispatch on an Any-typed value is unresolvable under juliac
# --trim, while a single instance branching inside is statically invokable.
function tokenclaim(@nospecialize(x))::ClaimNode
    x isa TokenClaim && return x::ClaimNode
    x === nothing && return ClaimNull()
    x isa Bool && return ClaimBool(x)
    x isa Int64 && return ClaimNumber(x)
    x isa Float64 && return ClaimNumber(x)
    x isa String && return ClaimString(x)
    x isa Symbol && return ClaimString(String(x))
    # Other integer/float/string types are accepted through their concrete
    # conversions (each an isa-guarded, statically dispatched call).
    x isa Int32 && return ClaimNumber(Int64(x))
    x isa UInt64 && return ClaimNumber(Int64(x))
    x isa Float32 && return ClaimNumber(Float64(x))
    x isa SubString{String} && return ClaimString(String(x))
    # Containers: the concrete types a JSON claim set (Dict{String,Any}) holds
    # first, then generic fallbacks for hand-built values.
    if x isa Vector{Any}
        items = TokenClaim[]
        for v in x
            push!(items, tokenclaim(v))
        end
        return ClaimArray(items)
    end
    if x isa Dict{String,Any}
        members = Dict{String,TokenClaim}()
        for (k, v) in x
            members[k] = tokenclaim(v)
        end
        return ClaimObject(members)
    end
    x isa Vector{String} && return ClaimArray(TokenClaim[ClaimString(v) for v in x])
    x isa Vector{Int64} && return ClaimArray(TokenClaim[ClaimNumber(v) for v in x])
    x isa Dict{String,String} && return ClaimObject(Dict{String,TokenClaim}(k => ClaimString(v) for (k, v) in x))
    x isa Dict{String,TokenClaim} && return ClaimObject(x)
    if x isa JSON.Object{String,Any}     # JSON.parse's default object type
        members = Dict{String,TokenClaim}()
        for (k, v) in x
            members[k] = tokenclaim(v)
        end
        return ClaimObject(members)
    end
    # No generic AbstractVector/AbstractDict fallback: iterating an arbitrary
    # container is dynamic and would defeat static compilation of every
    # caller. Convert exotic containers to Vector{Any}/Dict{String,Any} first.
    throw(ArgumentError("value of type $(typeof(x)) is not a JSON-representable claim value"))
end

"""
    tokenclaims(claims::AbstractDict) -> Dict{String,TokenClaim}

Convert a JWT claim set of plain Julia values into claim nodes.
"""
function tokenclaims(claims::Dict{String,Any})
    out = Dict{String,TokenClaim}()
    for (k, v) in claims
        out[k] = tokenclaim(v)
    end
    return out
end
tokenclaims(claims::Dict{String,TokenClaim}) = claims
function tokenclaims(claims::AbstractDict)
    out = Dict{String,Any}()
    for (k, v) in claims
        out[String(k)] = v
    end
    return tokenclaims(out)
end

"""
    claimvalue(node::TokenClaim) -> Any

Unwrap a claim node into plain Julia values (`nothing`, `Bool`, `Int64`,
`Float64`, `String`, `Vector{Any}`, `Dict{String,Any}`).
"""
function claimvalue(@nospecialize(c))
    c isa ClaimNull && return nothing
    c isa ClaimBool && return c.value
    c isa ClaimNumber && return c.value
    c isa ClaimString && return c.value
    c isa ClaimArray && return Any[claimvalue(v) for v in c.items]
    c isa ClaimObject && return Dict{String,Any}(k => claimvalue(v) for (k, v) in c.members)
    throw(ArgumentError("expected a TokenClaim, got $(typeof(c))"))
end

"""
    claimvalues(claims::Dict{String,TokenClaim}) -> Dict{String,Any}

Convert a claim-node set back into plain Julia values.
"""
claimvalues(claims::Dict{String,TokenClaim}) = Dict{String,Any}(k => claimvalue(v) for (k, v) in claims)

# Convenience accessors used by introspection/validation: typed reads that
# return `nothing` when the claim is absent or of another kind.
claimstring(claims::Dict{String,TokenClaim}, key::String) =
    (c = get(claims, key, nothing); c isa ClaimString ? c.value : nothing)
claimnumber(claims::Dict{String,TokenClaim}, key::String) =
    (c = get(claims, key, nothing); c isa ClaimNumber ? c.value : nothing)

# ── JSON reading ────────────────────────────────────────────────────────────
# Explicit branch per concrete node from the JSON kind of the source (each
# branch a statically dispatched `make`), returning the closed union. This is
# what `StructUtils.@choosetype` expresses, written out so the chosen type is
# dispatched rather than passed as a runtime `Type` value.

function StructUtils.make(st::StructUtils.StructStyle, ::Type{TokenClaim}, x, tags)::Tuple{ClaimNode,Any}
    t = JSON.gettype(x)
    if t == JSON.JSONTypes.OBJECT
        return StructUtils.make(st, ClaimObject, x, tags)
    elseif t == JSON.JSONTypes.ARRAY
        return StructUtils.make(st, ClaimArray, x, tags)
    elseif t == JSON.JSONTypes.STRING
        return StructUtils.make(st, ClaimString, x, tags)
    elseif t == JSON.JSONTypes.NUMBER
        return StructUtils.make(st, ClaimNumber, x, tags)
    elseif t == JSON.JSONTypes.TRUE || t == JSON.JSONTypes.FALSE
        return StructUtils.make(st, ClaimBool, x, tags)
    else
        return StructUtils.make(st, ClaimNull, x, tags)
    end
end
StructUtils.make(st::StructUtils.StructStyle, ::Type{TokenClaim}, x)::Tuple{ClaimNode,Any} =
    StructUtils.make(st, TokenClaim, x, (;))

# Scalar nodes are lifted from the parsed JSON scalar (structlike=false routes make() to lift()).
StructUtils.structlike(::Type{<:ClaimScalarNode}) = false
StructUtils.lift(::Type{ClaimBool}, x::Bool) = ClaimBool(x)
StructUtils.lift(::Type{ClaimNumber}, x::Int64) = ClaimNumber(x)
StructUtils.lift(::Type{ClaimNumber}, x::Float64) = ClaimNumber(x)
StructUtils.lift(::Type{ClaimString}, x::AbstractString) = ClaimString(String(x))
StructUtils.lift(::Type{ClaimNull}, ::Nothing) = ClaimNull()

# Container nodes are built through StructUtils' container protocol.
StructUtils.arraylike(::Type{ClaimArray}) = true
StructUtils.dictlike(::Type{ClaimObject}) = true
StructUtils.initialize(::StructUtils.StructStyle, ::Type{ClaimArray}, source) = ClaimArray(TokenClaim[])
StructUtils.initialize(::StructUtils.StructStyle, ::Type{ClaimObject}, source) = ClaimObject(Dict{String,TokenClaim}())
Base.push!(c::ClaimArray, v::ClaimNode) = (push!(c.items, v); c)
StructUtils.addkeyval!(c::ClaimObject, k::String, v::ClaimNode) = (c.members[k] = v; c)
Base.eltype(::Type{ClaimArray}) = TokenClaim
Base.eltype(::ClaimArray) = TokenClaim
Base.keytype(::Type{ClaimObject}) = String
Base.keytype(::ClaimObject) = String
Base.valtype(::Type{ClaimObject}) = TokenClaim
Base.valtype(::ClaimObject) = TokenClaim
Base.length(c::ClaimArray) = length(c.items)
Base.ndims(::Type{ClaimArray}) = 1

# ── JSON writing ────────────────────────────────────────────────────────────
# JSON.jl's writer recurses through an untyped closure argument, so a pair of
# mutually recursive container types (Vector{TokenClaim} <-> Dict{String,
# TokenClaim}) forms an inference cycle whole-program verification cannot
# close. Nested nodes are therefore serialized by a small typed serializer of
# our own and handed to JSON as JSONText; only the top-level claims dict goes
# through JSON's writer.

function _write_node!(io::IOBuffer, @nospecialize(c))
    if c isa ClaimNull
        print(io, "null")
    elseif c isa ClaimBool
        print(io, c.value ? "true" : "false")
    elseif c isa ClaimNumber
        JSON.json(io, c.value)
    elseif c isa ClaimString
        JSON.json(io, c.value)
    elseif c isa ClaimArray
        print(io, '[')
        for (i, item) in enumerate(c.items)
            i > 1 && print(io, ',')
            _write_node!(io, item)
        end
        print(io, ']')
    elseif c isa ClaimObject
        print(io, '{')
        first = true
        for (k, v) in c.members
            first || print(io, ',')
            first = false
            JSON.json(io, k)
            print(io, ':')
            _write_node!(io, v)
        end
        print(io, '}')
    else
        throw(ArgumentError("expected a TokenClaim, got $(typeof(c))"))
    end
    return nothing
end

function _node_json(@nospecialize(c))
    io = IOBuffer()
    _write_node!(io, c)
    return String(take!(io))
end

function StructUtils.applyeach(st::StructUtils.StructStyle, f, x::Dict{String,TokenClaim})
    for (k, v) in x
        ret = f(StructUtils.lowerkey(st, k), JSON.JSONText(_node_json(v)))
        ret isa StructUtils.EarlyReturn && return ret
    end
    return StructUtils.defaultstate(st)
end
function StructUtils.applyeach(st::StructUtils.StructStyle, f, x::Vector{TokenClaim})
    for i in eachindex(x)
        ret = f(StructUtils.lowerkey(st, i), JSON.JSONText(_node_json(@inbounds(x[i]))))
        ret isa StructUtils.EarlyReturn && return ret
    end
    return StructUtils.defaultstate(st)
end
# A bare node written on its own.
StructUtils.lower(c::TokenClaim) = JSON.JSONText(_node_json(c))
