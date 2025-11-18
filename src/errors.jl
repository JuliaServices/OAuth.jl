"""
    OAuthError(code::Symbol, message::String)

Lightweight exception that the package raises whenever a protocol precondition
fails (invalid metadata, HTTP errors, user cancellation, etc.).  Each error
includes a machine-friendly `code` so that callers can branch on categories,
and a human-friendly `message` that can be displayed directly to users.

# Examples
```julia
julia> using OAuth

julia> throw(OAuthError(:invalid_grant, "Refresh token was revoked"))
ERROR: OAuthError(invalid_grant): Refresh token was revoked
```
"""
struct OAuthError <: Exception
    code::Symbol
    message::String
end

"""
    OAuthError(code::AbstractString, message::AbstractString)

Convenience constructor that lets you pass stringly-typed codes—handy when you
bubble up `error` values from JSON responses—while still normalizing everything
to the canonical `Symbol` based representation.
"""
OAuthError(code::AbstractString, message::AbstractString) = OAuthError(Symbol(code), String(message))

Base.showerror(io::IO, err::OAuthError) = print(io, "OAuthError($(err.code)): $(err.message)")
