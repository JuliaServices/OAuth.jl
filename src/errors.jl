struct OAuthError <: Exception
    code::Symbol
    message::String
end

OAuthError(code::AbstractString, message::AbstractString) = OAuthError(Symbol(code), String(message))

Base.showerror(io::IO, err::OAuthError) = print(io, "OAuthError($(err.code)): $(err.message)")
