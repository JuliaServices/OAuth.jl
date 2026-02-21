using Documenter
using OAuth

makedocs(modules = [OAuth], sitename = "OAuth.jl", checkdocs = :none)

deploydocs(repo = "github.com/JuliaServices/OAuth.jl.git", push_preview = true)
