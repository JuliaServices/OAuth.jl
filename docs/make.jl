using Documenter, OAuth

makedocs()

deploydocs(
    deps = Deps.pip("mkdocs", "python-markdown-math"),
    repo = "github.com/randyzwitch/OAuth.jl.git"
    julia  = "0.6",
    osname = "linux"
)
