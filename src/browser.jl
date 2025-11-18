"""
    launch_browser(url; wait=false, command=nothing)

Opens the user’s default browser (or a custom `command`) to the supplied
URL.  Used by the PKCE helpers to guide end users through the hosted login
screen.  When `wait=true` the call blocks until the browser command exits,
which is handy for CLI tools that want to keep stdout tidy; otherwise we
return the spawned process handle immediately.

# Examples
```julia
julia> launch_browser(\"https://id.example/authorize?client_id=…\")
Process(`open https://id.example/authorize?client_id=…`, ProcessRunning)
```
"""
function launch_browser(url::AbstractString; wait::Bool=false, command::Union{Cmd,Nothing}=nothing)
    String(url) == "" && throw(ArgumentError("URL must be non-empty"))
    cmd = command === nothing ? default_browser_command(String(url)) : command
    if wait
        run(cmd)
        return nothing
    else
        process = run(cmd; wait=false)
        return process
    end
end

function default_browser_command(url::String)
    if Sys.isapple()
        return `open $(url)`
    elseif Sys.iswindows()
        return `cmd /c start "" $(url)`
    elseif Sys.islinux()
        return linux_browser_command(url)
    else
        throw(OAuthError(:platform_error, "Unsupported platform for browser launch"))
    end
end

function linux_browser_command(url::String)
    if get(ENV, "WSL_DISTRO_NAME", "") != ""
        return `wslview $(url)`
    end
    return `xdg-open $(url)`
end
