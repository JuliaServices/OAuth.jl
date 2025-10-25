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
