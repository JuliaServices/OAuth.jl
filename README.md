# OAuth

Linux: [![Build Status](https://travis-ci.org/randyzwitch/OAuth.jl.svg?branch=master)](https://travis-ci.org/randyzwitch/OAuth.jl) <br>
Windows:
[![Build status](https://ci.appveyor.com/api/projects/status/lu2jwu1yh464bdm4/branch/master?svg=true)](https://ci.appveyor.com/project/randyzwitch/oauth-jl/branch/master)
<br>
Coveralls: [![codecov.io](https://codecov.io/github/randyzwitch/OAuth.jl/coverage.svg?branch=master)](https://codecov.io/github/randyzwitch/OAuth.jl?branch=master)

My interpretation of the OAuth 1.0 protocol, based on my reading of [RFC5849](https://tools.ietf.org/html/rfc5849), the [liboauth](http://liboauth.sourceforge.net/) C library and factoring out the OAuth authentication code from [Twitter.jl](https://github.com/randyzwitch/Twitter.jl). At one point, this package relied on liboauth and was a wrapper of that library's functions built using [Clang.jl](https://github.com/ihnorton/Clang.jl); however, as I cleaned up the auto-generated functions from Clang, I decided that it would be easier and cleaner to re-write the library in Julia rather than require liboauth.

This is still a work-in-progress, but works as a replacement for the authentication in the Twitter.jl package, so it should be fairly complete in its implementation.
