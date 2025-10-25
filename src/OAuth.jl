module OAuth

using Dates, HTTP, JSON, Random, SHA, Base64, LibAwsCal, LibAwsCommon

include("errors.jl")
include("util.jl")
include("jwt_util.jl")
include("types.jl")
include("wwwauthenticate.jl")
include("discovery.jl")
include("pkce.jl")
include("browser.jl")
include("flow.jl")

export OAuthError
export WWWAuthenticateChallenge, parse_www_authenticate
export ProtectedResourceMetadata, AuthorizationServerMetadata, TokenResponse
export ConfidentialClientConfig, PublicClientConfig, AuthorizationRequest, PKCEVerifier
export ClientSecretAuth, PrivateKeyJWTAuth, DPoPAuth
export LoopbackListener, AuthorizationSession
export fetch_protected_resource_metadata, fetch_authorization_server_metadata
export select_authorization_server
export build_authorization_url
export generate_pkce_verifier, pkce_challenge
export launch_browser
export start_pkce_authorization, start_pkce_authorization_from_issuer
export exchange_code_for_token, wait_for_authorization_code
export complete_pkce_authorization, complete_pkce_authorization_from_issuer
export request_client_credentials_token, request_client_credentials_token_from_issuer
export stop_loopback_listener
export DEFAULT_LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT, DEFAULT_LOOPBACK_PATH

end
