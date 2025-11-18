module OAuth

using Dates, HTTP, JSON, Random, SHA, Base64, LibAwsCal, LibAwsCommon, FileWatching

const DEFAULT_RESPONSE_TYPE = "code"
const MAX_DPOP_NONCE_RETRIES = 1

include("errors.jl")
include("util.jl")
include("jwt_util.jl")
include("types.jl")
include("wwwauthenticate.jl")
include("discovery.jl")
include("pkce.jl")
include("browser.jl")
include("flow/common.jl")
include("flow/pkce.jl")
include("flow/device.jl")
include("flow/client.jl")
include("flow/dpop.jl")
include("server.jl")

export OAuthError
export WWWAuthenticateChallenge, parse_www_authenticate
export ProtectedResourceMetadata, AuthorizationServerMetadata, OAuthDiscoveryContext, TokenResponse
export ConfidentialClientConfig, PublicClientConfig, AuthorizationRequest, PKCEVerifier, RequestObjectSigner
export ClientSecretAuth, ClientSecretJWTAuth, PrivateKeyJWTAuth, TLSClientAuth, DPoPAuth, DPoPNonceCache
export RefreshTokenStore, InMemoryRefreshTokenStore, FileBasedRefreshTokenStore, CallbackRefreshTokenStore
export LoopbackListener, AuthorizationSession
export fetch_protected_resource_metadata, fetch_authorization_server_metadata, discover_oauth_metadata, discover_oauth_metadata_from_issuer
export select_authorization_server
export build_authorization_url
export generate_pkce_verifier, pkce_challenge
export launch_browser
export start_pkce_authorization, start_pkce_authorization_from_issuer, start_device_authorization, start_device_authorization_from_issuer
export exchange_code_for_token, wait_for_authorization_code
export complete_pkce_authorization, complete_pkce_authorization_from_issuer
export refresh_pkce_token, refresh_pkce_token_from_issuer
export request_client_credentials_token, request_client_credentials_token_from_issuer, oauth_request, poll_device_authorization_token
export register_dynamic_client, register_dynamic_client_from_issuer, update_dynamic_client, delete_dynamic_client
export stop_loopback_listener
export DEFAULT_LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT, DEFAULT_LOOPBACK_PATH
export ProtectedResourceConfig, AuthorizationServerConfig, JWTAccessTokenIssuer, IssuedAccessToken
export AccessTokenClaims, TokenValidationConfig, InMemoryTokenStore, DPoPReplayCache, DeviceAuthorizationResponse
export AllowAllAuthenticator, BasicCredentialsAuthenticator
export register_protected_resource_metadata!, register_authorization_server_metadata!
export register_jwks_endpoint!, protected_resource_middleware, public_jwk, DEFAULT_JWKS_PATH
export issue_access_token, validate_jwt_access_token
export store_access_token!, lookup_access_token, revoke_access_token!
export build_introspection_handler, build_revocation_handler
export build_www_authenticate_header
export load_refresh_token, save_refresh_token!, clear_refresh_token!
export AuthorizationEndpointConfig, TokenEndpointConfig, TokenEndpointClient
export AuthorizationRequestContext, AuthorizationGrantDecision, grant_authorization, deny_authorization
export AuthorizationCodeStore, AuthorizationCodeRecord, InMemoryAuthorizationCodeStore
export build_authorization_endpoint, build_token_endpoint, client_credentials_authenticator
export store_authorization_code!, consume_authorization_code!

end
