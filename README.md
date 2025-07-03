# OpenIDConnect

[![Build Status](https://github.com/tanmaykm/OpenIDConnect.jl/workflows/CI/badge.svg)](https://github.com/tanmaykm/OpenIDConnect.jl/actions?query=workflow%3ACI+branch%3Amaster)
[![codecov.io](http://codecov.io/github/tanmaykm/OpenIDConnect.jl/coverage.svg?branch=master)](http://codecov.io/github/tanmaykm/OpenIDConnect.jl?branch=master)

[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

This is an implementation of OpenID Connect in Julia, with methods implementing the authorization code flow.

# OpenID Connect Context (OIDCCtx)
The OpenID Connect context holds all states for a single OpenID Connect client configuration.

```julia
function OIDCCtx(
    issuer::String,
    redirect_uri::String,
    client_id::String,
    client_secret::String,
    scopes::Vector{String}=DEFAULT_SCOPES;
    verify::Union{Nothing,Bool}=nothing,
    cacrt::Union{Nothing,String,MbedTLS.CRT}=nothing,
    state_timeout_secs::Int=DEFAULT_STATE_TIMEOUT_SECS,
    allowed_skew_secs::Int=DEFAULT_SKEW_SECS,
    key_refresh_secs::Int=DEFAULT_KEY_REFRESH_SECS),
    random_device::RandomDevice=RandomDevice()
)
```

Parameters:
- `issuer`: Issuer URL, pointing to the OpenID server
- `redirect_uri`: The app URI to which OpenID server must redirect after authorization
- `client_id`, and `client_secret`: Client ID and secret that this context represents
- `scopes`: The scopes to request during authorization (default: openid, profile, email)

Keyword Parameters:
- `verify`: whether to validate the server certificate
- `cacrt`: the CA certificate to use to check the server certificate
- `state_timeout_secs`: seconds for which to keep the state associated with an authorization request (default: 60 seconds), server responses beyond this are rejected as stale
- `allowed_skew_secs`: while validating tokens, seconds to allow to account for time skew between machines (default: 120 seconds)
- `key_refresh_secs`: time interval in which to refresh the JWT signing keys (default: 1hr)

# Error Structures

- `OpenIDConnect.APIError`: Error detected at the client side. Members:
    - `error`: error code or message (String)
- `OpenIDConnect.AuthServerError`: Error returned from the OpenID server (see section 3.1.2.6 of https://openid.net/specs/openid-connect-core-1_0.html)
    - `error`: error code (String)
    - `error_description`: optional error description (String)
    - `error_uri`: optional error URI (String)

# Authorization Code Flow

## Authentication request.

### `flow_request_authorization_code`
Returns a String with the redirect URL. Caller must perform the redirection.
Acceptable optional args as listed in section 3.1.2.1 of specifications (https://openid.net/specs/openid-connect-core-1_0.html)

```julia
function flow_request_authorization_code(
    ctx::OIDCCtx;
    nonce=nothing,
    display=nothing,
    prompt=nothing,
    max_age=nothing,
    ui_locales=nothing,
    id_token_hint=nothing,
    login_hint=nothing,
    acr_values=nothing,
    pkce=false,
)
```

### `flow_get_authorization_code`
Given the params from the redirected response from the authentication request, extract the authorization code.
See sections 3.1.2.5 and 3.1.2.6 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns the authorization code on success.
Returns one of APIError or AuthServerError on failure.

```julia
function flow_get_authorization_code(
    ctx::OIDCCtx,
    query           # name-value pair Dict with query parameters are received from the OpenID server redirect
)
```

## Token Requests

### `flow_get_token`
Token Request. Given the authorization code obtained, invoke the token end point and obtain an id_token, access_token, refresh_token.
See section 3.1.3.1 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns a JSON object containing tokens on success.
Returns a AuthServerError or APIError object on failure.

```julia
function flow_get_token(
    ctx::OIDCCtx,
    code
)
```

### `flow_refresh_token`
Token Refresh. Given the refresh code obtained, invoke the token end point and obtain new tokens.
See section 12 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns a JSON object containing tokens on success.
Returns a AuthServerError or APIError object on failure.

```julia
function flow_refresh_token(
    ctx::OIDCCtx,
    refresh_token
)
```

## Token Validation

### `flow_validate_id_token`
Validate an OIDC token.
Validates both the structure and signature.
See section 3.1.3.7 of https://openid.net/specs/openid-connect-core-1_0.html

```
function flow_validate_id_token(
    ctx::OIDCCtx,
    id_token::Union{JWTs.JWT, String}
)
```

# Examples

## Standalone OIDC Demo

An example application built using OpenIDConnect using HTTP.jl is available as a [tool](tools/oidc_standalone.jl). The application demonstrates:

- **PKCE Support**: Proper implementation of Proof Key for Code Exchange (RFC 7636)
- **Pure Julia Flow**: Server-side authorization code flow without JavaScript dependencies
- **Error Handling**: Comprehensive error display for debugging
- **Token Refresh**: Support for refreshing access tokens

### Quick Start with Dex

The easiest way to check out the OIDC flow is using the included Dex test environment:

```bash
# Start the Dex OpenID Connect server
cd tools/dex
./start_dex.sh

# In another terminal, start the Julia client
julia ../oidc_standalone.jl settings.dex.json

# Open browser to http://127.0.0.1:8888
# Login with: admin@example.com / password
```

The tool can be used with any OpenID Connect provider by configuring the settings file.

### Usage

```bash
julia tools/oidc_standalone.jl <config-file> [--no-pkce]
```

- `config-file`: JSON configuration file (see [template](tools/settings.template))
- `--no-pkce`: Disable PKCE (enabled by default)

### Configuration

Populate a configuration file following this [template](tools/settings.template):

```json
{
    "issuer": "https://your.openid.provider/",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "do_refresh": true
}
```