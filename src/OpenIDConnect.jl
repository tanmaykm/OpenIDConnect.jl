module OpenIDConnect

using HTTP
using JSON
using MbedTLS
using Base64
using Random
using JWTs

const DEFAULT_SCOPES = ["openid", "profile", "email"]
const DEFAULT_STATE_TIMEOUT_SECS = 60
const DEFAULT_SKEW_SECS = 2*60
const STATE_PURGE_TRIGGER = 1024
const DEFAULT_KEY_REFRESH_SECS = 60*60

export OIDCCtx, flow_request_authorization_code, flow_get_authorization_code, flow_get_token, flow_validate_id_token, flow_refresh_token

"""
Holds an OpenID Connect context that can be used in subsequent OpenID request flows.
The context holds request states, and configuration options.
"""
struct OIDCCtx
    states::Dict{String,Float64}
    state_timeout_secs::Int
    allowed_skew_secs::Int
    openid_config::Dict{String,Any}
    http_tls_opts::Dict{Symbol,Any}
    validator::JWKSet
    key_refresh_secs::Int
    last_key_refresh::Float64
    client_id::String
    client_secret::String
    scopes::Vector{String}
    redirect_uri::String
    random_device::RandomDevice

    function OIDCCtx(issuer::String, redirect_uri::String, client_id::String, client_secret::String, scopes::Vector{String}=DEFAULT_SCOPES;
                        verify::Union{Nothing,Bool}=nothing, cacrt::Union{Nothing,String,MbedTLS.CRT}=nothing,
                        state_timeout_secs::Int=DEFAULT_STATE_TIMEOUT_SECS, allowed_skew_secs::Int=DEFAULT_SKEW_SECS, key_refresh_secs::Int=DEFAULT_KEY_REFRESH_SECS,
                        random_device::RandomDevice=RandomDevice())
        endswith(issuer, "/") || (issuer = issuer * "/")
        openid_config_url = issuer * ".well-known/openid-configuration"
        http_tls_opts = Dict{Symbol,Any}()

        if verify !== nothing
            http_tls_opts[:require_ssl_verification] = verify
        end

        if cacrt !== nothing
            isa(cacrt, String) && (cacrt = MbedTLS.crt_parse_file(cacrt))
            conf = MbedTLS.SSLConfig(verify === nothing || verify)
            MbedTLS.ca_chain!(conf, cacrt)
            http_tls_opts[:sslconfig] = conf
        end

        # fetch and store the openid config, along with the additional args for SSL
        openid_config = JSON.parse(String(HTTP.request("GET", openid_config_url; status_exception=true, http_tls_opts...).body))
        validator = JWKSet(openid_config["jwks_uri"])

        new(Dict{String,Float64}(), state_timeout_secs, allowed_skew_secs, openid_config, http_tls_opts, validator, key_refresh_secs, 0.0, client_id, client_secret, scopes, redirect_uri, random_device)
    end
end

authorization_endpoint(ctx::OIDCCtx) = ctx.openid_config["authorization_endpoint"]
token_endpoint(ctx::OIDCCtx) = ctx.openid_config["token_endpoint"]

function remember_state(ctx::OIDCCtx, state::String)
    ctx.states[state] = time()
    nothing
end

function validate_state(ctx::OIDCCtx, state::String)
    statestore = ctx.states
    if state in keys(statestore)
        t = statestore[state]
        delete!(statestore, state)
        if (time() - t) <= ctx.state_timeout_secs
            return true
        end
    end
    @info("encountered an unknown or expired state")
    if length(statestore) > STATE_PURGE_TRIGGER
        purge_states!(ctx)
    end
    false
end

function purge_states(ctx::OIDCCtx)
    tnow = time()
    tmout = ctx.state_timeout_secs
    filter!(nv->(tnow-nv[2])>tmout, ctx.states)
    nothing
end

"""
API calling error detected by this library
"""
struct APIError
    error::String
end

"""
Error returned from OpenID server
See section 3.1.2.6 of https://openid.net/specs/openid-connect-core-1_0.html
"""
struct AuthServerError
    error::String
    error_description::Union{Nothing,String}
    error_uri::Union{Nothing,String}
end

"""
Authentication request. Uses the authorization code flow.
Acceptable optional args as listed in section 3.1.2.1 of specifications (https://openid.net/specs/openid-connect-core-1_0.html)

Returns a String with the redirect URL.
Caller must perform the redirection.
"""
function flow_request_authorization_code(ctx::OIDCCtx; nonce=nothing, display=nothing, prompt=nothing, max_age=nothing, ui_locales=nothing, id_token_hint=nothing, login_hint=nothing, acr_values=nothing)
    @debug("oidc negotiation: initiating...")
    scopes = join(ctx.scopes, ' ')
    state = randstring(ctx.random_device, 10)
    remember_state(ctx, state)

    query = Dict("response_type"=>"code", "client_id"=>ctx.client_id, "redirect_uri"=>ctx.redirect_uri, "scope"=>scopes, "state"=>state)
    (nonce          === nothing) || (query["nonce"]         = String(nonce))
    (display        === nothing) || (query["display"]       = String(display))
    (prompt         === nothing) || (query["prompt"]        = String(prompt))
    (max_age        === nothing) || (query["max_age"]       = String(max_age))
    (ui_locales     === nothing) || (query["ui_locales"]    = String(ui_locales))
    (id_token_hint  === nothing) || (query["id_token_hint"] = String(id_token_hint))
    (login_hint     === nothing) || (query["login_hint"]    = String(login_hint))
    (acr_values     === nothing) || (query["acr_values"]    = String(acr_values))

    uri = HTTP.merge(HTTP.URIs.URI(authorization_endpoint(ctx)); query=query)
    return string(uri)
end

"""
Given the params from the redirected response from the authentication request, extract the authorization code.
See sections 3.1.2.5 and 3.1.2.6 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns the authorization code on success.
Returns one of APIError or AuthServerError on failure.
"""
function flow_get_authorization_code(ctx::OIDCCtx, @nospecialize(query))
    state = get(query, "state", get(query, :state, nothing))
    if state === nothing
        return APIError("invalid request, no state found")
    end
    if validate_state(ctx, String(state)) === nothing
        return APIError("invalid or expired state")
    end

    code = get(query, "code", get(query, :code, nothing))
    if code !== nothing
        return String(code)
    end

    errcode = get(query, "error", nothing)
    if errcode !== nothing
        return AuthServerError(errcode, get(query, "error_description", nothing), get(query, "error_uri", nothing))
    end
    return APIError("invalid request, no code or error found")
end

function parse_token_response(tok_res)
    @info("oidc: success response from token endpoint")
    resp_str = String(tok_res.body)

    if tok_res.status == 200
        return JSON.parse(resp_str)
    end

    try
        err_resp = JSON.parse(resp_str)
        errcode = get(err_resp, "error", nothing)
        if errcode !== nothing
            return AuthServerError(errcode, get(err_resp, "error_description", nothing), get(err_resp, "error_uri", nothing))
        end
    catch
        return APIError("unknown response from server: " * resp_str)
    end
end

"""
Token Request. Given the authorization code obtained, invoke the token end point and obtain an id_token, access_token, refresh_token.
See section 3.1.3.1 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns a JSON object containing tokens on success.
Returns a AuthServerError or APIError object on failure.
"""
function flow_get_token(ctx::OIDCCtx, code)
    data = Dict("grant_type"=>"authorization_code",
                "code"=>String(code),
                "redirect_uri"=>ctx.redirect_uri,
                "client_id"=>ctx.client_id,
                "client_secret"=>ctx.client_secret)
    headers = Dict("Content-Type"=>"application/x-www-form-urlencoded")
    tok_res = HTTP.request("POST", token_endpoint(ctx), headers, HTTP.URIs.escapeuri(data); status_exception=false, ctx.http_tls_opts...)
    return parse_token_response(tok_res)
end

"""
Token Refresh. Given the refresh code obtained, invoke the token end point and obtain new tokens.
See section 12 of https://openid.net/specs/openid-connect-core-1_0.html.

Returns a JSON object containing tokens on success.
Returns a AuthServerError or APIError object on failure.
"""
function flow_refresh_token(ctx::OIDCCtx, refresh_token)
    data = Dict("grant_type"=>"refresh_token",
                "refresh_token"=>String(refresh_token),
                "client_id"=>ctx.client_id,
                "client_secret"=>ctx.client_secret)
    headers = Dict("Content-Type"=>"application/x-www-form-urlencoded")
    tok_res = HTTP.request("POST", token_endpoint(ctx), headers, HTTP.URIs.escapeuri(data); status_exception=false, ctx.http_tls_opts...)
    return parse_token_response(tok_res)
end

"""
Validate an OIDC token.
Validates both the structure and signature.
See section 3.1.3.7 of https://openid.net/specs/openid-connect-core-1_0.html
"""
flow_validate_id_token(ctx::OIDCCtx, id_token) = flow_validate_id_token(ctx, JWT(;jwt=String(id_token)))
function flow_validate_id_token(ctx::OIDCCtx, jwt::JWT)
    isvalid = false

    if issigned(jwt)
        try
            tokclaims = claims(jwt)
            issue_time = tokclaims["iat"] - ctx.allowed_skew_secs
            expiry_time = tokclaims["exp"] + ctx.allowed_skew_secs
            isvalid = issue_time <= round(Int, time()) <= expiry_time
        catch ex
            @info("invalid token format ($ex)")
        end

        if isvalid
            validator = ctx.validator
            if (time() - ctx.last_key_refresh) >= ctx.key_refresh_secs
                jstr = String(HTTP.get(ctx.validator.url; ctx.http_tls_opts...).body)
                keys = JSON.parse(jstr)["keys"]
                refresh!(keys, Dict{String,JWK}();)
            end
            isvalid = validate!(jwt, validator)
        end
    end

    return isvalid
end

end # module
