using Mux
using HTTP
using JSON
using OpenIDConnect
using JWTs

headers(req) = req[:headers]
query(req) = parse_query(req[:query])
function parse_query(qstr)
    res = Dict{String,String}()
    for qsub in split(qstr, '&')
        nv = split(qsub, '=')
        res[nv[1]] = length(nv) > 1 ? nv[2] : ""
    end
    res
end

function pretty(j)
    iob = IOBuffer()
    JSON.print(iob, j, 4)
    String(take!(iob))
end

function login(oidcctx::OIDCCtx)
    openid_config = oidcctx.openid_config
    issuer = openid_config["issuer"]
    openid_config_url = issuer * ".well-known/openid-configuration"

    """
    <html><head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/oidc-client/1.5.1/oidc-client.js"></script>
        <script>
            var settings = {
                    issuer: '$issuer',
                    authority: '$openid_config_url',
                    metadata: {
                        issuer: '$issuer',
                        authorization_endpoint: '$(openid_config["authorization_endpoint"])',
                        userinfo_endpoint: '$(openid_config["token_endpoint"])',
                        jwks_uri: '$(openid_config["jwks_uri"])',
                    },
                    client_id: '$(oidcctx.client_id)',
                    redirect_uri: 'http://127.0.0.1:8888/auth/login',
                    response_type: 'code',
                    scope: 'openid email profile offline_access'
                };
            var mgr = new Oidc.UserManager(settings);
            var user = mgr.signinRedirect();
        </script>
    </head><body></body></html>
    """
end

function show_token(oidcctx::OIDCCtx, authresp, authenticated)
    id_token = authresp["id_token"]
    jwt = JWT(;jwt=id_token)
    isvalid = flow_validate_id_token(oidcctx, jwt)

    token_claims = claims(jwt)

    jbox_auth = Dict(
        "Authorization" => ("Bearer " * id_token)
    )

    authenticated[] = true
    can_refresh = "refresh_token" in keys(authresp)
    refresh_link = can_refresh ? """<hr/><a href="/auth/refresh?refresh_token=$(authresp["refresh_token"])">Refresh</a>""" : ""

    """<html><body>
    OpenID Authentication:
    <pre>$(pretty(authresp))</pre><hr/>
    JWT Token:
    <pre>$(pretty(token_claims))</pre><hr/>
    Authentication Bearer Token:
    <pre>$(pretty(jbox_auth))</pre><hr/>
    Validation success: $isvalid 
    $(refresh_link)
    </body></html>"""
end

function token(oidcctx::OIDCCtx, req, authenticated)
    resp = query(req)
    code = resp["code"]
    authresp = flow_get_token(oidcctx, code)
    show_token(oidcctx, authresp, authenticated)
end

function refresh(oidcctx::OIDCCtx, req, authenticated)
    resp = query(req)
    refresh_token = resp["refresh_token"]
    authresp = flow_refresh_token(oidcctx, refresh_token)
    show_token(oidcctx, authresp, authenticated)
end

function main()
    if length(ARGS) != 1
        println("Usage: julia oidc_standalone.jl <configuration_file>")
        exit(1)
    end

    config = open(ARGS[1]) do f
            JSON.parse(f)
        end
    oidcctx = OIDCCtx(String(config["issuer"]), "http://127.0.0.1:8888/auth/login", String(config["client_id"]), String(config["client_secret"]), ["openid", "email", "profile", "offline_access"])
    authenticated = Ref(false)

    @app test = (
         Mux.defaults,
         page("/", req->login(oidcctx)),
         page("/auth/login", req->token(oidcctx, req, authenticated)),
         page("/auth/refresh", req->refresh(oidcctx, req, authenticated)),
         Mux.notfound())

    @info("Standalone OIDC test server starting on port 8888")
    serve(test, 8888)

    while config["do_refresh"] || !(authenticated[])
        sleep(10)
    end
    sleep(10)
end

main()
