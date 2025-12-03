using HTTP
using JSON
using OpenIDConnect
using JWTs

function parse_query(query_string::AbstractString)
    res = Dict{String,String}()
    isempty(query_string) && return res
    
    for pair in split(query_string, '&')
        if !isempty(pair)
            key_val = split(pair, '=', limit=2)
            if length(key_val) == 2
                key = HTTP.URIs.unescapeuri(key_val[1])
                val = HTTP.URIs.unescapeuri(key_val[2])
                res[key] = val
            end
        end
    end
    res
end

function pretty_json(obj)
    io = IOBuffer()
    JSON.print(io, obj, 4)
    String(take!(io))
end

function html_page(title::String, content::String)
    """
    <!DOCTYPE html>
    <html>
    <head>
        <title>$title</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
            .error { color: red; }
            .success { color: green; }
            a { color: #0066cc; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>$title</h1>
        $content
    </body>
    </html>
    """
end

function handle_root(oidc_ctx::OIDCCtx, use_pkce::Bool)
    try
        # Generate authorization URL using the library's proper PKCE flow
        auth_url = flow_request_authorization_code(oidc_ctx; pkce=use_pkce)
        
        content = """
        <p>Click the link below to start the OpenID Connect authentication flow:</p>
        <p><a href="$auth_url">Authenticate with OpenID Connect</a></p>
        <p><strong>PKCE Mode:</strong> $(use_pkce ? "Enabled" : "Disabled")</p>
        <hr>
        <p><strong>Authorization URL:</strong></p>
        <pre>$auth_url</pre>
        """
        
        return html_page("OpenID Connect Demo", content)
    catch e
        error_content = """
        <p class="error">Error generating authorization URL: $e</p>
        """
        return html_page("Error", error_content)
    end
end

function handle_callback(oidc_ctx::OIDCCtx, query_params::Dict{String,String}, authenticated::Ref{Bool})
    try
        # Extract authorization code using the library's proper flow
        auth_code_result = flow_get_authorization_code(oidc_ctx, query_params)
        
        # Check if we got an error
        if isa(auth_code_result, OpenIDConnect.APIError)
            error_content = """
            <p class="error">API Error: $(auth_code_result.error)</p>
            """
            return html_page("Authentication Error", error_content)
        elseif isa(auth_code_result, OpenIDConnect.AuthServerError)
            error_content = """
            <p class="error">Auth Server Error: $(auth_code_result.error)</p>
            $(auth_code_result.error_description !== nothing ? "<p>Description: $(auth_code_result.error_description)</p>" : "")
            $(auth_code_result.error_uri !== nothing ? "<p>URI: $(auth_code_result.error_uri)</p>" : "")
            """
            return html_page("Authentication Error", error_content)
        end
        
        # We have a valid authorization code, now exchange it for tokens
        token_result = flow_get_token(oidc_ctx, auth_code_result)
        
        # Check if token exchange failed
        if isa(token_result, OpenIDConnect.APIError)
            error_content = """
            <p class="error">Token API Error: $(token_result.error)</p>
            """
            return html_page("Token Error", error_content)
        elseif isa(token_result, OpenIDConnect.AuthServerError)
            error_content = """
            <p class="error">Token Auth Server Error: $(token_result.error)</p>
            $(token_result.error_description !== nothing ? "<p>Description: $(token_result.error_description)</p>" : "")
            $(token_result.error_uri !== nothing ? "<p>URI: $(token_result.error_uri)</p>" : "")
            """
            return html_page("Token Error", error_content)
        end
        
        # Success! Process the tokens
        authenticated[] = true
        
        id_token = token_result["id_token"]
        jwt = JWT(;jwt=id_token)
        is_valid = flow_validate_id_token(oidc_ctx, jwt)
        token_claims = claims(jwt)
        
        bearer_token = Dict("Authorization" => "Bearer " * id_token)
        
        can_refresh = haskey(token_result, "refresh_token")
        refresh_link = can_refresh ? 
            """<p><a href="/auth/refresh?refresh_token=$(token_result["refresh_token"])">Refresh Tokens</a></p>""" : ""
        
        content = """
        <p class="success">Authentication successful!</p>
        
        <h3>Token Response:</h3>
        <pre>$(pretty_json(token_result))</pre>
        
        <h3>ID Token Claims:</h3>
        <pre>$(pretty_json(token_claims))</pre>
        
        <h3>Bearer Token Header:</h3>
        <pre>$(pretty_json(bearer_token))</pre>
        
        <h3>Token Validation:</h3>
        <p>ID Token Valid: <strong>$(is_valid ? "YES" : "NO")</strong></p>
        
        $refresh_link
        
        <hr>
        <p><a href="/">Start Over</a></p>
        """
        
        return html_page("Authentication Success", content)
        
    catch e
        error_content = """
        <p class="error">Unexpected error: $e</p>
        <pre>$(sprint(showerror, e, catch_backtrace()))</pre>
        """
        return html_page("Error", error_content)
    end
end

function handle_refresh(oidc_ctx::OIDCCtx, query_params::Dict{String,String}, authenticated::Ref{Bool})
    try
        refresh_token = get(query_params, "refresh_token", "")
        if isempty(refresh_token)
            error_content = """
            <p class="error">No refresh token provided</p>
            """
            return html_page("Refresh Error", error_content)
        end
        
        # Use the library's refresh token flow
        refresh_result = flow_refresh_token(oidc_ctx, refresh_token)
        
        # Check if refresh failed
        if isa(refresh_result, OpenIDConnect.APIError)
            error_content = """
            <p class="error">Refresh API Error: $(refresh_result.error)</p>
            """
            return html_page("Refresh Error", error_content)
        elseif isa(refresh_result, OpenIDConnect.AuthServerError)
            error_content = """
            <p class="error">Refresh Auth Server Error: $(refresh_result.error)</p>
            $(refresh_result.error_description !== nothing ? "<p>Description: $(refresh_result.error_description)</p>" : "")
            $(refresh_result.error_uri !== nothing ? "<p>URI: $(refresh_result.error_uri)</p>" : "")
            """
            return html_page("Refresh Error", error_content)
        end
        
        # Success! Show the refreshed tokens
        id_token = refresh_result["id_token"]
        jwt = JWT(;jwt=id_token)
        is_valid = flow_validate_id_token(oidc_ctx, jwt)
        token_claims = claims(jwt)
        
        content = """
        <p class="success">Tokens refreshed successfully!</p>
        
        <h3>Refreshed Token Response:</h3>
        <pre>$(pretty_json(refresh_result))</pre>
        
        <h3>New ID Token Claims:</h3>
        <pre>$(pretty_json(token_claims))</pre>
        
        <h3>Token Validation:</h3>
        <p>ID Token Valid: <strong>$(is_valid ? "✓ YES" : "✗ NO")</strong></p>
        
        <hr>
        <p><a href="/">Start Over</a></p>
        """
        
        return html_page("Token Refresh Success", content)
        
    catch e
        error_content = """
        <p class="error">Unexpected error during refresh: $e</p>
        <pre>$(sprint(showerror, e, catch_backtrace()))</pre>
        """
        return html_page("Refresh Error", error_content)
    end
end

function request_handler(oidc_ctx::OIDCCtx, use_pkce::Bool, authenticated::Ref{Bool})
    return function(request::HTTP.Request)
        uri = HTTP.URIs.URI(request.target)
        path = uri.path
        query_params = parse_query(uri.query)
        
        response_body = ""
        
        if path == "/"
            response_body = handle_root(oidc_ctx, use_pkce)
        elseif path == "/auth/login"
            response_body = handle_callback(oidc_ctx, query_params, authenticated)
        elseif path == "/auth/refresh"
            response_body = handle_refresh(oidc_ctx, query_params, authenticated)
        else
            response_body = html_page("404 Not Found", "<p>Page not found</p>")
            return HTTP.Response(404, ["Content-Type" => "text/html"], response_body)
        end
        
        return HTTP.Response(200, ["Content-Type" => "text/html"], response_body)
    end
end

function main()
    if length(ARGS) < 1
        println("Usage: julia oidc_standalone.jl <configuration_file> [--no-pkce]")
        println("  configuration_file: JSON file with OIDC configuration")
        println("  --no-pkce: Disable PKCE (default: enabled)")
        exit(1)
    end
    
    config_file = ARGS[1]
    use_pkce = !("--no-pkce" in ARGS)
    
    # Load configuration
    config = open(config_file, "r") do f
        JSON.parse(f, dicttype = Dict{String,Any})
    end
    
    # Create OIDC context
    oidc_ctx = OIDCCtx(
        String(config["issuer"]), 
        "http://127.0.0.1:8888/auth/login", 
        String(config["client_id"]), 
        String(config["client_secret"]), 
        ["openid", "email", "profile", "offline_access"]
    )
    
    authenticated = Ref(false)
    
    # Create HTTP server
    handler = request_handler(oidc_ctx, use_pkce, authenticated)
    
    println("🚀 OpenID Connect Demo Server starting...")
    println("📋 Configuration: $config_file")
    println("🔒 PKCE: $(use_pkce ? "Enabled" : "Disabled")")
    println("🌐 Server: http://127.0.0.1:8888")
    println("🎯 Issuer: $(config["issuer"])")
    println("📝 Client ID: $(config["client_id"])")
    println("\nClick the link above to start the authentication flow!")
    
    # Start the server
    HTTP.serve(handler, "127.0.0.1", 8888; verbose=false)
end

main()