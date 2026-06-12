using OpenIDConnect
using Test
using Random
using HTTP
using NetworkOptions

function test_state_store()
    @testset "State store" begin
        ctx = OIDCCtx("https://accounts.google.com", "http://127.0.0.1:8888/auth/login", "test_client_id", "test_client_secret"; state_timeout_secs=5)
        state = randstring(10)
        OpenIDConnect.remember_state(ctx, state)
        @test length(ctx.states) == 1
        @test OpenIDConnect.validate_state(ctx, state)
        sleep(10)
        @info("expecting an invalid state")
        @test !OpenIDConnect.validate_state(ctx, state)
        @test length(ctx.states) == 0
        nothing
    end
end

function test_oidc_flow()
    @testset "OIDC flow" begin
        ctx = OIDCCtx("https://accounts.google.com", "http://127.0.0.1:8888/auth/login", "test_client_id", "test_client_secret"; state_timeout_secs=5)
        @test OpenIDConnect.authorization_endpoint(ctx) == "https://accounts.google.com/o/oauth2/v2/auth"
        @test OpenIDConnect.token_endpoint(ctx) == "https://oauth2.googleapis.com/token"

        # flow request authorization code
        uri_string = flow_request_authorization_code(ctx)
        uri = HTTP.URIs.URI(uri_string)
        @test uri.host == "accounts.google.com"

        query = HTTP.URIs.queryparams(uri)
        @test get(query, "client_id", "") == "test_client_id"
        @test get(query, "redirect_uri", "") == "http://127.0.0.1:8888/auth/login"
        @test get(query, "scope", "") == "openid profile email"
        @test get(query, "response_type", "") == "code"
        @test !isempty(get(query, "state", ""))

        uri_string = flow_request_authorization_code(ctx; nonce="test_nonce", display="test_display", prompt="test_prompt", max_age="12345", ui_locales="en", id_token_hint="test_id_tok_hint", login_hint="test_login_hint", acr_values="test_acr")
        uri = HTTP.URIs.URI(uri_string)
        @test uri.host == "accounts.google.com"

        query = HTTP.URIs.queryparams(uri)
        @test get(query, "client_id", "") == "test_client_id"
        @test get(query, "redirect_uri", "") == "http://127.0.0.1:8888/auth/login"
        @test get(query, "scope", "") == "openid profile email"
        @test get(query, "response_type", "") == "code"
        @test !isempty(get(query, "state", ""))
        @test get(query, "nonce", "") == "test_nonce"
        @test get(query, "display", "") == "test_display"
        @test get(query, "prompt", "") == "test_prompt"
        @test get(query, "max_age", "") == "12345"
        @test get(query, "ui_locales", "") == "en"
        @test get(query, "id_token_hint", "") == "test_id_tok_hint"
        @test get(query, "login_hint", "") == "test_login_hint"
        @test get(query, "acr_values", "") == "test_acr"

        # flow get authorization code
        @test isa(flow_get_authorization_code(ctx, Dict()), OpenIDConnect.APIError)
        @info("expecting an invalid state")
        @test isa(flow_get_authorization_code(ctx, Dict("state"=>"teststate")), OpenIDConnect.APIError)
        OpenIDConnect.remember_state(ctx, "teststate")
        @test isa(flow_get_authorization_code(ctx, Dict("state"=>"teststate")), OpenIDConnect.APIError)
        @info("expecting an invalid state")
        @test isa(flow_get_authorization_code(ctx, Dict("state"=>"teststate", "error"=>"testerror")), OpenIDConnect.AuthServerError)
        @info("expecting an invalid state")
        @test "testcode" == flow_get_authorization_code(ctx, Dict("state"=>"teststate", "code"=>"testcode"))
    end
end

function test_custom_cacrt()
    @testset "Custom CA certificate" begin
        cafile = NetworkOptions.ca_roots_path()

        # A custom CA file builds a custom HTTP.Client; the context must construct
        # and resolve the openid configuration successfully.
        ctx = OIDCCtx("https://accounts.google.com", "http://127.0.0.1:8888/auth/login", "test_client_id", "test_client_secret"; cacrt=cafile)
        @test OpenIDConnect.token_endpoint(ctx) == "https://oauth2.googleapis.com/token"

        # Regression: verify=false together with cacrt must not throw. HTTP v2 rejects
        # require_ssl_verification overrides when an explicit client is passed, so the
        # verify intent has to be carried by the TLS config instead.
        ctx = OIDCCtx("https://accounts.google.com", "http://127.0.0.1:8888/auth/login", "test_client_id", "test_client_secret"; verify=false, cacrt=cafile)
        @test OpenIDConnect.token_endpoint(ctx) == "https://oauth2.googleapis.com/token"

        # A cacrt that is not an existing file is rejected with a clear error.
        @test_throws ErrorException OIDCCtx("https://accounts.google.com", "http://127.0.0.1:8888/auth/login", "test_client_id", "test_client_secret"; cacrt="/no/such/ca-file.pem")
    end
end

@testset "OpenIDConnect" begin
    test_state_store()
    test_oidc_flow()
    test_custom_cacrt()
end
