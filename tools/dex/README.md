# Dex OpenID Connect Test Environment

This directory contains a complete test environment for OpenID Connect using [Dex](https://dexidp.io/), an OpenID Connect identity provider.

## Quick Start

1. **Start Dex server**:
   ```bash
   ./start_dex.sh
   ```

2. **Run the Julia OIDC client**:
   ```bash
   julia ../oidc_standalone.jl settings.dex.json
   ```

3. **Open browser** and navigate to: http://127.0.0.1:8888

4. **Login with test credentials**:
   - Email: `admin@example.com`
   - Password: `password`

## Files

- **`docker-compose.yml`**: Docker Compose configuration for Dex
- **`config.yaml`**: Dex server configuration
- **`settings.dex.json`**: Julia client configuration
- **`start_dex.sh`**: Script to start Dex server
- **`README.md`**: This documentation

## Configuration Details

### Dex Server
- **URL**: http://127.0.0.1:5556/dex
- **Client ID**: `local`
- **Client Secret**: `123123123ABCABCABC123123123ABCAB`
- **Redirect URI**: `http://127.0.0.1:8888/auth/login`

### Test User
- **Email**: `admin@example.com`
- **Password**: `password`
- **Groups**: `admin`, `users`

## PKCE Testing

The setup supports both PKCE-enabled and PKCE-disabled flows:

### Test with PKCE (default)
```bash
julia ../oidc_standalone.jl settings.dex.json
```

### Test without PKCE
```bash
julia ../oidc_standalone.jl settings.dex.json --no-pkce
```

## OpenID Connect Endpoints

When Dex is running, these endpoints are available:

- **OpenID Configuration**: http://127.0.0.1:5556/dex/.well-known/openid-configuration
- **Authorization**: http://127.0.0.1:5556/dex/auth
- **Token**: http://127.0.0.1:5556/dex/token
- **UserInfo**: http://127.0.0.1:5556/dex/userinfo
- **JWKS**: http://127.0.0.1:5556/dex/keys

## Troubleshooting

### Check Dex Status
```bash
docker-compose logs -f
```

### View OpenID Configuration
```bash
curl -s http://127.0.0.1:5556/dex/.well-known/openid-configuration | jq
```

### Stop Dex
```bash
docker-compose down
```

### Restart Dex
```bash
docker-compose restart
```

## Common Issues

1. **Port 5556 already in use**: Stop other services using port 5556
2. **Docker not running**: Start Docker daemon
3. **Permission denied**: Make sure `start_dex.sh` is executable (`chmod +x start_dex.sh`)

## Development Notes

- Dex stores data in memory, so all sessions are lost when the container restarts
- The configuration includes refresh token support for testing token refresh flows
- PKCE is enabled by default in the Dex configuration
- The test user password is hashed using bcrypt