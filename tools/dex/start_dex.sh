#!/bin/bash

# Start Dex OpenID Connect server for testing
# This script launches a Dex server with predefined configuration

cd "$(dirname "$0")"

echo "🚀 Starting Dex OpenID Connect server..."
echo "📋 Configuration: config.yaml"
echo "🌐 Server: http://127.0.0.1:5556/dex"
echo "👤 Test User: admin@example.com / password"
echo "🔑 Client ID: local"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed or not in PATH"
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping any existing Dex containers..."
docker-compose down --remove-orphans

# Start the Dex server
echo "🔄 Starting Dex server..."
docker-compose up -d

# Wait for health check
echo "⏳ Waiting for Dex to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:5556/dex/healthz > /dev/null 2>&1; then
        echo "✅ Dex is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Dex failed to start within 30 seconds"
        echo "📋 Check logs with: docker-compose logs"
        exit 1
    fi
    sleep 1
done

echo ""
echo "🎉 Dex OpenID Connect server is running!"
echo "🌐 OpenID Configuration: http://127.0.0.1:5556/dex/.well-known/openid-configuration"
echo "🔐 Authorization Endpoint: http://127.0.0.1:5556/dex/auth"
echo "🎟️  Token Endpoint: http://127.0.0.1:5556/dex/token"
echo ""
echo "🧪 To test with the Julia client, run:"
echo "   julia ../oidc_standalone.jl settings.dex.json"
echo ""
echo "🛑 To stop Dex, run:"
echo "   docker-compose down"
echo ""
echo "📋 To view logs, run:"
echo "   docker-compose logs -f"