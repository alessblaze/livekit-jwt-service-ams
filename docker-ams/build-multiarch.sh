#!/bin/bash
set -e

echo "Building binaries for multiple architectures..."

# Create bin directory if it doesn't exist
mkdir -p bin

# Build AMD64 binary
echo "Building AMD64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o bin/livekit-jwt-service-ams-amd64 ..

# Build ARM64 binary  
echo "Building ARM64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GO111MODULE=on go build -a -o bin/livekit-jwt-service-ams-arm64 ..

echo "Binaries built successfully!"
ls -la bin/livekit-jwt-service-ams-*

echo "Building and pushing multi-arch Docker images..."

# Build and push multi-arch image
docker buildx build \
  -t alessmicro/livekit-jwt-service-ams:latest \
  -f Dockerfile \
  --platform linux/amd64,linux/arm64 \
  --push \
  .

echo "Multi-arch build complete!"
