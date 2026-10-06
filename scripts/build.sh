#!/usr/bin/env bash
set -euo pipefail
echo "Building frontend..."
(cd frontend && npm run build)
echo "Building backend..."
(cd backend && go build -o ../bin/ciphervault ./cmd/server)
echo "Build complete: bin/ciphervault"

