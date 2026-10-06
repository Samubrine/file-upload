#!/usr/bin/env bash
set -euo pipefail
if [ ! -f "bin/ciphervault" ]; then
    ./scripts/build.sh
fi
echo "Starting CipherVault on http://localhost:8080..."
./bin/ciphervault -port 8080 -static frontend/dist -db data/ciphervault.db

