#!/usr/bin/env bash
set -euo pipefail
echo "Running backend tests..."
(cd backend && go test -v -race ./...)

