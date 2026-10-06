#!/usr/bin/env bash
set -euo pipefail
echo "Running benchmarks..."
(cd benchmarks && go run .)
echo "Benchmark results written to benchmarks/results/"

