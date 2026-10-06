# Run Reproducible Benchmarks
Write-Host "Running benchmarks..."
Set-Location benchmarks
go run .
Set-Location ..
Write-Host "Benchmark results written to benchmarks/results/"

