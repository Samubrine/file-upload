# Run All Tests
Write-Host "Running backend tests..."
Set-Location backend
go test -v -race ./...
Set-Location ..

