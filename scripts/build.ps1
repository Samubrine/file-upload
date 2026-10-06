# Build CipherVault Backend and Frontend
Write-Host "Building frontend..."
Set-Location frontend
npm run build
Set-Location ..

Write-Host "Building backend..."
Set-Location backend
go build -o ../bin/ciphervault.exe ./cmd/server
Set-Location ..
Write-Host "Build complete! Executable is at bin/ciphervault.exe"

