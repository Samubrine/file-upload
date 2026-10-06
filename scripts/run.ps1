# Run CipherVault Server
if (-not (Test-Path "bin/ciphervault.exe")) {
    & ./scripts/build.ps1
}
Write-Host "Starting CipherVault on http://localhost:8080..."
& ./bin/ciphervault.exe -port 8080 -static frontend/dist -db data/ciphervault.db

