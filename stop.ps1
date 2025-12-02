# Stop Vulnerability Detector

Write-Host "Stopping Vulnerability Detector..." -ForegroundColor Yellow

# Find and kill uvicorn processes
$processes = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*uvicorn*"
}

if ($processes) {
    $processes | Stop-Process -Force
    Write-Host "✓ Application stopped" -ForegroundColor Green
} else {
    Write-Host "! No running application found" -ForegroundColor Yellow
}

# Optionally stop MongoDB
$stopMongo = Read-Host "Do you want to stop MongoDB as well? (y/n)"
if ($stopMongo -eq "y") {
    Stop-Service -Name "MongoDB" -ErrorAction SilentlyContinue
    Write-Host "✓ MongoDB stopped" -ForegroundColor Green
}

Write-Host ""
Write-Host "All processes stopped" -ForegroundColor Cyan
