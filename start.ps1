# Vulnerability Detector - Startup Script for Windows
# Run this script to start the application

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Vulnerability Detector - Startup" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check if MongoDB is running
Write-Host "[1/5] Checking MongoDB status..." -ForegroundColor Yellow
$mongoService = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue

if ($mongoService) {
    if ($mongoService.Status -eq "Running") {
        Write-Host "  ✓ MongoDB is running" -ForegroundColor Green
    } else {
        Write-Host "  ! MongoDB is not running. Starting..." -ForegroundColor Yellow
        Start-Service -Name "MongoDB"
        Start-Sleep -Seconds 3
        Write-Host "  ✓ MongoDB started" -ForegroundColor Green
    }
} else {
    Write-Host "  ✗ MongoDB service not found" -ForegroundColor Red
    Write-Host "  Please install MongoDB or start it manually" -ForegroundColor Yellow
}

# Check Python
Write-Host ""
Write-Host "[2/5] Checking Python installation..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "  ✗ Python not found" -ForegroundColor Red
    Write-Host "  Please install Python 3.11+ from python.org" -ForegroundColor Yellow
    exit 1
}

# Check virtual environment
Write-Host ""
Write-Host "[3/5] Checking virtual environment..." -ForegroundColor Yellow
if (Test-Path ".\venv\Scripts\Activate.ps1") {
    Write-Host "  ✓ Virtual environment found" -ForegroundColor Green
} else {
    Write-Host "  ! Virtual environment not found. Creating..." -ForegroundColor Yellow
    python -m venv venv
    Write-Host "  ✓ Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host ""
Write-Host "[4/5] Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Check dependencies
Write-Host ""
Write-Host "[5/5] Checking dependencies..." -ForegroundColor Yellow
$pipList = pip list
if ($pipList -match "fastapi") {
    Write-Host "  ✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "  ! Dependencies not found. Installing..." -ForegroundColor Yellow
    pip install -r requirements.txt
    Write-Host "  ✓ Dependencies installed" -ForegroundColor Green
}

# Start the application
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Starting Vulnerability Detector..." -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access the application at:" -ForegroundColor Green
Write-Host "  Homepage:    http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs:    http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Dashboard:   http://localhost:8000/dashboard" -ForegroundColor White
Write-Host ""
Write-Host "Press CTRL+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start uvicorn
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
