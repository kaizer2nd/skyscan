# PowerShell script to set up ML infrastructure
# Run this to quickly add AI/ML to your scanner

Write-Host "🤖 Setting up AI/ML for Vulnerability Scanner..." -ForegroundColor Cyan

# Step 1: Create directory structure
Write-Host "`n📁 Creating ML directories..." -ForegroundColor Yellow
New-Item -Path "app\ml" -ItemType Directory -Force | Out-Null
New-Item -Path "app\ml\models" -ItemType Directory -Force | Out-Null
New-Item -Path "app\ml\data" -ItemType Directory -Force | Out-Null
Write-Host "✅ Directories created" -ForegroundColor Green

# Step 2: Install ML dependencies
Write-Host "`n📦 Installing ML dependencies..." -ForegroundColor Yellow
Write-Host "This may take a few minutes..." -ForegroundColor Gray

if (Test-Path "venv\Scripts\Activate.ps1") {
    & venv\Scripts\Activate.ps1
    pip install scikit-learn==1.3.2 numpy==1.24.3 pandas==2.1.4 nvdlib==0.7.6 joblib==1.3.2 scipy==1.11.4
} else {
    Write-Host "⚠️  Virtual environment not found. Installing globally..." -ForegroundColor Yellow
    pip install scikit-learn==1.3.2 numpy==1.24.3 pandas==2.1.4 nvdlib==0.7.6 joblib==1.3.2 scipy==1.11.4
}

Write-Host "✅ Dependencies installed" -ForegroundColor Green

# Step 3: Create ML module files
Write-Host "`n📝 Creating ML module files..." -ForegroundColor Yellow

# Create __init__.py
$initContent = @"
"""
AI/ML Module for Self-Improving Vulnerability Detection
"""
from .ml_engine import MLEngine

try:
    from .cve_updater import CVEUpdater
except ImportError:
    CVEUpdater = None

__all__ = ['MLEngine', 'CVEUpdater']
__version__ = '1.0.0'
"@

Set-Content -Path "app\ml\__init__.py" -Value $initContent

Write-Host "✅ ML module files created" -ForegroundColor Green

# Step 4: Copy implementation files
Write-Host "`n📋 Next steps:" -ForegroundColor Cyan
Write-Host "1. Copy the ML implementation files to app\ml\ directory" -ForegroundColor White
Write-Host "   - ml_engine.py (main ML engine)" -ForegroundColor White
Write-Host "   - cve_updater.py (CVE auto-updater)" -ForegroundColor White
Write-Host "2. Run: python train_initial_model.py" -ForegroundColor White
Write-Host "3. Integrate with scan_router.py (see QUICK_START_ML.md)" -ForegroundColor White
Write-Host "4. Update frontend to show ML insights" -ForegroundColor White

Write-Host "`n🎉 ML infrastructure setup complete!" -ForegroundColor Green
Write-Host "📖 See AI_ML_INTEGRATION_GUIDE.md for detailed documentation" -ForegroundColor Cyan
Write-Host "🚀 See QUICK_START_ML.md for quick integration steps" -ForegroundColor Cyan
