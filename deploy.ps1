# SkyScan - Quick Deploy to Railway

Write-Host "🚀 SkyScan - Railway Deployment Helper" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Generate SECRET_KEY
Write-Host "📝 Step 1: Generating SECRET_KEY..." -ForegroundColor Yellow
$secretKey = python -c "import secrets; print(secrets.token_hex(32))"
Write-Host "SECRET_KEY: $secretKey" -ForegroundColor Green
Write-Host "⚠️  SAVE THIS - You'll need it for Railway!" -ForegroundColor Red
Write-Host ""

# Step 2: Check if git is initialized
Write-Host "📝 Step 2: Checking Git repository..." -ForegroundColor Yellow
if (-not (Test-Path ".git")) {
    Write-Host "Initializing Git repository..." -ForegroundColor Cyan
    git init
    Write-Host "✅ Git initialized" -ForegroundColor Green
} else {
    Write-Host "✅ Git already initialized" -ForegroundColor Green
}
Write-Host ""

# Step 3: Add all files
Write-Host "📝 Step 3: Adding files to Git..." -ForegroundColor Yellow
git add .
Write-Host "✅ Files staged" -ForegroundColor Green
Write-Host ""

# Step 4: Commit
Write-Host "📝 Step 4: Creating commit..." -ForegroundColor Yellow
git commit -m "SkyScan - Initial deployment commit"
Write-Host "✅ Committed" -ForegroundColor Green
Write-Host ""

# Step 5: Instructions
Write-Host "🎯 NEXT STEPS - Do These Manually:" -ForegroundColor Magenta
Write-Host "===================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "1️⃣  Create GitHub Repository:" -ForegroundColor Yellow
Write-Host "   - Go to: https://github.com/new" -ForegroundColor White
Write-Host "   - Repository name: skyscan" -ForegroundColor White
Write-Host "   - Make it Public" -ForegroundColor White
Write-Host "   - Click 'Create repository'" -ForegroundColor White
Write-Host ""

Write-Host "2️⃣  Push to GitHub:" -ForegroundColor Yellow
Write-Host "   Run these commands after creating the repo:" -ForegroundColor White
Write-Host "   git remote add origin https://github.com/YOUR_USERNAME/skyscan.git" -ForegroundColor Cyan
Write-Host "   git branch -M main" -ForegroundColor Cyan
Write-Host "   git push -u origin main" -ForegroundColor Cyan
Write-Host ""

Write-Host "3️⃣  Deploy to Railway:" -ForegroundColor Yellow
Write-Host "   - Go to: https://railway.app" -ForegroundColor White
Write-Host "   - Login with GitHub" -ForegroundColor White
Write-Host "   - Click 'New Project' → 'Deploy from GitHub repo'" -ForegroundColor White
Write-Host "   - Select 'skyscan' repository" -ForegroundColor White
Write-Host ""

Write-Host "4️⃣  Add MongoDB to Railway:" -ForegroundColor Yellow
Write-Host "   - In your project, click '+ New'" -ForegroundColor White
Write-Host "   - Select 'Database' → 'Add MongoDB'" -ForegroundColor White
Write-Host ""

Write-Host "5️⃣  Set Environment Variables:" -ForegroundColor Yellow
Write-Host "   - Click on your web service (not MongoDB)" -ForegroundColor White
Write-Host "   - Go to 'Variables' tab" -ForegroundColor White
Write-Host "   - Add: SECRET_KEY = $secretKey" -ForegroundColor Cyan
Write-Host "   - MONGODB_URL is auto-filled by Railway" -ForegroundColor White
Write-Host ""

Write-Host "6️⃣  Generate Domain:" -ForegroundColor Yellow
Write-Host "   - Go to 'Settings' tab" -ForegroundColor White
Write-Host "   - Scroll to 'Domains'" -ForegroundColor White
Write-Host "   - Click 'Generate Domain'" -ForegroundColor White
Write-Host ""

Write-Host "✅ Your app will be live in 2-5 minutes!" -ForegroundColor Green
Write-Host ""
Write-Host "📚 Full guide: See RAILWAY_DEPLOY.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
