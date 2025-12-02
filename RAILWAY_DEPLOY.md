# 🚀 SkyScan - Railway Deployment Guide

## Step-by-Step Deployment to Railway

### 1. Sign Up for Railway
1. Go to **https://railway.app**
2. Click **"Login"** → Sign in with **GitHub**
3. Authorize Railway to access your GitHub

---

### 2. Push Your Code to GitHub

```powershell
# Initialize git (if not already done)
cd "C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT"
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - SkyScan vulnerability scanner"

# Create GitHub repository at https://github.com/new
# Name it: skyscan

# Add remote and push
git remote add origin https://github.com/YOUR_USERNAME/skyscan.git
git branch -M main
git push -u origin main
```

---

### 3. Deploy to Railway

1. **Go to Railway Dashboard**: https://railway.app/dashboard
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Choose your **skyscan** repository
5. Railway will start building automatically

---

### 4. Add MongoDB Service

1. In your Railway project, click **"+ New"**
2. Select **"Database"** → **"Add MongoDB"**
3. Railway will create a MongoDB instance
4. **Copy the connection string** (automatically set as `MONGODB_URL`)

---

### 5. Configure Environment Variables

1. Click on your **web service** (not MongoDB)
2. Go to **"Variables"** tab
3. Add these variables:

```
SECRET_KEY = <click "Generate" button or paste: run in terminal>
MONGODB_URL = <auto-filled by Railway>
```

**Generate SECRET_KEY**:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
Copy the output and paste as `SECRET_KEY` value.

---

### 6. Deploy Settings (Auto-Configured)

Railway automatically detects:
- ✅ **Procfile** → Runs `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- ✅ **nixpacks.toml** → Installs `nmap` package
- ✅ **requirements.txt** → Installs Python dependencies
- ✅ **runtime.txt** → Uses Python 3.13

---

### 7. Monitor Deployment

1. Click on **"Deployments"** tab
2. Watch the build logs:
   - Installing nmap... ✅
   - Installing Python packages... ✅
   - Starting uvicorn... ✅
3. Wait for **"SUCCESS"** status (2-5 minutes)

---

### 8. Get Your Live URL

1. Go to **"Settings"** tab
2. Scroll to **"Domains"**
3. Click **"Generate Domain"**
4. You'll get: `https://skyscan-production.up.railway.app`

**Your app is now LIVE!** 🎉

---

### 9. Test Your Deployed App

Visit your Railway URL:
```
https://your-app-name.up.railway.app
```

Test:
- ✅ Register new user
- ✅ Login
- ✅ Start network scan
- ✅ View scan results
- ✅ Check scan history

---

## 🔄 Updating After Deployment

**Yes, you can update your deployed app anytime!**

### Method 1: Push to GitHub (Auto-Deploy)
```powershell
# Make your changes
# Then commit and push
git add .
git commit -m "Updated feature X"
git push origin main

# Railway automatically redeploys!
```

### Method 2: Manual Deploy from Railway
1. Go to Railway dashboard
2. Click **"Deployments"**
3. Click **"Deploy"** button
4. Select branch to deploy

**Every push to GitHub triggers automatic redeployment!**

---

## 📊 Railway Free Tier Limits

- **500 hours/month** of usage
- **512 MB RAM** per service
- **1 GB storage** for MongoDB
- **100 GB bandwidth/month**
- **Auto-sleep after 30 min inactivity** (wakes on request)

**Perfect for your MIT project!**

---

## 🐛 Troubleshooting

### Build Failed: Nmap Not Found
✅ Already fixed with `nixpacks.toml`

### MongoDB Connection Error
1. Check `MONGODB_URL` variable is set
2. Verify MongoDB service is running (green status)
3. Restart the web service

### App Not Loading
1. Check deployment logs for errors
2. Verify `Procfile` exists
3. Make sure `PORT` env variable is used: `--port $PORT`

### Scans Failing
1. Nmap might not be installed - check build logs
2. Verify `nixpacks.toml` is committed to git
3. Restart deployment

---

## 🎯 Quick Deployment Checklist

- [x] Renamed to SkyScan
- [x] Created `Procfile`
- [x] Created `nixpacks.toml` (for nmap)
- [x] Created `runtime.txt`
- [x] Updated config.py with env variables
- [x] Ready to push to GitHub
- [ ] Create GitHub repository
- [ ] Push code to GitHub
- [ ] Deploy on Railway
- [ ] Add MongoDB service
- [ ] Set SECRET_KEY variable
- [ ] Generate domain
- [ ] Test live app

---

## 📝 Next Steps

1. **Push to GitHub** (see Step 2 above)
2. **Deploy to Railway** (see Step 3 above)
3. **Share your live URL** with your MIT team!

**Your SkyScan app will be accessible worldwide!** 🌍

---

## 💡 Pro Tips

- **Custom Domain**: Railway allows custom domains (myapp.com)
- **Monitoring**: Railway shows CPU, memory, network usage
- **Logs**: Real-time logs available in dashboard
- **Rollback**: Can rollback to previous deployments
- **Scaling**: Upgrade plan for more resources

**Need help?** Railway has excellent Discord support: https://discord.gg/railway

---

**Ready to deploy? Follow steps 1-8 above!** 🚀
