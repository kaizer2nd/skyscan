# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Option 1: Using Docker (Easiest)

```powershell
# 1. Make sure Docker Desktop is running
docker --version

# 2. Navigate to project
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# 3. Start everything
docker-compose up -d

# 4. Open browser
start http://localhost:8000
```

**That's it!** Your vulnerability detector is running.

---

### Option 2: Manual Setup

```powershell
# 1. Create virtual environment
python -m venv venv

# 2. Activate it
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Make sure MongoDB is running
# Check: Get-Service MongoDB

# 5. Start the app
uvicorn app.main:app --reload

# 6. Open browser
start http://localhost:8000
```

---

## 📝 First Time Use

### 1. Create Account
- Go to http://localhost:8000/register
- Enter email: `test@example.com`
- Enter password: `password123`
- Click "Create Account"

### 2. Login
- Go to http://localhost:8000/login
- Use credentials from above
- Click "Login"

### 3. Run Your First Scan
- You'll be redirected to dashboard
- Click on "Network Scan" card
- Confirm to start scan
- Wait 10-30 seconds
- Scan appears in "Scan History" table
- Click "View" to see results

---

## 🧪 Testing API with Postman

### Import Collection
1. Open Postman
2. Click "Import"
3. Select `Vulnerability_Detector_API.postman_collection.json`
4. Collection imported!

### Test Workflow
1. **Register User**
   - Run the request
   - Should return 201 Created

2. **Login**
   - Run the request
   - Token saved automatically

3. **Get User Info**
   - Run the request
   - Should show your user details

4. **Start Network Scan**
   - Run the request
   - Note the `scan_id`

5. **Get Scan History**
   - Run the request after 30 seconds
   - Should show completed scan

6. **Get Scan Detail**
   - Update `scan_id` in the request
   - Run the request
   - View full vulnerability report

---

## 📊 Understanding the Dashboard

### Overview Section
- **Total Scans**: Number of scans you've performed
- **Critical Vulnerabilities**: Highest severity issues found
- **High Severity**: Important issues to address
- **Medium/Low**: Less urgent findings

### New Scan Options
- **Network Scan**: Scans localhost for open ports and services
- **Cloud Scan**: Analyzes cloud configuration (demo mode)
- **Full Scan**: Combines network + cloud scanning

### Scan History Table
Shows all your previous scans with:
- Scan ID (shortened)
- Type (network/cloud/full)
- Timestamp
- Status (completed/running/failed)
- Severity counts
- View button for detailed report

---

## 🔍 What Gets Scanned?

### Network Scan
- Discovers network assets (default: localhost)
- Scans common ports (22, 80, 443, etc.)
- Fingerprints services and versions
- Matches against CVE database
- Generates CVSS scores
- Creates remediation plan

### Cloud Scan
- Checks storage permissions
- Analyzes network security groups
- Reviews IAM policies
- Verifies encryption settings
- Identifies misconfigurations

### Full Scan
- Combines both network and cloud
- Comprehensive vulnerability assessment
- Prioritized findings
- Complete remediation roadmap

---

## 📈 Sample Scan Results

After running a scan, you'll see:

### Summary
```
Risk Level: HIGH
Risk Score: 7.5/10
Total Vulnerabilities: 12
  - Critical: 2
  - High: 4
  - Medium: 5
  - Low: 1
```

### Vulnerabilities
Each finding includes:
- CVE ID (e.g., CVE-2021-44228)
- Description
- CVSS Score
- Affected service/product
- Detected version
- Priority score

### Remediation Plan
Prioritized actions:
- Immediate: Critical issues
- High: Important patches
- Medium: Schedule in next cycle
- Estimated effort
- Risk reduction

---

## 🛑 Common Issues

### "Cannot connect to MongoDB"
```powershell
# Start MongoDB service
Start-Service MongoDB

# Or check if running
Get-Service MongoDB
```

### "Port 8000 already in use"
```powershell
# Find and kill process
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### "Nmap not found"
- Add Nmap to PATH
- Or run as Administrator
- Or use Docker deployment

### "Login failed"
- Make sure you registered first
- Check email/password spelling
- Try registering again with different email

---

## 🎯 Next Steps

1. ✅ **Explore API Documentation**
   - Visit http://localhost:8000/docs
   - Try out different endpoints
   - See request/response examples

2. ✅ **Customize Scans**
   - Modify scan targets
   - Adjust scan parameters
   - Add custom CVE data

3. ✅ **Review Reports**
   - Download JSON reports
   - Analyze vulnerabilities
   - Follow remediation steps

4. ✅ **Test Security**
   - Try authentication flows
   - Test with different users
   - Verify authorization

---

## 📞 Need Help?

Check these resources:
1. **Full Documentation**: See README.md
2. **Installation Guide**: See INSTALLATION.md
3. **API Docs**: http://localhost:8000/docs
4. **Logs**: Check terminal output for errors

---

## 🎉 Success!

You now have a fully functional vulnerability detection platform!

**Happy Scanning!** 🔒🛡️
