# 🎯 USAGE GUIDE - Vulnerability Detector

## Table of Contents
1. [First Time Setup](#first-time-setup)
2. [Starting the Application](#starting-the-application)
3. [Creating Your Account](#creating-your-account)
4. [Running Scans](#running-scans)
5. [Viewing Results](#viewing-results)
6. [Understanding Reports](#understanding-reports)
7. [API Testing](#api-testing)
8. [Common Tasks](#common-tasks)
9. [Tips & Tricks](#tips--tricks)

---

## First Time Setup

### Prerequisites Installed?
Check if you have everything:

```powershell
# Check Python
python --version
# Should show: Python 3.11.x or higher

# Check MongoDB
Get-Service MongoDB
# Should show: Running

# Check Nmap
nmap --version
# Should show: Nmap version 7.x
```

If any are missing, see [INSTALLATION.md](INSTALLATION.md)

### Initialize Project

```powershell
# Navigate to project
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# Quick setup (recommended)
.\start.ps1

# OR Manual setup
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

---

## Starting the Application

### Easy Method (Recommended)
```powershell
# Just run the startup script
.\start.ps1
```

This script will:
- ✅ Check MongoDB status
- ✅ Check Python installation
- ✅ Create/activate virtual environment
- ✅ Install dependencies if needed
- ✅ Start the web server

### Manual Method
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Docker Method
```powershell
# Start with Docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Verify It's Running
Open browser to: http://localhost:8000

You should see the landing page!

---

## Creating Your Account

### Step 1: Navigate to Registration
1. Open http://localhost:8000
2. Click "Get Started" or "Register"
3. You'll be redirected to registration page

### Step 2: Fill Registration Form
- **Email**: Enter a valid email (e.g., `yourname@example.com`)
- **Password**: Minimum 6 characters (e.g., `mypassword123`)
- **Confirm Password**: Re-enter the same password

### Step 3: Submit
- Click "Create Account"
- Wait for success message
- You'll be redirected to login page

**Note**: Email must be unique. Use different emails for multiple accounts.

---

## Running Scans

### From Dashboard

#### Step 1: Login
1. Go to http://localhost:8000/login
2. Enter your email and password
3. Click "Login"
4. You'll be redirected to dashboard

#### Step 2: Choose Scan Type

**Option A: Network Scan** (Recommended for first test)
- Scans network infrastructure
- Uses Nmap to discover assets
- Identifies open ports and services
- Matches against CVE database
- **Duration**: 10-30 seconds

**Option B: Cloud Scan**
- Scans cloud configuration
- Checks for misconfigurations
- Analyzes security groups
- Reviews IAM policies
- **Duration**: 5-15 seconds

**Option C: Full Scan**
- Combines Network + Cloud
- Comprehensive assessment
- Complete vulnerability report
- **Duration**: 30-90 seconds

#### Step 3: Start Scan
1. Click the scan type card (e.g., "Network Scan")
2. Confirm the action
3. Wait for "Scan started successfully!" message
4. Scan ID will be shown

#### Step 4: Monitor Progress
- Scan runs in background
- Dashboard auto-refreshes every 30 seconds
- Check "Scan History" table for status
- Status will change: Pending → Running → Completed

### From API (Advanced)

```bash
# Get your access token first (from login)
TOKEN="your-access-token-here"

# Start network scan
curl -X POST http://localhost:8000/api/scan/network \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "scan_type": "quick"}'
```

---

## Viewing Results

### Dashboard View

#### Scan History Table
Located at bottom of dashboard. Shows:
- **Scan ID**: Unique identifier (shortened)
- **Type**: network/cloud/full
- **Timestamp**: When scan was performed
- **Status**: completed/running/failed
- **Severity Counts**: Critical, High, Medium, Low
- **Actions**: View button

#### View Detailed Results
1. Find your completed scan in history table
2. Click "View" button
3. Modal popup opens with full report

### Report Sections

#### 1. Executive Summary
```
Risk Level: HIGH
Risk Score: 7.5/10
Total Vulnerabilities: 3
  - Critical: 1
  - High: 1
  - Medium: 1
```

#### 2. Severity Breakdown
Visual cards showing:
- Critical (Red)
- High (Orange)
- Medium (Blue)
- Low (Gray)

#### 3. Vulnerabilities Table
Shows top 10 vulnerabilities:
- CVE ID
- Description
- Severity
- CVSS Score
- Affected Asset

#### 4. Remediation Plan
Accordion with prioritized actions:
- Priority level (Immediate/High/Medium)
- Recommended action
- Estimated effort
- Risk reduction percentage

### Download Report
1. Click "Download Report" button in modal
2. JSON file downloads with complete data
3. File name: `scan_report_{scan_id}.json`

---

## Understanding Reports

### Risk Levels

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| **CRITICAL** | 9.0-10.0 | Severe risk | Fix immediately |
| **HIGH** | 7.0-8.9 | Significant risk | Fix urgently |
| **MEDIUM** | 4.0-6.9 | Moderate risk | Schedule fix |
| **LOW** | 0.1-3.9 | Minor risk | Fix when convenient |

### CVSS Scores
- **10.0**: Maximum severity
- **7.0+**: High severity
- **4.0-6.9**: Medium severity
- **0-3.9**: Low severity

### Severity Counts
Each scan shows counts like:
```
CRITICAL: 2    ← Most urgent
HIGH: 5        ← Important
MEDIUM: 8      ← Moderate
LOW: 3         ← Least urgent
```

### Priority Scores
Vulnerabilities are prioritized (0-100):
- **90-100**: Immediate action required
- **70-89**: High priority
- **50-69**: Medium priority
- **0-49**: Low priority

### Sample Vulnerability

```json
{
  "cve_id": "CVE-2021-44228",
  "description": "Apache Log4j2 Remote Code Execution",
  "severity": "CRITICAL",
  "cvss_score": 10.0,
  "affected_product": "Apache Log4j",
  "detected_version": "2.14.1",
  "port": 8080,
  "asset_ip": "127.0.0.1",
  "priority_score": 100,
  "exploitability": "High"
}
```

**What this means**:
- Critical vulnerability (worst level)
- Perfect CVSS score (10.0)
- Affects Log4j version 2.14.1
- Found on port 8080
- Highly exploitable
- Fix immediately!

---

## API Testing

### Using Postman

#### Step 1: Import Collection
1. Open Postman
2. Click "Import"
3. Select `Vulnerability_Detector_API.postman_collection.json`
4. Click "Import"

#### Step 2: Set Base URL
1. Click collection name
2. Go to "Variables" tab
3. Set `base_url` to `http://localhost:8000`
4. Save

#### Step 3: Test Workflow

**1. Register User**
- Select "Authentication → Register User"
- Click "Send"
- Should get 201 Created

**2. Login**
- Select "Authentication → Login"
- Click "Send"
- Token automatically saved!

**3. Get User Info**
- Select "User Management → Get User Info"
- Click "Send"
- See your user details

**4. Start Scan**
- Select "Vulnerability Scanning → Network Scan"
- Click "Send"
- Note the scan_id

**5. Check History**
- Select "User Management → Get Scan History"
- Click "Send"
- See all your scans

**6. Get Scan Detail**
- Select "User Management → Get Scan Detail"
- Update `:scan_id` in URL
- Click "Send"
- See full report

### Using cURL

```powershell
# Register
curl -X POST http://localhost:8000/api/auth/register `
  -H "Content-Type: application/json" `
  -d '{"email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8000/api/auth/login `
  -H "Content-Type: application/x-www-form-urlencoded" `
  -d "username=test@example.com&password=password123"

# Save token from response, then:
$TOKEN = "your-token-here"

# Start scan
curl -X POST http://localhost:8000/api/scan/network `
  -H "Authorization: Bearer $TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"target":"127.0.0.1","scan_type":"quick"}'
```

---

## Common Tasks

### Task 1: Check Application Status
```powershell
# Check if running
curl http://localhost:8000/api/health

# Should return:
# {"status":"healthy","app":"Vulnerability Detector","version":"1.0.0"}
```

### Task 2: View All Scans
1. Login to dashboard
2. Scroll to "Scan History"
3. All scans listed with details

### Task 3: Download Scan Report
1. View scan detail (click "View")
2. Click "Download Report" button
3. JSON file saves to Downloads folder
4. Open with text editor or import to analysis tools

### Task 4: Compare Scans
1. Run multiple scans over time
2. Download each report
3. Compare severity counts
4. Track improvement

### Task 5: Share Results
1. Download report JSON
2. Send to team members
3. Import into ticketing system
4. Use for compliance documentation

### Task 6: Restart Application
```powershell
# Stop
.\stop.ps1

# Start
.\start.ps1
```

### Task 7: View Logs
Check terminal where uvicorn is running for:
- Request logs
- Error messages
- Database connections
- Scan progress

### Task 8: Clear All Data
```powershell
# Connect to MongoDB
mongosh

# Switch to database
use vuln_detector

# Delete all users (careful!)
db.users.deleteMany({})

# Exit
exit
```

---

## Tips & Tricks

### 💡 Productivity Tips

**1. Bookmark Important Pages**
- Dashboard: `http://localhost:8000/dashboard`
- API Docs: `http://localhost:8000/docs`

**2. Use Keyboard Shortcuts**
- `CTRL + R`: Refresh dashboard
- `CTRL + F5`: Hard refresh (clear cache)
- `F12`: Open browser DevTools (debug)

**3. Auto-Refresh Dashboard**
Dashboard auto-refreshes every 30 seconds. To disable:
- Open browser DevTools (F12)
- Console tab
- Type: `clearInterval()`

**4. Quick Login**
Save credentials in browser for faster testing

**5. Multiple Users**
Create multiple accounts for testing:
- user1@test.com
- user2@test.com
- admin@test.com

### 🎯 Best Practices

**1. Regular Scans**
- Run weekly scans
- Track trends over time
- Document improvements

**2. Review Priority Items**
- Focus on Critical/High first
- Schedule Medium for next cycle
- Track Low for awareness

**3. Keep Records**
- Download reports regularly
- Archive JSON files
- Track remediation progress

**4. Monitor Performance**
- Check scan duration
- Monitor resource usage
- Optimize scan frequency

**5. Security Hygiene**
- Change default SECRET_KEY
- Use strong passwords
- Logout after sessions
- Keep MongoDB secure

### 🔧 Troubleshooting Tips

**Problem**: Scan takes too long
**Solution**: 
- Network scans: Reduce port range
- Cloud scans: Should be fast
- Check system resources

**Problem**: No vulnerabilities found
**Solution**:
- Normal if system is updated
- Try scanning different targets
- Check CVE database has data

**Problem**: Dashboard not updating
**Solution**:
- Refresh browser (F5)
- Check console for errors (F12)
- Verify MongoDB connection

**Problem**: Can't login after registration
**Solution**:
- Check email spelling
- Try registering again
- Clear browser cache

**Problem**: Port 8000 in use
**Solution**:
```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### 📊 Interpreting Results

**Many Critical Issues**: 
- System needs immediate attention
- Prioritize patches
- Consider taking offline if public

**Mostly Medium/Low**:
- Good security posture
- Schedule regular updates
- Monitor for new CVEs

**No Issues Found**:
- Excellent! System up-to-date
- Continue regular scans
- Stay vigilant

**Cloud Misconfigurations**:
- Review IAM policies
- Enable MFA
- Restrict public access
- Enable encryption

---

## 🎓 Learning Resources

### Understanding Vulnerabilities
- **CVE Database**: https://cve.mitre.org/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **NVD**: https://nvd.nist.gov/

### Network Security
- **Nmap Tutorial**: https://nmap.org/book/
- **Port Scanning**: https://nmap.org/book/port-scanning.html

### Cloud Security
- **AWS Best Practices**: https://aws.amazon.com/security/
- **Azure Security**: https://docs.microsoft.com/en-us/azure/security/
- **GCP Security**: https://cloud.google.com/security

### API Development
- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **MongoDB Manual**: https://docs.mongodb.com/manual/

---

## 🚀 Advanced Usage

### Custom Scan Targets
Modify `network_scanner.py` to scan:
- Specific IP ranges
- Custom port lists
- Multiple hosts

### Scheduled Scans
Set up Windows Task Scheduler:
1. Create PowerShell script
2. Call API endpoint
3. Schedule daily/weekly

### Integration
Integrate with:
- JIRA (ticket creation)
- Slack (notifications)
- Email (reports)
- SIEM systems

### Custom Reports
Modify `report_builder.py` to:
- Add PDF export
- Custom formatting
- Additional metrics
- Compliance mappings

---

## ✅ Quick Reference

### URLs
```
Homepage:    http://localhost:8000
Login:       http://localhost:8000/login
Register:    http://localhost:8000/register
Dashboard:   http://localhost:8000/dashboard
API Docs:    http://localhost:8000/docs
Health:      http://localhost:8000/api/health
```

### Commands
```powershell
Start:       .\start.ps1
Stop:        .\stop.ps1
Docker:      docker-compose up -d
Logs:        # Check terminal
MongoDB:     Get-Service MongoDB
```

### Files
```
Docs:        README.md, INSTALLATION.md, QUICKSTART.md, API.md
Config:      .env
Postman:     Vulnerability_Detector_API.postman_collection.json
CVE Data:    app/scan/cve_database.json
```

---

**Happy Scanning!** 🔒🛡️

For more help, see:
- [README.md](README.md) - Full documentation
- [INSTALLATION.md](INSTALLATION.md) - Setup guide
- [QUICKSTART.md](QUICKSTART.md) - Quick start
- [API.md](API.md) - API reference
