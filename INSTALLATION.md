# Installation Guide - Vulnerability Detector

## Windows Installation (Detailed)

### Step 1: Install Python 3.11+

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run installer
3. **Important**: Check "Add Python to PATH"
4. Click "Install Now"
5. Verify installation:
```powershell
python --version
# Should show Python 3.11.x or higher
```

### Step 2: Install MongoDB

1. Download MongoDB Community Server from [mongodb.com](https://www.mongodb.com/try/download/community)
2. Run the installer (`.msi` file)
3. Choose "Complete" installation
4. Install MongoDB as a Windows Service (recommended)
5. Use default data directory: `C:\Program Files\MongoDB\Server\7.0\data`
6. Verify installation:
```powershell
# Check if MongoDB service is running
Get-Service MongoDB

# Or connect to MongoDB
mongo
# or
mongosh
```

### Step 3: Install Nmap

1. Download Nmap from [nmap.org/download.html](https://nmap.org/download.html)
2. Choose "Latest stable release self-installer"
3. Run the installer
4. Accept default installation path: `C:\Program Files (x86)\Nmap`
5. Add Nmap to PATH:
   - Open System Properties → Environment Variables
   - Edit "Path" in System Variables
   - Add: `C:\Program Files (x86)\Nmap`
   - Click OK
6. Verify installation:
```powershell
nmap --version
# Should show Nmap version 7.x or higher
```

### Step 4: Setup Project

```powershell
# Navigate to project directory
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# If you get execution policy error, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install -r requirements.txt
```

### Step 5: Configure Environment

```powershell
# Copy environment template
copy .env.example .env

# Edit .env file (use notepad or any text editor)
notepad .env
```

Update the `.env` file:
```env
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=vuln_detector
SECRET_KEY=09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Step 6: Run the Application

```powershell
# Make sure virtual environment is activated
# You should see (venv) in your prompt

# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

You should see output like:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Starting Vulnerability Detector v1.0.0
INFO:     Successfully connected to MongoDB
INFO:     Application startup complete
```

### Step 7: Access the Application

Open your web browser and visit:
- Homepage: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Dashboard: http://localhost:8000/dashboard

---

## Docker Installation (Alternative)

### Prerequisites
1. Install Docker Desktop for Windows from [docker.com](https://www.docker.com/products/docker-desktop/)
2. Enable WSL 2 if prompted
3. Start Docker Desktop

### Installation Steps

```powershell
# Navigate to project directory
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# Build and start all services
docker-compose up --build

# Or run in background (detached mode)
docker-compose up -d
```

### Verify Docker Installation

```powershell
# Check running containers
docker ps

# You should see:
# - vuln_detector_api (port 8000)
# - vuln_detector_mongodb (port 27017)
```

### Access Application
Same as manual installation:
- http://localhost:8000

### Stop Docker Services

```powershell
# Stop containers
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

---

## Troubleshooting

### Python Issues

**Problem**: `python` command not found
**Solution**: 
- Reinstall Python with "Add to PATH" checked
- Or use `py` instead of `python`

**Problem**: Virtual environment activation fails
**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### MongoDB Issues

**Problem**: Cannot connect to MongoDB
**Solution**:
1. Check if service is running:
```powershell
Get-Service MongoDB
```
2. Start service if stopped:
```powershell
Start-Service MongoDB
```
3. Or run manually:
```powershell
mongod --dbpath C:\data\db
```

**Problem**: Access denied to MongoDB
**Solution**: Run MongoDB without authentication for development:
```powershell
mongod --noauth --dbpath C:\data\db
```

### Nmap Issues

**Problem**: `nmap` command not found
**Solution**: Add Nmap to PATH manually:
1. Find Nmap installation directory (usually `C:\Program Files (x86)\Nmap`)
2. Add to System PATH
3. Restart PowerShell

**Problem**: Nmap requires administrator privileges
**Solution**: 
- Run PowerShell as Administrator
- Or use Docker deployment (recommended)

### Port Conflicts

**Problem**: Port 8000 already in use
**Solution**:
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Kill the process (use PID from above)
taskkill /PID <PID> /F

# Or use different port
uvicorn app.main:app --port 8080
```

**Problem**: Port 27017 (MongoDB) already in use
**Solution**: Stop other MongoDB instances or use different port

### Firewall Issues

**Problem**: Cannot access from other devices on network
**Solution**:
1. Open Windows Firewall
2. Allow inbound connections for port 8000
3. Or temporarily disable firewall for testing

---

## Post-Installation

### Create First User

1. Go to http://localhost:8000/register
2. Enter email and password
3. Click "Create Account"
4. Login at http://localhost:8000/login

### Run First Scan

1. Login to dashboard
2. Click "Network Scan"
3. Wait for scan to complete (shown in history table)
4. Click "View" to see detailed results

### Test with Postman

1. Import `Vulnerability_Detector_API.postman_collection.json`
2. Set `base_url` to `http://localhost:8000`
3. Run "Register User" request
4. Run "Login" request (saves token automatically)
5. Try other requests

---

## Development Mode

For development with auto-reload:

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run with reload
uvicorn app.main:app --reload --log-level debug
```

## Production Deployment

For production:

1. Generate strong SECRET_KEY:
```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

2. Update `.env` with production values
3. Use production WSGI server
4. Enable MongoDB authentication
5. Configure reverse proxy (IIS/nginx)
6. Enable HTTPS
7. Set up monitoring

---

## Getting Help

If you encounter issues:
1. Check application logs
2. Verify all prerequisites are installed
3. Check Windows Event Viewer for service errors
4. Review MongoDB logs: `C:\Program Files\MongoDB\Server\7.0\log\mongod.log`
5. Check firewall settings

## Success Checklist

- [ ] Python 3.11+ installed and in PATH
- [ ] MongoDB installed and service running
- [ ] Nmap installed and in PATH
- [ ] Virtual environment created and activated
- [ ] Dependencies installed via pip
- [ ] .env file configured
- [ ] Application starts without errors
- [ ] Can access http://localhost:8000
- [ ] Can register and login
- [ ] Can run vulnerability scan
- [ ] MongoDB connected successfully

---

**You're ready to start scanning for vulnerabilities!** 🎉
