# Vulnerability Detector - Advanced Cybersecurity Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-brightgreen.svg)](https://www.mongodb.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A comprehensive vulnerability detection and assessment platform for network infrastructure and cloud environments. Built with FastAPI, MongoDB, and modern scanning technologies.

## 🌟 Features

### Core Capabilities
- ✅ **Network Vulnerability Scanning** - Asset discovery using Nmap with automated port scanning
- ✅ **Cloud Security Assessment** - Configuration analysis for AWS, Azure, and GCP
- ✅ **Service Fingerprinting** - Automatic identification of software versions
- ✅ **CVE Matching Engine** - Comprehensive vulnerability database with 10,000+ CVEs
- ✅ **CVSS Scoring & Prioritization** - Risk assessment using industry standards
- ✅ **Automated Report Generation** - Detailed vulnerability reports with remediation guidance
- ✅ **User Dashboard** - Real-time scan tracking and historical analytics
- ✅ **JWT Authentication** - Secure user authentication with bcrypt password hashing

### Technical Stack
- **Backend**: Python 3.11, FastAPI, Uvicorn
- **Database**: MongoDB with Motor (async driver)
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Scanning**: Python-Nmap, custom vulnerability engines
- **Security**: JWT tokens, bcrypt hashing
- **Deployment**: Docker, Docker Compose

## 📁 Project Structure

```
MINI_PROJECT/
│
├── app/                          # Backend application
│   ├── auth/                     # Authentication module
│   │   ├── auth_models.py        # User & token models
│   │   ├── auth_service.py       # JWT & password services
│   │   └── auth_router.py        # Auth endpoints
│   │
│   ├── users/                    # User management
│   │   ├── users_models.py       # User response models
│   │   └── users_router.py       # User endpoints
│   │
│   ├── scan/                     # Vulnerability scanning
│   │   ├── network_scanner.py    # Network asset discovery
│   │   ├── cloud_scanner.py      # Cloud config scanner
│   │   ├── fingerprint.py        # Service fingerprinting
│   │   ├── match_engine.py       # CVE matching
│   │   ├── cvss_engine.py        # CVSS scoring
│   │   ├── scan_router.py        # Scan endpoints
│   │   └── cve_database.json     # CVE data
│   │
│   ├── database/                 # Database layer
│   │   └── mongodb.py            # MongoDB connection
│   │
│   ├── reports/                  # Report generation
│   │   └── report_builder.py     # Report builder
│   │
│   ├── config.py                 # Configuration
│   └── main.py                   # FastAPI application
│
├── frontend/                     # Frontend application
│   ├── index.html                # Landing page
│   ├── login.html                # Login page
│   ├── register.html             # Registration page
│   ├── dashboard.html            # User dashboard
│   │
│   └── static/                   # Static assets
│       ├── styles.css            # Custom styles
│       ├── auth.js               # Authentication logic
│       └── dashboard.js          # Dashboard logic
│
├── requirements.txt              # Python dependencies
├── Dockerfile                    # Docker image config
├── docker-compose.yml            # Docker compose config
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+** installed
- **MongoDB** installed and running
- **Nmap** installed (for network scanning)
- **Git** (optional)

### Option 1: Manual Installation (Windows)

#### Step 1: Install MongoDB
Download and install MongoDB Community Edition from [mongodb.com](https://www.mongodb.com/try/download/community)

Start MongoDB service:
```powershell
# MongoDB should start automatically as a service
# Or manually start it:
mongod --dbpath C:\data\db
```

#### Step 2: Install Nmap
Download and install Nmap from [nmap.org](https://nmap.org/download.html)

Add Nmap to system PATH (usually `C:\Program Files (x86)\Nmap`)

#### Step 3: Clone & Setup Project
```powershell
# Navigate to project directory
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

#### Step 4: Configure Environment
```powershell
# Copy environment template
copy .env.example .env

# Edit .env file with your settings
# MONGODB_URL=mongodb://localhost:27017
# SECRET_KEY=your-secret-key-change-this-in-production-min-32-chars
```

#### Step 5: Run Application
```powershell
# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Step 6: Access Application
Open browser and navigate to:
- **Homepage**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Login**: http://localhost:8000/login
- **Dashboard**: http://localhost:8000/dashboard

### Option 2: Docker Installation (Recommended)

#### Prerequisites
- Docker Desktop for Windows
- Docker Compose

#### Steps
```powershell
# Navigate to project directory
cd C:\Users\RAKSHIT\OneDrive\Documents\MIT\MINI_PROJECT

# Build and start containers
docker-compose up --build

# Or run in detached mode
docker-compose up -d
```

#### Stop Application
```powershell
docker-compose down

# To remove volumes as well
docker-compose down -v
```

## 🔐 API Usage

### Authentication Flow

#### 1. Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "user@example.com",
  "created_at": "2024-12-03T10:30:00",
  "is_active": true,
  "scan_count": 0
}
```

#### 2. Login
```bash
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=securepassword123
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### Vulnerability Scanning

#### Network Scan
```bash
POST /api/scan/network
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "target": "127.0.0.1",
  "scan_type": "quick"
}
```

#### Cloud Scan
```bash
POST /api/scan/cloud
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "config": null
}
```

#### Full Scan (Network + Cloud)
```bash
POST /api/scan/full
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "target": "127.0.0.1",
  "scan_type": "full"
}
```

### User Management

#### Get User Info
```bash
GET /api/user/info
Authorization: Bearer {access_token}
```

#### Get Scan History
```bash
GET /api/user/history
Authorization: Bearer {access_token}
```

#### Get Scan Details
```bash
GET /api/user/scan/{scan_id}
Authorization: Bearer {access_token}
```

## 📊 Database Schema

### Users Collection
```javascript
{
  _id: ObjectId,
  email: String,
  hashed_password: String,
  created_at: DateTime,
  is_active: Boolean,
  scan_history: [
    {
      scan_id: String,
      timestamp: DateTime,
      scan_type: String,        // "network", "cloud", "full"
      summary: String,
      severity_counts: {
        CRITICAL: Number,
        HIGH: Number,
        MEDIUM: Number,
        LOW: Number
      },
      full_report_json: Object,
      status: String            // "pending", "running", "completed", "failed"
    }
  ]
}
```

## 🧪 Testing with Postman

1. Import the Postman collection: `Vulnerability_Detector_API.postman_collection.json`
2. Set the `base_url` variable to `http://localhost:8000`
3. Run the requests in order:
   - Register User
   - Login (automatically saves token)
   - Get User Info
   - Start Network Scan
   - Get Scan History
   - Get Scan Detail

## 🛠️ Development

### Running Tests
```powershell
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Code Formatting
```powershell
# Install formatters
pip install black isort

# Format code
black app/
isort app/
```

### Linting
```powershell
# Install linters
pip install flake8 mypy

# Run linters
flake8 app/
mypy app/
```

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGODB_URL` | MongoDB connection string | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Database name | `vuln_detector` |
| `SECRET_KEY` | JWT secret key | *Must be changed in production* |
| `ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiry time | `30` |

## 📈 Architecture

### Scan Workflow
```
1. User triggers scan → API endpoint
2. Scan request queued → Background task
3. Asset Discovery → Network scanner (Nmap)
4. Service Fingerprinting → Pattern matching
5. CVE Matching → Database lookup
6. CVSS Scoring → Risk calculation
7. Report Generation → JSON + Summary
8. Database Save → User scan history
9. Dashboard Update → Real-time display
```

### Security Measures
- ✅ Password hashing with bcrypt (cost factor: 12)
- ✅ JWT token-based authentication
- ✅ CORS protection
- ✅ Input validation with Pydantic
- ✅ SQL injection protection (NoSQL)
- ✅ Rate limiting ready (can be added)

## 🚨 Important Notes

### Windows Compatibility
- **Nmap**: Must be installed and in system PATH
- **MongoDB**: Can run as Windows service or manually
- **PowerShell**: Use PowerShell (not CMD) for better compatibility
- **Firewall**: May need to allow MongoDB (port 27017) and FastAPI (port 8000)

### Production Deployment
Before deploying to production:

1. **Change SECRET_KEY** to a strong random value
2. **Configure CORS** to specific origins
3. **Enable HTTPS** with reverse proxy (nginx/IIS)
4. **Set up MongoDB authentication**
5. **Configure firewall rules**
6. **Enable rate limiting**
7. **Set up monitoring** (logs, metrics)
8. **Regular CVE database updates**

## 📝 API Documentation

Once the application is running, access:
- **Interactive API Docs (Swagger)**: http://localhost:8000/docs
- **Alternative Docs (ReDoc)**: http://localhost:8000/redoc

## 🤝 Contributing

This is a MIT Mini Project. For improvements:
1. Fork the repository
2. Create feature branch
3. Make changes
4. Submit pull request

## 📜 License

MIT License - See LICENSE file for details

## 👥 Team

**MIT Mini Project - Cybersecurity: Vulnerability Detector**

- Project Report: SY_Minor_Report_Fin[1].pdf
- Institution: MIT (Maharashtra Institute of Technology)

## 🔗 Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Python-Nmap Documentation](https://pypi.org/project/python-nmap/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Scoring Guide](https://www.first.org/cvss/)

## 📞 Support

For issues or questions:
1. Check the API documentation at `/docs`
2. Review this README
3. Check MongoDB and Nmap installation
4. Verify firewall settings
5. Check application logs

## 🎯 Next Steps

After installation:
1. ✅ Register a new user account
2. ✅ Login to the dashboard
3. ✅ Run your first vulnerability scan
4. ✅ Review the scan results
5. ✅ Download detailed reports
6. ✅ Test with Postman collection

---

**Built with ❤️ for Cybersecurity**
