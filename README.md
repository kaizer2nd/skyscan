# SkyScan - Professional Vulnerability Detection Platform

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Latest-brightgreen.svg)](https://www.mongodb.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Deployed on Railway](https://img.shields.io/badge/Deployed-Railway-blueviolet.svg)](https://railway.app/)

A professional-grade vulnerability detection and security assessment platform for network infrastructure and cloud environments. Features advanced scanning capabilities, compliance mapping, and comprehensive vulnerability reporting.

🔗 **Live Demo**: [SkyScan on Railway](https://skyscan-production.up.railway.app/)

## 🌟 Key Features

### Advanced Scanning Capabilities
- ✅ **Professional Network Scanning** - Multi-technique Nmap scanning with service detection, OS fingerprinting, and version analysis
- ✅ **Cloud Security Assessment** - Comprehensive checks for AWS/Azure/GCP with compliance framework mapping (CIS, NIST, PCI-DSS, HIPAA, SOC2)
- ✅ **Real-time Vulnerability Detection** - Automated CVE correlation based on service versions with risk scoring
- ✅ **CVSS v3 Scoring** - Professional risk assessment and vulnerability prioritization
- ✅ **Compliance Reporting** - Automated compliance status for multiple frameworks
- ✅ **Detailed Remediation Plans** - Step-by-step guidance with prioritized recommendations

### User Experience
- ✅ **Modern UI** - Starry animated background with professional dashboard
- ✅ **Real-time Updates** - Live scan progress tracking and history
- ✅ **Secure Authentication** - JWT-based auth with bcrypt password hashing
- ✅ **Responsive Design** - Works seamlessly on desktop and mobile

### Technical Stack
- **Backend**: Python 3.13, FastAPI, Uvicorn (async)
- **Database**: MongoDB with Motor (async driver)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla), Bootstrap 5
- **Security**: JWT tokens, bcrypt hashing, input validation with Pydantic
- **Deployment**: Docker, Railway (production)

## 📁 Project Structure

```
skyscan/
├── app/                          # Backend application
│   ├── auth/                     # Authentication (JWT, bcrypt)
│   ├── users/                    # User management & scan history
│   ├── scan/                     # Scanning engine (Nmap, CVE matching, CVSS)
│   ├── reports/                  # Report generation
│   ├── database/                 # MongoDB async connection
│   ├── config.py                 # Environment configuration
│   └── main.py                   # FastAPI application entry
│
├── frontend/                     # Web interface
│   ├── index.html                # Landing page
│   ├── dashboard.html            # Security dashboard
│   ├── login.html / register.html
│   └── static/                   # CSS, JS assets
│
├── Dockerfile                    # Production Docker image
├── docker-compose.yml            # Local development
├── requirements.txt              # Python dependencies
├── API.md                        # API documentation
└── .env.example                  # Environment template
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.13+** installed
- **MongoDB** (via Railway for production, or local for development)
- **Nmap** installed (for network scanning)
- **Git** for version control

### Local Development Setup

#### 1. Install Nmap
Download and install Nmap from [nmap.org](https://nmap.org/download.html)

Add Nmap to system PATH (usually `C:\Program Files (x86)\Nmap`)

#### 2. Clone Repository
```powershell
git clone https://github.com/kaizer2nd/skyscan.git
cd skyscan
```

#### 3. Create Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

#### 5. Configure Environment
Create `.env` file from template:
```powershell
cp .env.example .env
```

Edit `.env` with your MongoDB connection string:
```env
MONGODB_URL=mongodb://localhost:27017/skyscan
SECRET_KEY=your-secret-key-here
```

#### 6. Run Application
```powershell
python run.py
```

Visit `http://localhost:8000` to access SkyScan.

### Production Deployment (Railway)

SkyScan is deployed on [Railway](https://railway.app) at [skyscan-production.up.railway.app](https://skyscan-production.up.railway.app)

#### Deploy Your Own Instance

1. **Fork Repository**
```powershell
# Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/skyscan.git
```

2. **Create Railway Project**
- Visit [railway.app](https://railway.app)
- Click "New Project" → "Deploy from GitHub"
- Select your forked repository

3. **Add MongoDB Service**
- In Railway project, click "New" → "Database" → "Add MongoDB"
- Copy the connection string from MongoDB service variables

4. **Configure Environment Variables**
Set these variables in Railway:
```
MONGODB_URL=<your-railway-mongodb-connection-string>
SECRET_KEY=<generate-secure-random-key>
PORT=8000
```

5. **Deploy**
- Railway auto-deploys on push to main branch
- Build uses `Dockerfile` (installs nmap automatically)
- Application starts with `run.py`

### Docker Setup (Alternative)

```powershell
# Build image
docker build -t skyscan .

# Run container
docker run -p 8000:8000 -e MONGODB_URL="your-connection-string" skyscan
```

Or use Docker Compose:
```powershell
docker-compose up --build
```

## 📖 Usage

### 1. Register Account
- Visit `/register` or click "Register" on homepage
- Create account with email and secure password
- Login redirects to dashboard automatically

### 2. Network Scanning
Scan network infrastructure for vulnerabilities:

```bash
POST /api/scan/network
{
  "targets": "192.168.1.0/24",  # Single IP, range, or CIDR
  "scan_type": "quick"           # 'quick' or 'comprehensive'
}
```

**Features:**
- **Asset Discovery**: Detects live hosts with OS fingerprinting
- **Port Analysis**: Scans 22+ common ports (SSH, HTTP, HTTPS, FTP, MySQL, RDP, SMB, etc.)
- **Service Detection**: Identifies running services with version information
- **CVE Matching**: Automatically correlates known vulnerabilities with detected services
- **Risk Scoring**: CVSS v3-based risk assessment for each finding
- **Compliance Mapping**: Maps vulnerabilities to CIS, NIST, PCI-DSS, HIPAA, SOC2 frameworks

### 3. Cloud Security Scanning
Assess cloud infrastructure security posture:

```bash
POST /api/scan/cloud
{
  "provider": "aws",             # 'aws', 'azure', or 'gcp'
  "credentials": {...},          # Cloud provider credentials
  "region": "us-east-1"
}
```

**Checks:**
- **Storage Security**: Public buckets, versioning, encryption at rest
- **Network Exposure**: SSH, RDP, database ports open to 0.0.0.0/0
- **IAM Security**: MFA enforcement, inactive users, overprivileged service accounts
- **Encryption**: Unencrypted EBS volumes, KMS key rotation
- **Logging**: CloudTrail, VPC Flow Logs, S3 access logging
- **Password Policies**: Strength requirements, rotation, expiration
- **Compliance Assessment**: Automated compliance framework alignment
- **Risk Scoring**: Weighted risk score (0-100) based on findings

### 4. View Reports
- Access scan history from dashboard
- Download detailed PDF/JSON reports
- Review compliance status across frameworks
- Track remediation progress

### 5. API Documentation
Interactive API docs available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

Key endpoints:
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Get JWT token
- `GET /api/users/me` - Get user profile
- `POST /api/scan/network` - Initiate network scan
- `POST /api/scan/cloud` - Initiate cloud scan
- `GET /api/users/me/scans` - Retrieve scan history

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

## 🛠️ Development

### Running Tests
```powershell
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest

# Or run the scanner test script
python test_scanner.py
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

### Testing with Postman
1. Import `Vulnerability_Detector_API.postman_collection.json`
2. Set `base_url` variable to `http://localhost:8000`
3. Run requests in order: Register → Login → Scan → View History

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MONGODB_URL` | MongoDB connection string | `mongodb://localhost:27017/skyscan` | ✅ |
| `SECRET_KEY` | JWT secret key (min 32 chars) | *Random generated* | ✅ |
| `DATABASE_NAME` | Database name | `skyscan` | ❌ |
| `ALGORITHM` | JWT signing algorithm | `HS256` | ❌ |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT token expiration | `30` | ❌ |
| `PORT` | Application port | `8000` | ❌ |

### Security Best Practices
- **Never commit `.env`** to version control
- **Use strong SECRET_KEY**: Generate with `openssl rand -hex 32`
- **Production MongoDB**: Use authenticated connection strings with TLS

## 📈 Architecture

**SkyScan** uses a modern, scalable architecture:

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│  Frontend   │─────▶│   FastAPI    │─────▶│  MongoDB    │
│  (HTML/JS)  │      │   Backend    │      │  (Railway)  │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │    Nmap      │
                     │   Scanner    │
                     └──────────────┘
```

**Technology Stack:**
- **Backend**: FastAPI 0.115 (async Python 3.13)
- **Authentication**: JWT with bcrypt password hashing
- **Database**: MongoDB with Motor (async driver)
- **Scanning Engine**: Nmap with subprocess integration
- **Deployment**: Docker + Railway PaaS
- **Frontend**: Vanilla JavaScript with modern CSS

## 🚨 Platform Notes

### Windows
- **Nmap**: Must be installed and in system PATH
- **MongoDB**: Can run as Windows service or manually
- **PowerShell**: Use PowerShell (not CMD) for better compatibility

### Production Checklist
1. Change SECRET_KEY to a strong random value
2. Configure CORS to specific origins
3. Enable HTTPS with reverse proxy
4. Set up MongoDB authentication
5. Enable rate limiting
6. Set up monitoring (logs, metrics)

## 🔗 Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Python-Nmap Documentation](https://pypi.org/project/python-nmap/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Scoring Guide](https://www.first.org/cvss/)

## 🤝 Contributing

Contributions welcome! Please follow these guidelines:

1. Fork repository and create feature branch
2. Follow code style: Use Black formatter and isort
3. Add tests for new features
4. Update documentation for API changes
5. Submit pull request with clear description

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## 📞 Support

- **Live Demo**: [skyscan-production.up.railway.app](https://skyscan-production.up.railway.app)
- **GitHub Issues**: [github.com/kaizer2nd/skyscan/issues](https://github.com/kaizer2nd/skyscan/issues)
- **API Docs**: See `/docs` endpoint on running instance

---

**Built with ❤️ for cybersecurity professionals**
