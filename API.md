# API Documentation

## Base URL
```
http://localhost:8000
```

## Authentication

All protected endpoints require JWT authentication:
```
Authorization: Bearer <access_token>
```

---

## Endpoints

### 🔐 Authentication

#### Register User
Create a new user account.

**Endpoint:** `POST /api/auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:** `201 Created`
```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "user@example.com",
  "created_at": "2024-12-03T10:30:00.000Z",
  "is_active": true,
  "scan_count": 0
}
```

**Error Responses:**
- `400 Bad Request`: Email already registered
- `422 Unprocessable Entity`: Invalid email format

---

#### Login
Authenticate user and receive access token.

**Endpoint:** `POST /api/auth/login`

**Content-Type:** `application/x-www-form-urlencoded`

**Request Body:**
```
username=user@example.com&password=securepassword123
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzAxNjEyMDAwfQ.signature",
  "token_type": "bearer"
}
```

**Error Responses:**
- `401 Unauthorized`: Incorrect email or password

---

### 👤 User Management

#### Get User Info
Retrieve current user information.

**Endpoint:** `GET /api/user/info`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "email": "user@example.com",
  "created_at": "2024-12-03T10:30:00.000Z",
  "total_scans": 5,
  "is_active": true
}
```

---

#### Get Scan History
Retrieve all scans for current user.

**Endpoint:** `GET /api/user/history`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
[
  {
    "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2024-12-03T11:00:00.000Z",
    "scan_type": "network",
    "summary": "Scan completed. Found 3 vulnerabilities.",
    "severity_counts": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 1,
      "LOW": 0
    },
    "status": "completed"
  }
]
```

---

#### Get Scan Detail
Retrieve detailed results for a specific scan.

**Endpoint:** `GET /api/user/scan/{scan_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Path Parameters:**
- `scan_id` (string): The scan identifier

**Response:** `200 OK`
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2024-12-03T11:00:00.000Z",
  "scan_type": "network",
  "summary": "=== Vulnerability Scan Report ===...",
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0
  },
  "full_report_json": {
    "metadata": {...},
    "executive_summary": {...},
    "vulnerability_details": [...],
    "remediation_plan": [...]
  },
  "status": "completed"
}
```

**Error Responses:**
- `404 Not Found`: Scan not found

---

### 🔍 Vulnerability Scanning

#### Network Scan
Perform network infrastructure vulnerability scan.

**Endpoint:** `POST /api/scan/network`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "target": "127.0.0.1",
  "scan_type": "quick"
}
```

**Parameters:**
- `target` (string, optional): IP address or hostname. Default: "127.0.0.1"
- `scan_type` (string, optional): "quick" or "full". Default: "quick"

**Response:** `200 OK`
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "started",
  "message": "Network scan initiated for target 127.0.0.1"
}
```

**Notes:**
- Scan runs in background
- Check status via `/api/user/history` endpoint
- Typical completion time: 10-60 seconds

---

#### Cloud Scan
Perform cloud configuration vulnerability scan.

**Endpoint:** `POST /api/scan/cloud`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "config": null
}
```

**Parameters:**
- `config` (object, optional): Cloud configuration. Use `null` for demo mode.

**Response:** `200 OK`
```json
{
  "scan_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "status": "started",
  "message": "Cloud vulnerability scan initiated"
}
```

---

#### Full Scan
Perform comprehensive scan (network + cloud).

**Endpoint:** `POST /api/scan/full`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "target": "127.0.0.1",
  "scan_type": "full"
}
```

**Response:** `200 OK`
```json
{
  "scan_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "status": "started",
  "message": "Full vulnerability scan initiated"
}
```

**Notes:**
- Combines network and cloud scanning
- Longer completion time: 60-180 seconds
- Comprehensive vulnerability assessment

---

### 🏥 System

#### Health Check
Check application health status.

**Endpoint:** `GET /api/health`

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "app": "Vulnerability Detector",
  "version": "1.0.0"
}
```

---

## Response Models

### Scan Report Structure

```json
{
  "metadata": {
    "report_version": "1.0",
    "scan_type": "network",
    "timestamp": "2024-12-03T11:00:00.000Z",
    "total_assets": 1,
    "total_vulnerabilities": 3
  },
  "executive_summary": {
    "summary": "Scan identified 3 vulnerabilities...",
    "risk_level": "HIGH",
    "risk_score": 7.5,
    "critical_findings": 1,
    "high_findings": 1,
    "total_findings": 3
  },
  "vulnerability_details": [
    {
      "cve_id": "CVE-2021-44228",
      "description": "Apache Log4j2 Remote Code Execution",
      "severity": "CRITICAL",
      "cvss_score": 10.0,
      "affected_product": "Apache Log4j",
      "detected_version": "2.14.1",
      "service": "http",
      "port": 8080,
      "asset_ip": "127.0.0.1",
      "priority_score": 100,
      "exploitability": "High"
    }
  ],
  "remediation_plan": [
    {
      "cve_id": "CVE-2021-44228",
      "priority": "Immediate",
      "affected_asset": "127.0.0.1",
      "affected_service": "http",
      "current_version": "2.14.1",
      "recommended_action": "Immediately patch or upgrade Apache Log4j...",
      "estimated_effort": "Medium",
      "risk_reduction": 100.0
    }
  ],
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0
  },
  "compliance_impact": {
    "status": "Non-Compliant",
    "risk_level": "High",
    "impact_description": "Critical vulnerabilities present...",
    "frameworks": ["PCI-DSS", "ISO 27001", "NIST"]
  }
}
```

---

## Error Responses

### Standard Error Format
```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created (registration) |
| 400 | Bad Request | Invalid input, duplicate email |
| 401 | Unauthorized | Invalid token, wrong credentials |
| 404 | Not Found | Scan ID not found |
| 422 | Unprocessable Entity | Validation error |
| 500 | Internal Server Error | Server error |

---

## Rate Limiting

Currently no rate limiting is enforced. For production:
- Implement rate limiting per user
- Suggested: 100 requests/hour for scans
- 1000 requests/hour for other endpoints

---

## Pagination

Scan history is not paginated by default. All scans returned.

For large datasets, consider:
- Adding `?limit=10&offset=0` parameters
- Server-side pagination
- Cursor-based pagination

---

## Webhooks

Webhooks not currently supported. Possible future enhancements:
- Scan completion notifications
- High severity vulnerability alerts
- Report ready notifications

---

## SDK/Client Libraries

No official SDKs yet. Use standard HTTP clients:
- **Python**: `requests`, `httpx`
- **JavaScript**: `fetch`, `axios`
- **C#**: `HttpClient`
- **Java**: `OkHttp`, `RestTemplate`

---

## Interactive Documentation

For interactive API testing:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

Both provide:
- Live API testing
- Request/response examples
- Schema validation
- Authentication testing

---

## Versioning

Current version: `v1.0.0`

API versioning strategy:
- Breaking changes: Major version increment
- New features: Minor version increment
- Bug fixes: Patch version increment

Future versions may use URL versioning:
- `/api/v1/scan/network`
- `/api/v2/scan/network`

---

## Support

For API issues:
1. Check this documentation
2. Review interactive docs at `/docs`
3. Check application logs
4. Verify authentication token
5. Ensure MongoDB is running

---

**Last Updated**: December 3, 2024
