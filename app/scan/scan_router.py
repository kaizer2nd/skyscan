from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from app.auth.auth_service import get_current_user_email
from app.database.mongodb import get_database
from app.scan.vulnerability_scanner import VulnerabilityScanner
from app.scan.network_scanner import NetworkScanner
from app.scan.cloud_scanner import CloudScanner
from app.scan.fingerprint import Fingerprinting
from app.scan.match_engine import CVEMatcher
from app.scan.cvss_engine import CVSSEngine
from app.reports.report_builder import ReportBuilder
import logging
import uuid

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["Vulnerability Scanning"])


class VulnerabilityScanRequest(BaseModel):
    """Industry-standard vulnerability scan request"""
    target: str  # URL or IP address


class NetworkScanRequest(BaseModel):
    """Network scan request"""
    target: Optional[str] = "127.0.0.1"
    scan_type: Optional[str] = "quick"  # "quick" or "full"


class CloudScanRequest(BaseModel):
    """Cloud scan request"""
    config: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    """Scan response"""
    scan_id: str
    status: str
    message: str


@router.post("/vulnerability", response_model=ScanResponse)
async def scan_vulnerability(
    request: VulnerabilityScanRequest,
    background_tasks: BackgroundTasks,
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """
    Perform industry-standard comprehensive vulnerability scan
    - Port scanning (11 common ports)
    - HTTP header security analysis
    - SSL/TLS certificate check
    - Directory/endpoint discovery
    - Exposed sensitive files check
    - SQL injection probing
    """
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    background_tasks.add_task(
        perform_vulnerability_scan,
        scan_id=scan_id,
        target=request.target,
        user_email=current_user_email,
        db=db
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Comprehensive vulnerability scan initiated for {request.target}"
    )


@router.post("/network", response_model=ScanResponse)
async def scan_network(
    request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """
    Perform network vulnerability scan
    """
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    background_tasks.add_task(
        perform_network_scan,
        scan_id=scan_id,
        target=request.target,
        scan_type=request.scan_type,
        user_email=current_user_email,
        db=db
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Network scan initiated for target {request.target}"
    )


@router.post("/cloud", response_model=ScanResponse)
async def scan_cloud(
    request: CloudScanRequest,
    background_tasks: BackgroundTasks,
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """
    Perform cloud infrastructure vulnerability scan
    """
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    background_tasks.add_task(
        perform_cloud_scan,
        scan_id=scan_id,
        config=request.config,
        user_email=current_user_email,
        db=db
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="Cloud vulnerability scan initiated"
    )


@router.post("/full", response_model=ScanResponse)
async def scan_full(
    network_request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    current_user_email: str = Depends(get_current_user_email),
    db=Depends(get_database)
):
    """
    Perform comprehensive vulnerability scan (network + cloud)
    """
    scan_id = str(uuid.uuid4())
    
    # Start full scan in background
    background_tasks.add_task(
        perform_full_scan,
        scan_id=scan_id,
        target=network_request.target,
        user_email=current_user_email,
        db=db
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="Full vulnerability scan initiated"
    )


async def perform_vulnerability_scan(
    scan_id: str,
    target: str,
    user_email: str,
    db
):
    """Perform comprehensive vulnerability scan and save results"""
    try:
        logger.info(f"Starting vulnerability scan {scan_id} for user {user_email} on target {target}")
        
        # Initialize scanner
        scanner = VulnerabilityScanner()
        
        # Perform comprehensive scan
        scan_results = await scanner.scan(target)
        
        # Check if scan had errors
        if 'error' in scan_results:
            raise Exception(scan_results['error'])
        
        # Format the report
        formatted_report = format_vulnerability_report(scan_results)
        
        # Calculate severity counts
        severity_counts = calculate_severity_counts(scan_results)
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'vulnerability',
            'target': scan_results.get('target'),
            'summary': formatted_report['summary'],
            'severity_score': scan_results.get('severity_score', 0),
            'risk_level': scan_results.get('risk_level', 'Unknown'),
            'severity_counts': severity_counts,
            'full_report_json': scan_results,
            'formatted_report': formatted_report['full_text'],
            'status': 'completed'
        }
        
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': scan_record}}
        )
        
        logger.info(f"Vulnerability scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Vulnerability scan {scan_id} failed: {e}")
        # Save error status
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': {
                'scan_id': scan_id,
                'timestamp': datetime.utcnow(),
                'scan_type': 'vulnerability',
                'target': target,
                'summary': f"Scan failed: {str(e)}",
                'severity_score': 0,
                'risk_level': 'Unknown',
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'full_report_json': {},
                'formatted_report': '',
                'status': 'failed'
            }}}
        )


def format_vulnerability_report(scan_results: Dict[str, Any]) -> Dict[str, str]:
    """Format scan results into readable text report"""
    lines = []
    lines.append("=" * 70)
    lines.append("VULNERABILITY SCAN REPORT")
    lines.append(f"Target: {scan_results.get('target', 'Unknown')}")
    lines.append(f"IP Address: {scan_results.get('ip', 'Unknown')}")
    lines.append(f"Scan Time: {scan_results.get('timestamp', 'Unknown')}")
    lines.append("=" * 70)
    lines.append("")
    
    checks = scan_results.get('checks', {})
    
    # [1] Port Scan Results - Matching Nmap format
    lines.append("[1] PORT SCAN RESULTS")
    lines.append("-" * 70)
    port_scan = checks.get('port_scan', {})
    lines.append(f"Host: {scan_results.get('ip', 'Unknown')}")
    lines.append(f"Status: Up")
    lines.append("")
    
    if port_scan.get('open_count', 0) > 0:
        lines.append("Open Ports:")
        for port_info in port_scan.get('ports', []):
            if port_info['status'] == 'open':
                lines.append(f"  - {port_info['port']}/tcp ({port_info['service']})")
                # Add risk indicator for sensitive ports
                if port_info['port'] in [21, 22, 3306, 445]:
                    lines.append(f"    ⚠️  RISK: {port_info['service']} service exposed")
    else:
        lines.append("Open Ports: None detected")
    
    lines.append("")
    if port_scan.get('closed_count', 0) > 0 or port_scan.get('filtered_count', 0) > 0:
        lines.append("Closed/Filtered Ports:")
        for port_info in port_scan.get('ports', []):
            if port_info['status'] != 'open':
                lines.append(f"  - {port_info['port']}/tcp")
    
    lines.append("")
    lines.append(f"Summary: {port_scan.get('open_count', 0)} open, "
                f"{port_scan.get('closed_count', 0)} closed, "
                f"{port_scan.get('filtered_count', 0)} filtered")
    lines.append("")
    
    # [2] Header Security Analysis
    lines.append("[2] HTTP SECURITY HEADERS")
    lines.append("-" * 70)
    headers = checks.get('header_security', {})
    if headers.get('error'):
        lines.append(f"⚠️  ERROR: {headers['error']}")
        lines.append("    Unable to fetch HTTP headers (service may be down)")
    else:
        if headers.get('missing_headers'):
            lines.append("❌ Missing Security Headers:")
            for h in headers['missing_headers']:
                lines.append(f"    • {h['header']}")
                lines.append(f"      Impact: {h['description']}")
                lines.append(f"      Risk: Medium")
        
        if headers.get('present_headers'):
            lines.append("")
            lines.append("✓ Present Security Headers:")
            for h in headers['present_headers']:
                lines.append(f"    • {h['header']}: {h['value']}")
        
        if headers.get('risky_headers'):
            lines.append("")
            lines.append("⚠️  Risky Headers Detected:")
            for h in headers['risky_headers']:
                lines.append(f"    • {h['header']}: {h['value']}")
                lines.append(f"      Issue: {h['issue']}")
                lines.append(f"      Risk: Low-Medium")
        
        lines.append("")
        lines.append(f"Overall Status: {headers.get('status', 'Unknown')}")
    lines.append("")
    
    # [3] SSL/TLS Certificate
    lines.append("[3] SSL/TLS CERTIFICATE SECURITY")
    lines.append("-" * 70)
    ssl = checks.get('ssl_certificate', {})
    if ssl.get('is_https'):
        lines.append(f"Certificate Status: {ssl.get('status', 'Unknown')}")
        lines.append(f"Security Rating: {ssl.get('rating', 'Unknown')}")
        
        if ssl.get('days_until_expiry') is not None:
            days = ssl['days_until_expiry']
            if days < 0:
                lines.append(f"⚠️  CRITICAL: Certificate EXPIRED {abs(days)} days ago!")
                lines.append("    Risk: HIGH - Immediate renewal required")
            elif days < 30:
                lines.append(f"⚠️  WARNING: Certificate expires in {days} days")
                lines.append("    Risk: Medium - Plan renewal soon")
            else:
                lines.append(f"✓ Expires in: {days} days")
        
        if ssl.get('error'):
            lines.append(f"⚠️  SSL Error: {ssl['error']}")
            lines.append("    Risk: HIGH")
        
        if ssl.get('issuer'):
            issuer = ssl['issuer']
            lines.append(f"Issuer: {issuer.get('organizationName', issuer.get('commonName', 'Unknown'))}")
    else:
        lines.append(f"Status: {ssl.get('message', 'Not an HTTPS URL')}")
        if 'https' not in scan_results.get('target', '').lower():
            lines.append("⚠️  Risk: Medium - No HTTPS encryption")
    lines.append("")
    
    # [4] Directory Discovery
    lines.append("[4] DIRECTORY/ENDPOINT DISCOVERY")
    lines.append("-" * 70)
    directories = checks.get('directory_discovery', {})
    
    found_any = False
    for endpoint in directories.get('endpoints', []):
        if endpoint.get('found'):
            if not found_any:
                lines.append("⚠️  Accessible Endpoints Found:")
                found_any = True
            code = endpoint.get('status_code', 0)
            lines.append(f"    • {endpoint['path']} → HTTP {code}")
            if endpoint['path'] in ['/admin', '/config', '/backup']:
                lines.append(f"      Risk: HIGH - Sensitive endpoint exposed")
            else:
                lines.append(f"      Risk: Low")
    
    if not found_any:
        lines.append("✓ No sensitive endpoints discovered")
    
    lines.append("")
    lines.append(f"Summary: {directories.get('found_count', 0)} accessible, "
                f"{directories.get('not_found_count', 0)} not found")
    lines.append("")
    
    # [5] Exposed Files
    lines.append("[5] SENSITIVE FILE EXPOSURE CHECK")
    lines.append("-" * 70)
    files = checks.get('exposed_files', {})
    
    exposed_any = False
    for file_info in files.get('files', []):
        if file_info.get('exposed'):
            if not exposed_any:
                lines.append("🚨 CRITICAL: Exposed Sensitive Files Detected!")
                exposed_any = True
            lines.append(f"    • {file_info['filename']}")
            lines.append(f"      Status: ACCESSIBLE (HTTP {file_info.get('status_code', 200)})")
            lines.append(f"      Risk: CRITICAL - Immediate action required")
            lines.append("")
    
    if not exposed_any:
        lines.append("✓ No sensitive files exposed")
        lines.append("")
        lines.append("Files checked:")
        for file_info in files.get('files', []):
            lines.append(f"    • {file_info['filename']} → SAFE")
    
    if files.get('exposed_count', 0) > 0:
        lines.append("")
        lines.append(f"⚠️  ALERT: {files['exposed_count']} sensitive file(s) publicly accessible!")
    
    lines.append("")
    
    # [6] SQL Injection Test
    lines.append("[6] SQL INJECTION VULNERABILITY TEST")
    lines.append("-" * 70)
    sql = checks.get('sql_injection', {})
    lines.append(f"Test Result: {sql.get('message', 'No results')}")
    lines.append(f"Vulnerability Status: {'DETECTED' if sql.get('vulnerable') else 'Not Detected'}")
    lines.append(f"Risk Level: {sql.get('risk_level', 'Unknown')}")
    
    if sql.get('vulnerable'):
        lines.append("")
        lines.append("🚨 CRITICAL: Potential SQL Injection Vulnerability!")
        lines.append("    Detected SQL error patterns in responses")
        lines.append("    Risk: CRITICAL - Database may be exploitable")
        lines.append("    Action: Implement prepared statements immediately")
    
    lines.append("")
    
    # Overall Severity Score
    lines.append("=" * 70)
    lines.append("OVERALL RISK ASSESSMENT")
    lines.append("=" * 70)
    severity_score = scan_results.get('severity_score', 0)
    risk_level = scan_results.get('risk_level', 'Unknown')
    
    lines.append(f"Severity Score: {severity_score}/100")
    lines.append(f"Risk Level: {risk_level.upper()}")
    lines.append("")
    
    # Risk-based recommendations
    if severity_score >= 70:
        lines.append("🚨 HIGH RISK - IMMEDIATE ACTION REQUIRED!")
        lines.append("    • Critical vulnerabilities detected")
        lines.append("    • System is at significant risk of compromise")
        lines.append("    • Address issues immediately")
    elif severity_score >= 40:
        lines.append("⚠️  MEDIUM RISK - Address vulnerabilities soon")
        lines.append("    • Several security issues detected")
        lines.append("    • Plan remediation within 30 days")
        lines.append("    • Monitor for exploitation attempts")
    else:
        lines.append("✓ LOW RISK - Maintain current security posture")
        lines.append("    • No critical vulnerabilities detected")
        lines.append("    • Continue regular security monitoring")
        lines.append("    • Address minor issues when possible")
    
    lines.append("")
    
    # Count issues by severity
    counts = calculate_severity_counts(scan_results)
    if counts['CRITICAL'] > 0 or counts['HIGH'] > 0:
        lines.append("Issue Breakdown:")
        lines.append(f"    🔴 Critical: {counts['CRITICAL']}")
        lines.append(f"    🟠 High: {counts['HIGH']}")
        lines.append(f"    🟡 Medium: {counts['MEDIUM']}")
        lines.append(f"    🔵 Low: {counts['LOW']}")
    
    lines.append("=" * 70)
    
    full_text = "\n".join(lines)
    
    # Create summary
    summary = (f"Scan completed for {scan_results.get('target')}. "
               f"Risk: {risk_level.upper()} ({severity_score}/100). "
               f"{port_scan.get('open_count', 0)} ports open, "
               f"{len(headers.get('missing_headers', []))} headers missing, "
               f"{files.get('exposed_count', 0)} files exposed.")
    
    return {
        'summary': summary,
        'full_text': full_text
    }


def calculate_severity_counts(scan_results: Dict[str, Any]) -> Dict[str, int]:
    """Calculate severity counts from scan results"""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    checks = scan_results.get('checks', {})
    
    # Exposed files are CRITICAL
    exposed_files = checks.get('exposed_files', {}).get('exposed_count', 0)
    counts['CRITICAL'] += exposed_files
    
    # SQL injection vulnerability is CRITICAL
    if checks.get('sql_injection', {}).get('vulnerable'):
        counts['CRITICAL'] += 1
    
    # Open sensitive ports are HIGH
    port_scan = checks.get('port_scan', {})
    sensitive_ports = [21, 22, 25, 3306, 445]
    for port_info in port_scan.get('ports', []):
        if port_info['status'] == 'open' and port_info['port'] in sensitive_ports:
            counts['HIGH'] += 1
    
    # SSL issues
    ssl = checks.get('ssl_certificate', {})
    if ssl.get('status') == 'Expired':
        counts['HIGH'] += 1
    elif ssl.get('status') == 'Invalid':
        counts['MEDIUM'] += 1
    
    # Missing security headers are MEDIUM
    missing_headers = len(checks.get('header_security', {}).get('missing_headers', []))
    counts['MEDIUM'] += missing_headers
    
    # Found directories are LOW
    found_dirs = checks.get('directory_discovery', {}).get('found_count', 0)
    counts['LOW'] += found_dirs
    
    return counts


def format_network_scan_report(report: Dict[str, Any]) -> Dict[str, str]:
    """Format network scan results into Nmap-style readable text report"""
    lines = []
    lines.append("=" * 70)
    lines.append("NETWORK SCAN REPORT")
    lines.append(f"Scan Time: {report.get('scan_info', {}).get('start_time', 'Unknown')}")
    lines.append("=" * 70)
    lines.append("")
    
    # Asset information
    assets = report.get('assets', [])
    
    for asset in assets:
        ip = asset.get('ip', 'Unknown')
        hostname = asset.get('hostname', '')
        
        # Show hostname if available, otherwise just IP
        if hostname and hostname != 'Unknown':
            lines.append(f"Host: {hostname} ({ip})")
        else:
            lines.append(f"Host: {ip}")
        
        lines.append(f"Status: {'Up' if asset.get('state') == 'up' else 'Down'}")
        lines.append("")
        
        # Separate ports by state
        all_ports = asset.get('ports', [])
        open_ports = [p for p in all_ports if p.get('state') == 'open']
        closed_filtered_ports = [p for p in all_ports if p.get('state') in ['closed', 'filtered']]
        
        # Display open ports
        if open_ports:
            lines.append("Open Ports:")
            for port_info in open_ports:
                port_num = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                
                # Build port line
                port_line = f"  - {port_num}/{protocol} ({service}"
                if product:
                    port_line += f" - {product}"
                if version:
                    port_line += f" {version}"
                port_line += ")"
                lines.append(port_line)
                
                # Risk indicator for sensitive services
                if port_num in [21, 22, 25, 3306, 445, 3389]:
                    lines.append(f"    ⚠️  RISK: {service.upper()} service exposed - HIGH")
        else:
            lines.append("Open Ports: None detected")
        
        lines.append("")
        
        # Display closed/filtered ports
        if closed_filtered_ports:
            lines.append("Closed/Filtered Ports:")
            # Show all closed/filtered ports (not just first 10)
            for port_info in closed_filtered_ports:
                port_num = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                state = port_info.get('state', 'filtered')
                lines.append(f"  - {port_num}/{protocol} ({state})")
        
        lines.append("")
        lines.append("-" * 70)
        lines.append("")
    
    # Vulnerabilities
    vulnerabilities = report.get('vulnerabilities', [])
    if vulnerabilities:
        lines.append("DETECTED VULNERABILITIES")
        lines.append("-" * 70)
        
        for vuln in vulnerabilities[:10]:  # Show top 10
            severity = vuln.get('severity', 'UNKNOWN')
            cve_id = vuln.get('cve_id', 'N/A')
            description = vuln.get('description', 'No description')
            cvss_score = vuln.get('cvss_score', 0)
            
            # Severity emoji
            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
            
            lines.append(f"{emoji} {severity} - {cve_id}")
            lines.append(f"   CVSS Score: {cvss_score}")
            lines.append(f"   {description[:100]}...")
            lines.append(f"   Affected: {vuln.get('affected_product', 'Unknown')}")
            lines.append("")
        
        if len(vulnerabilities) > 10:
            lines.append(f"... and {len(vulnerabilities) - 10} more vulnerabilities")
            lines.append("")
    
    # Risk assessment
    risk_assessment = report.get('risk_assessment', {})
    lines.append("OVERALL RISK ASSESSMENT")
    lines.append("-" * 70)
    lines.append(f"Risk Score: {risk_assessment.get('overall_score', 0)}/100")
    lines.append(f"Risk Level: {risk_assessment.get('risk_level', 'Unknown').upper()}")
    lines.append("")
    
    # Severity breakdown
    severity_counts = report.get('severity_counts', {})
    if any(severity_counts.values()):
        lines.append("Issue Breakdown:")
        lines.append(f"    🔴 Critical: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"    🟠 High: {severity_counts.get('HIGH', 0)}")
        lines.append(f"    🟡 Medium: {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"    🔵 Low: {severity_counts.get('LOW', 0)}")
    
    lines.append("=" * 70)
    
    full_text = "\n".join(lines)
    
    # Create summary
    total_assets = len(assets)
    total_vulns = len(vulnerabilities)
    risk_level = risk_assessment.get('risk_level', 'Unknown')
    
    summary = (f"Network scan completed. {total_assets} host(s) discovered, "
               f"{total_vulns} vulnerabilities found. Risk: {risk_level.upper()}")
    
    return {
        'summary': summary,
        'full_text': full_text
    }


def format_cloud_scan_report(report: Dict[str, Any]) -> Dict[str, str]:
    """Format cloud scan results into readable text report"""
    lines = []
    lines.append("=" * 70)
    lines.append("CLOUD SECURITY SCAN REPORT")
    lines.append(f"Scan Time: {report.get('scan_info', {}).get('start_time', 'Unknown')}")
    lines.append("=" * 70)
    lines.append("")
    
    # Vulnerabilities/Findings
    vulnerabilities = report.get('vulnerabilities', [])
    if vulnerabilities:
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 70)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            description = vuln.get('description', 'No description')
            resource = vuln.get('affected_product', 'Unknown resource')
            service = vuln.get('service', 'Unknown service')
            
            # Severity emoji
            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
            
            lines.append(f"{emoji} {severity} - {service}")
            lines.append(f"   Resource: {resource}")
            lines.append(f"   Issue: {description}")
            lines.append("")
    else:
        lines.append("✓ No security findings detected")
        lines.append("")
    
    # SSL/TLS Checks
    lines.append("SSL/TLS SECURITY")
    lines.append("-" * 70)
    
    # Check if any SSL-related findings exist
    ssl_issues = [v for v in vulnerabilities if 'certificate' in v.get('description', '').lower() or 
                  'tls' in v.get('description', '').lower() or 'ssl' in v.get('description', '').lower()]
    
    if ssl_issues:
        for issue in ssl_issues:
            lines.append(f"⚠️  {issue.get('description')}")
            lines.append(f"    Risk: {issue.get('severity')}")
            lines.append("")
    else:
        lines.append("✓ No SSL/TLS issues detected")
        lines.append("")
    
    # Risk assessment
    risk_assessment = report.get('risk_assessment', {})
    lines.append("OVERALL RISK ASSESSMENT")
    lines.append("-" * 70)
    lines.append(f"Risk Score: {risk_assessment.get('overall_score', 0)}/100")
    lines.append(f"Risk Level: {risk_assessment.get('risk_level', 'Unknown').upper()}")
    lines.append("")
    
    # Severity breakdown
    severity_counts = report.get('severity_counts', {})
    if any(severity_counts.values()):
        lines.append("Issue Breakdown:")
        lines.append(f"    🔴 Critical: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"    🟠 High: {severity_counts.get('HIGH', 0)}")
        lines.append(f"    🟡 Medium: {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"    🔵 Low: {severity_counts.get('LOW', 0)}")
    
    lines.append("=" * 70)
    
    full_text = "\n".join(lines)
    
    # Create summary
    total_findings = len(vulnerabilities)
    risk_level = risk_assessment.get('risk_level', 'Unknown')
    
    summary = (f"Cloud scan completed. {total_findings} security finding(s) detected. "
               f"Risk: {risk_level.upper()}")
    
    return {
        'summary': summary,
        'full_text': full_text
    }


def format_full_scan_report(report: Dict[str, Any]) -> Dict[str, str]:
    """Format full scan (network + cloud) results into comprehensive readable text report"""
    lines = []
    lines.append("=" * 70)
    lines.append("COMPREHENSIVE SECURITY SCAN REPORT")
    lines.append("(Network + Cloud)")
    lines.append(f"Scan Time: {report.get('scan_info', {}).get('start_time', 'Unknown')}")
    lines.append("=" * 70)
    lines.append("")
    
    # Network findings
    lines.append("[NETWORK SECURITY]")
    lines.append("-" * 70)
    
    assets = report.get('assets', [])
    for asset in assets:
        ip = asset.get('ip', 'Unknown')
        hostname = asset.get('hostname', '')
        
        # Show hostname if available
        if hostname and hostname != 'Unknown':
            lines.append(f"Host: {hostname} ({ip})")
        else:
            lines.append(f"Host: {ip}")
        
        lines.append(f"Status: {'Up' if asset.get('state') == 'up' else 'Down'}")
        lines.append("")
        
        # Separate ports by state
        all_ports = asset.get('ports', [])
        open_ports = [p for p in all_ports if p.get('state') == 'open']
        closed_filtered_ports = [p for p in all_ports if p.get('state') in ['closed', 'filtered']]
        
        # Display open ports
        if open_ports:
            lines.append("Open Ports:")
            for port_info in open_ports:
                port_num = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                
                # Build port line
                port_line = f"  - {port_num}/{protocol} ({service}"
                if product:
                    port_line += f" - {product}"
                if version:
                    port_line += f" {version}"
                port_line += ")"
                lines.append(port_line)
                
                # Risk indicator
                if port_num in [21, 22, 25, 3306, 445, 3389]:
                    lines.append(f"    ⚠️  RISK: {service.upper()} exposed - HIGH")
        else:
            lines.append("Open Ports: None")
        
        lines.append("")
        
        # Display closed/filtered ports
        if closed_filtered_ports:
            lines.append("Closed/Filtered Ports:")
            for port_info in closed_filtered_ports:
                port_num = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                state = port_info.get('state', 'filtered')
                lines.append(f"  - {port_num}/{protocol} ({state})")
        
        lines.append("")
    
    # All vulnerabilities (network + cloud)
    lines.append("[DETECTED VULNERABILITIES]")
    lines.append("-" * 70)
    
    vulnerabilities = report.get('vulnerabilities', [])
    if vulnerabilities:
        # Group by severity
        critical = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        medium = [v for v in vulnerabilities if v.get('severity') == 'MEDIUM']
        low = [v for v in vulnerabilities if v.get('severity') == 'LOW']
        
        if critical:
            lines.append("🔴 CRITICAL ISSUES:")
            for vuln in critical[:5]:
                lines.append(f"   • {vuln.get('description', 'Unknown')[:80]}")
                lines.append(f"     CVE: {vuln.get('cve_id', 'N/A')} | CVSS: {vuln.get('cvss_score', 0)}")
            if len(critical) > 5:
                lines.append(f"   ... and {len(critical) - 5} more critical issues")
            lines.append("")
        
        if high:
            lines.append("🟠 HIGH SEVERITY:")
            for vuln in high[:5]:
                lines.append(f"   • {vuln.get('description', 'Unknown')[:80]}")
            if len(high) > 5:
                lines.append(f"   ... and {len(high) - 5} more high severity issues")
            lines.append("")
        
        if medium:
            lines.append(f"🟡 MEDIUM SEVERITY: {len(medium)} issue(s)")
            lines.append("")
        
        if low:
            lines.append(f"🔵 LOW SEVERITY: {len(low)} issue(s)")
            lines.append("")
    else:
        lines.append("✓ No vulnerabilities detected")
        lines.append("")
    
    # Overall risk assessment
    lines.append("[OVERALL RISK ASSESSMENT]")
    lines.append("-" * 70)
    
    risk_assessment = report.get('risk_assessment', {})
    risk_score = risk_assessment.get('overall_score', 0)
    risk_level = risk_assessment.get('risk_level', 'Unknown')
    
    lines.append(f"Risk Score: {risk_score}/100")
    lines.append(f"Risk Level: {risk_level.upper()}")
    lines.append("")
    
    # Risk recommendations
    if risk_score >= 70:
        lines.append("🚨 HIGH RISK - IMMEDIATE ACTION REQUIRED!")
        lines.append("    • Critical vulnerabilities present")
        lines.append("    • System at significant risk")
        lines.append("    • Address issues immediately")
    elif risk_score >= 40:
        lines.append("⚠️  MEDIUM RISK - Address soon")
        lines.append("    • Multiple security issues detected")
        lines.append("    • Plan remediation within 30 days")
    else:
        lines.append("✓ LOW RISK - Good security posture")
        lines.append("    • No critical issues detected")
        lines.append("    • Continue monitoring")
    
    lines.append("")
    
    # Severity breakdown
    severity_counts = report.get('severity_counts', {})
    if any(severity_counts.values()):
        lines.append("Issue Breakdown:")
        lines.append(f"    🔴 Critical: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"    🟠 High: {severity_counts.get('HIGH', 0)}")
        lines.append(f"    🟡 Medium: {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"    🔵 Low: {severity_counts.get('LOW', 0)}")
    
    lines.append("=" * 70)
    
    full_text = "\n".join(lines)
    
    # Create summary
    total_assets = len(assets)
    total_vulns = len(vulnerabilities)
    
    summary = (f"Full scan completed. {total_assets} host(s), {total_vulns} vulnerabilities. "
               f"Risk: {risk_level.upper()} ({risk_score}/100)")
    
    return {
        'summary': summary,
        'full_text': full_text
    }


async def perform_network_scan(
    scan_id: str,
    target: str,
    scan_type: str,
    user_email: str,
    db
):
    """Perform network scan and save results"""
    try:
        logger.info(f"Starting network scan {scan_id} for user {user_email}")
        
        # Initialize scanners
        network_scanner = NetworkScanner()
        fingerprinter = Fingerprinting()
        cve_matcher = CVEMatcher()
        cvss_engine = CVSSEngine()
        report_builder = ReportBuilder()
        
        # Step 1: Asset Discovery
        assets = await network_scanner.discover_assets(target)
        
        # Step 2: Fingerprinting
        fingerprinted_assets = fingerprinter.batch_fingerprint(assets)
        
        # Step 3: CVE Matching
        match_results = cve_matcher.match_vulnerabilities(fingerprinted_assets)
        vulnerabilities = match_results['vulnerabilities']
        
        # Step 4: CVSS Scoring & Risk Assessment
        risk_assessment = cvss_engine.calculate_risk_score(vulnerabilities)
        prioritized_vulns = cvss_engine.prioritize_vulnerabilities(vulnerabilities)
        remediation_plan = cvss_engine.generate_remediation_plan(vulnerabilities)
        
        # Step 5: Build Report
        report = report_builder.build_report(
            scan_type="network",
            assets=fingerprinted_assets,
            vulnerabilities=prioritized_vulns,
            risk_assessment=risk_assessment,
            remediation_plan=remediation_plan
        )
        
        # Format the report in Nmap-style
        formatted_report = format_network_scan_report(report)
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'network',
            'target': target,
            'summary': formatted_report['summary'],
            'severity_score': risk_assessment.get('overall_score', 0),
            'risk_level': risk_assessment.get('risk_level', 'Unknown'),
            'severity_counts': match_results['severity_counts'],
            'full_report_json': report,
            'formatted_report': formatted_report['full_text'],
            'status': 'completed'
        }
        
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': scan_record}}
        )
        
        logger.info(f"Network scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Network scan {scan_id} failed: {e}")
        # Save error status
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': {
                'scan_id': scan_id,
                'timestamp': datetime.utcnow(),
                'scan_type': 'network',
                'target': target,
                'summary': f"Scan failed: {str(e)}",
                'severity_score': 0,
                'risk_level': 'Unknown',
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'full_report_json': {},
                'formatted_report': '',
                'status': 'failed'
            }}}
        )


async def perform_cloud_scan(
    scan_id: str,
    config: Dict[str, Any],
    user_email: str,
    db
):
    """Perform cloud scan and save results"""
    try:
        logger.info(f"Starting cloud scan {scan_id} for user {user_email}")
        
        # Initialize scanners
        cloud_scanner = CloudScanner()
        cvss_engine = CVSSEngine()
        report_builder = ReportBuilder()
        
        # Perform cloud configuration scan
        scan_results = await cloud_scanner.scan_cloud_config(config)
        
        # Convert findings to vulnerability format
        vulnerabilities = []
        for finding in scan_results.get('findings', []):
            vuln = {
                'cve_id': 'CONFIG-ISSUE',
                'description': finding['description'],
                'severity': finding['severity'],
                'cvss_score': _severity_to_cvss(finding['severity']),
                'affected_product': finding['resource'],
                'service': finding['type'],
                'asset_ip': 'cloud-resource'
            }
            vulnerabilities.append(vuln)
        
        # Risk assessment
        risk_assessment = cvss_engine.calculate_risk_score(vulnerabilities)
        remediation_plan = cvss_engine.generate_remediation_plan(vulnerabilities)
        
        # Build report
        report = report_builder.build_report(
            scan_type="cloud",
            assets=[],
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            remediation_plan=remediation_plan
        )
        
        # Format the report
        formatted_report = format_cloud_scan_report(report)
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'cloud',
            'target': 'Cloud Infrastructure',
            'summary': formatted_report['summary'],
            'severity_score': risk_assessment.get('overall_score', 0),
            'risk_level': risk_assessment.get('risk_level', 'Unknown'),
            'severity_counts': scan_results.get('severity_breakdown', {}),
            'full_report_json': report,
            'formatted_report': formatted_report['full_text'],
            'status': 'completed'
        }
        
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': scan_record}}
        )
        
        logger.info(f"Cloud scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Cloud scan {scan_id} failed: {e}")
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': {
                'scan_id': scan_id,
                'timestamp': datetime.utcnow(),
                'scan_type': 'cloud',
                'target': 'Cloud Infrastructure',
                'summary': f"Scan failed: {str(e)}",
                'severity_score': 0,
                'risk_level': 'Unknown',
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'full_report_json': {},
                'formatted_report': '',
                'status': 'failed'
            }}}
        )


async def perform_full_scan(
    scan_id: str,
    target: str,
    user_email: str,
    db
):
    """Perform comprehensive scan (network + cloud) and save results"""
    try:
        logger.info(f"Starting full scan {scan_id} for user {user_email}")
        
        # Initialize all scanners
        network_scanner = NetworkScanner()
        cloud_scanner = CloudScanner()
        fingerprinter = Fingerprinting()
        cve_matcher = CVEMatcher()
        cvss_engine = CVSSEngine()
        report_builder = ReportBuilder()
        
        # Network scan
        assets = await network_scanner.discover_assets(target)
        fingerprinted_assets = fingerprinter.batch_fingerprint(assets)
        network_results = cve_matcher.match_vulnerabilities(fingerprinted_assets)
        network_vulns = network_results['vulnerabilities']
        
        # Cloud scan
        cloud_results = await cloud_scanner.scan_cloud_config()
        cloud_vulns = []
        for finding in cloud_results.get('findings', []):
            vuln = {
                'cve_id': 'CONFIG-ISSUE',
                'description': finding['description'],
                'severity': finding['severity'],
                'cvss_score': _severity_to_cvss(finding['severity']),
                'affected_product': finding['resource'],
                'service': finding['type'],
                'asset_ip': 'cloud-resource'
            }
            cloud_vulns.append(vuln)
        
        # Combine vulnerabilities
        all_vulnerabilities = network_vulns + cloud_vulns
        
        # Risk assessment
        risk_assessment = cvss_engine.calculate_risk_score(all_vulnerabilities)
        prioritized_vulns = cvss_engine.prioritize_vulnerabilities(all_vulnerabilities)
        remediation_plan = cvss_engine.generate_remediation_plan(all_vulnerabilities)
        
        # Build comprehensive report
        report = report_builder.build_report(
            scan_type="full",
            assets=fingerprinted_assets,
            vulnerabilities=prioritized_vulns,
            risk_assessment=risk_assessment,
            remediation_plan=remediation_plan
        )
        
        # Format the report
        formatted_report = format_full_scan_report(report)
        
        # Calculate combined severity counts
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in all_vulnerabilities:
            sev = vuln.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'full',
            'target': target,
            'summary': formatted_report['summary'],
            'severity_score': risk_assessment.get('overall_score', 0),
            'risk_level': risk_assessment.get('risk_level', 'Unknown'),
            'severity_counts': severity_counts,
            'full_report_json': report,
            'formatted_report': formatted_report['full_text'],
            'status': 'completed'
        }
        
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': scan_record}}
        )
        
        logger.info(f"Full scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Full scan {scan_id} failed: {e}")
        await db.users.update_one(
            {'email': user_email},
            {'$push': {'scan_history': {
                'scan_id': scan_id,
                'timestamp': datetime.utcnow(),
                'scan_type': 'full',
                'target': target,
                'summary': f"Scan failed: {str(e)}",
                'severity_score': 0,
                'risk_level': 'Unknown',
                'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'full_report_json': {},
                'formatted_report': '',
                'status': 'failed'
            }}}
        )


def _severity_to_cvss(severity: str) -> float:
    """Convert severity level to CVSS score"""
    mapping = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 2.5
    }
    return mapping.get(severity, 0.0)
