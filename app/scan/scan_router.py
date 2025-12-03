from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from app.auth.auth_service import get_current_user_email
from app.database.mongodb import get_database
from app.scan.vulnerability_scanner import VulnerabilityScanner
from app.scan.network_scanner import NetworkScanner
from app.scan.cloud_scanner import CloudScanner
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
    lines.append("CLOUD VULNERABILITY SCAN REPORT")
    lines.append(f"Target: {scan_results.get('target', 'Unknown')}")
    lines.append(f"IP Address: {scan_results.get('ip', 'Unknown')}")
    lines.append(f"Scan Time: {scan_results.get('timestamp', 'Unknown')}")
    lines.append("=" * 70)
    lines.append("")
    
    checks = scan_results.get('checks', {})
    
    # [1] Port Scan Results
    lines.append("[1] PORT SCAN RESULTS")
    lines.append("-" * 70)
    port_scan = checks.get('port_scan', {})
    for port_info in port_scan.get('ports', []):
        status = port_info['status'].upper()
        lines.append(f"    Port {port_info['port']} ({port_info['service']}): {status}")
    lines.append(f"    Summary: {port_scan.get('open_count', 0)} open, "
                f"{port_scan.get('closed_count', 0)} closed, "
                f"{port_scan.get('filtered_count', 0)} filtered")
    lines.append("")
    
    # [2] Header Security Analysis
    lines.append("[2] HEADER SECURITY ANALYSIS")
    lines.append("-" * 70)
    headers = checks.get('header_security', {})
    if headers.get('error'):
        lines.append(f"    Error: {headers['error']}")
    else:
        if headers.get('missing_headers'):
            lines.append("    Missing Headers:")
            for h in headers['missing_headers']:
                lines.append(f"        - {h['header']} ({h['description']})")
        if headers.get('risky_headers'):
            lines.append("    Risky Headers:")
            for h in headers['risky_headers']:
                lines.append(f"        - {h['header']}: {h['issue']}")
                lines.append(f"          Value: {h['value']}")
        lines.append(f"    Status: {headers.get('status', 'Unknown')}")
    lines.append("")
    
    # [3] SSL/TLS Certificate
    lines.append("[3] SSL/TLS CERTIFICATE")
    lines.append("-" * 70)
    ssl = checks.get('ssl_certificate', {})
    if ssl.get('is_https'):
        lines.append(f"    Status: {ssl.get('status', 'Unknown')}")
        lines.append(f"    Rating: {ssl.get('rating', 'Unknown')}")
        if ssl.get('days_until_expiry') is not None:
            lines.append(f"    Expires In: {ssl['days_until_expiry']} days")
        if ssl.get('error'):
            lines.append(f"    Error: {ssl['error']}")
    else:
        lines.append(f"    {ssl.get('message', 'Not an HTTPS URL')}")
    lines.append("")
    
    # [4] Directory Discovery
    lines.append("[4] DIRECTORY DISCOVERY")
    lines.append("-" * 70)
    directories = checks.get('directory_discovery', {})
    for endpoint in directories.get('endpoints', []):
        status = "Found" if endpoint.get('found') else "Not Found"
        code = endpoint.get('status_code', 0)
        lines.append(f"    {endpoint['path']} → {code} {status}")
    lines.append(f"    Summary: {directories.get('found_count', 0)} found, "
                f"{directories.get('not_found_count', 0)} not found")
    lines.append("")
    
    # [5] Exposed Files
    lines.append("[5] EXPOSED SENSITIVE FILES")
    lines.append("-" * 70)
    files = checks.get('exposed_files', {})
    for file_info in files.get('files', []):
        status = "⚠️ EXPOSED" if file_info.get('exposed') else "✓ SAFE"
        lines.append(f"    {file_info['filename']} → {status}")
    if files.get('exposed_count', 0) > 0:
        lines.append(f"    ⚠️ WARNING: {files['exposed_count']} sensitive file(s) exposed!")
    else:
        lines.append("    ✓ No sensitive files exposed")
    lines.append("")
    
    # [6] SQL Injection Test
    lines.append("[6] SQL INJECTION TEST")
    lines.append("-" * 70)
    sql = checks.get('sql_injection', {})
    lines.append(f"    Vulnerable: {'Yes' if sql.get('vulnerable') else 'No'}")
    lines.append(f"    Risk Level: {sql.get('risk_level', 'Unknown')}")
    lines.append(f"    {sql.get('message', 'No results')}")
    lines.append("")
    
    # Overall Severity Score
    lines.append("=" * 70)
    lines.append("OVERALL SEVERITY SCORE")
    lines.append("=" * 70)
    severity_score = scan_results.get('severity_score', 0)
    risk_level = scan_results.get('risk_level', 'Unknown')
    lines.append(f"    Score: {severity_score}/100")
    lines.append(f"    Risk Level: {risk_level}")
    lines.append("")
    
    if severity_score >= 70:
        lines.append("    ⚠️ HIGH RISK - Immediate action required!")
    elif severity_score >= 40:
        lines.append("    ⚠️ MEDIUM RISK - Address vulnerabilities soon")
    else:
        lines.append("    ✓ LOW RISK - Maintain current security posture")
    
    lines.append("=" * 70)
    
    full_text = "\n".join(lines)
    
    # Create summary
    summary = (f"Vulnerability scan completed for {scan_results.get('target')}. "
               f"Risk Level: {risk_level} ({severity_score}/100). "
               f"{port_scan.get('open_count', 0)} ports open, "
               f"{len(headers.get('missing_headers', []))} security headers missing, "
               f"{files.get('exposed_count', 0)} sensitive files exposed.")
    
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
        
        summary = report_builder.build_summary(report)
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'network',
            'summary': summary,
            'severity_counts': match_results['severity_counts'],
            'full_report_json': report,
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
                'summary': f"Scan failed: {str(e)}",
                'severity_counts': {},
                'full_report_json': {},
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
                'cvss_score': self._severity_to_cvss(finding['severity']),
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
        
        summary = report_builder.build_summary(report)
        
        # Save to database
        scan_record = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow(),
            'scan_type': 'cloud',
            'summary': summary,
            'severity_counts': scan_results.get('severity_breakdown', {}),
            'full_report_json': report,
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
                'summary': f"Scan failed: {str(e)}",
                'severity_counts': {},
                'full_report_json': {},
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
        
        summary = report_builder.build_summary(report)
        
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
            'summary': summary,
            'severity_counts': severity_counts,
            'full_report_json': report,
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
                'summary': f"Scan failed: {str(e)}",
                'severity_counts': {},
                'full_report_json': {},
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
