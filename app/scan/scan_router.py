from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from app.auth.auth_service import get_current_user_email
from app.database.mongodb import get_database
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
