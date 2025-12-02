from datetime import datetime
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Build comprehensive vulnerability reports"""
    
    def __init__(self):
        self.report_version = "1.0"
    
    def build_report(
        self,
        scan_type: str,
        assets: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any],
        remediation_plan: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build comprehensive vulnerability report
        
        Args:
            scan_type: Type of scan performed
            assets: Scanned assets
            vulnerabilities: Detected vulnerabilities
            risk_assessment: Risk assessment results
            remediation_plan: Remediation recommendations
        
        Returns:
            Complete report dictionary
        """
        report = {
            'metadata': {
                'report_version': self.report_version,
                'scan_type': scan_type,
                'timestamp': datetime.utcnow().isoformat(),
                'total_assets': len(assets),
                'total_vulnerabilities': len(vulnerabilities)
            },
            'executive_summary': self._build_executive_summary(
                scan_type, assets, vulnerabilities, risk_assessment
            ),
            'risk_assessment': risk_assessment,
            'vulnerability_details': vulnerabilities,
            'affected_assets': self._build_asset_summary(assets),
            'remediation_plan': remediation_plan,
            'severity_breakdown': self._calculate_severity_breakdown(vulnerabilities),
            'compliance_impact': self._assess_compliance_impact(vulnerabilities)
        }
        
        return report
    
    def _build_executive_summary(
        self,
        scan_type: str,
        assets: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build executive summary"""
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        summary_text = f"Scan identified {len(vulnerabilities)} vulnerabilities across {len(assets)} asset(s). "
        
        if critical_count > 0:
            summary_text += f"{critical_count} critical vulnerabilities require immediate attention. "
        
        if high_count > 0:
            summary_text += f"{high_count} high-severity vulnerabilities should be addressed urgently."
        
        if len(vulnerabilities) == 0:
            summary_text = f"No vulnerabilities detected in {scan_type} scan of {len(assets)} asset(s)."
        
        return {
            'summary': summary_text,
            'risk_level': risk_assessment.get('risk_level', 'UNKNOWN'),
            'risk_score': risk_assessment.get('risk_score', 0.0),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'total_findings': len(vulnerabilities)
        }
    
    def _build_asset_summary(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build summary of affected assets"""
        asset_summaries = []
        
        for asset in assets:
            vulns = asset.get('vulnerabilities', [])
            
            summary = {
                'ip': asset.get('ip'),
                'hostname': asset.get('hostname', 'Unknown'),
                'vulnerability_count': len(vulns),
                'highest_severity': self._get_highest_severity(vulns),
                'critical_count': sum(1 for v in vulns if v.get('severity') == 'CRITICAL'),
                'high_count': sum(1 for v in vulns if v.get('severity') == 'HIGH')
            }
            
            asset_summaries.append(summary)
        
        return asset_summaries
    
    def _get_highest_severity(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get highest severity level from vulnerabilities"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
        
        for severity in severity_order:
            if any(v.get('severity') == severity for v in vulnerabilities):
                return severity
        
        return 'NONE'
    
    def _calculate_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate vulnerability counts by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return breakdown
    
    def _assess_compliance_impact(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance impact of findings"""
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        # Determine compliance status
        if critical_count > 0:
            status = 'Non-Compliant'
            risk = 'High'
            impact = 'Critical vulnerabilities present significant compliance risks'
        elif high_count > 3:
            status = 'At Risk'
            risk = 'Medium'
            impact = 'Multiple high-severity issues may affect compliance'
        elif len(vulnerabilities) > 0:
            status = 'Needs Attention'
            risk = 'Low'
            impact = 'Some vulnerabilities should be addressed for best practices'
        else:
            status = 'Compliant'
            risk = 'Low'
            impact = 'No significant compliance issues detected'
        
        return {
            'status': status,
            'risk_level': risk,
            'impact_description': impact,
            'frameworks': ['PCI-DSS', 'ISO 27001', 'NIST'],
            'recommendations': [
                'Address all critical vulnerabilities immediately',
                'Implement regular vulnerability scanning',
                'Maintain patch management procedures'
            ]
        }
    
    def build_summary(self, report: Dict[str, Any]) -> str:
        """Build text summary from report"""
        exec_sum = report.get('executive_summary', {})
        
        summary_lines = [
            "=== Vulnerability Scan Report ===",
            f"Timestamp: {report['metadata']['timestamp']}",
            f"Scan Type: {report['metadata']['scan_type']}",
            "",
            f"Risk Level: {exec_sum.get('risk_level', 'UNKNOWN')}",
            f"Risk Score: {exec_sum.get('risk_score', 0.0)}/10",
            "",
            f"Total Vulnerabilities: {exec_sum.get('total_findings', 0)}",
            f"  - Critical: {exec_sum.get('critical_findings', 0)}",
            f"  - High: {exec_sum.get('high_findings', 0)}",
            "",
            exec_sum.get('summary', 'No summary available')
        ]
        
        return "\n".join(summary_lines)
