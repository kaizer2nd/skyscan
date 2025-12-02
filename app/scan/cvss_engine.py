import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class CVSSEngine:
    """CVSS scoring and risk assessment engine"""
    
    def __init__(self):
        self.severity_thresholds = {
            'CRITICAL': (9.0, 10.0),
            'HIGH': (7.0, 8.9),
            'MEDIUM': (4.0, 6.9),
            'LOW': (0.1, 3.9),
            'NONE': (0.0, 0.0)
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall risk score based on vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        
        Returns:
            Risk assessment results
        """
        if not vulnerabilities:
            return {
                'risk_score': 0.0,
                'risk_level': 'NONE',
                'total_cvss': 0.0,
                'average_cvss': 0.0,
                'vulnerability_count': 0
            }
        
        # Calculate total and average CVSS
        total_cvss = sum(v.get('cvss_score', 0.0) for v in vulnerabilities)
        avg_cvss = total_cvss / len(vulnerabilities) if vulnerabilities else 0.0
        
        # Calculate weighted risk score
        # Higher weight for critical vulnerabilities
        weighted_score = 0.0
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss_score', 0.0)
            severity = vuln.get('severity', 'LOW')
            
            if severity == 'CRITICAL':
                weighted_score += cvss * 2.0
            elif severity == 'HIGH':
                weighted_score += cvss * 1.5
            elif severity == 'MEDIUM':
                weighted_score += cvss * 1.0
            else:
                weighted_score += cvss * 0.5
        
        # Normalize to 0-10 scale
        risk_score = min(weighted_score / len(vulnerabilities), 10.0)
        risk_level = self._get_severity_level(risk_score)
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'total_cvss': round(total_cvss, 2),
            'average_cvss': round(avg_cvss, 2),
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _get_severity_level(self, score: float) -> str:
        """Get severity level from CVSS score"""
        for severity, (min_score, max_score) in self.severity_thresholds.items():
            if min_score <= score <= max_score:
                return severity
        return 'LOW'
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities based on CVSS and exploitability
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Sorted list of vulnerabilities with priority scores
        """
        prioritized = []
        
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss_score', 0.0)
            severity = vuln.get('severity', 'LOW')
            
            # Calculate priority score (0-100)
            priority_score = cvss * 10  # Base on CVSS
            
            # Add bonus for critical/high severity
            if severity == 'CRITICAL':
                priority_score += 20
            elif severity == 'HIGH':
                priority_score += 10
            
            # Add exploitability factor (simplified)
            if cvss >= 9.0:
                exploitability = 'High'
                priority_score += 15
            elif cvss >= 7.0:
                exploitability = 'Medium'
                priority_score += 5
            else:
                exploitability = 'Low'
            
            prioritized.append({
                **vuln,
                'priority_score': min(priority_score, 100),
                'exploitability': exploitability
            })
        
        # Sort by priority score descending
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return prioritized
    
    def generate_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate remediation plan based on prioritized vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Remediation plan with recommended actions
        """
        prioritized = self.prioritize_vulnerabilities(vulnerabilities)
        
        remediation_plan = []
        
        for vuln in prioritized:
            action = {
                'cve_id': vuln.get('cve_id'),
                'priority': 'Immediate' if vuln['priority_score'] > 80 else 'High' if vuln['priority_score'] > 60 else 'Medium',
                'affected_asset': vuln.get('asset_ip'),
                'affected_service': vuln.get('service'),
                'current_version': vuln.get('detected_version'),
                'recommended_action': self._get_recommended_action(vuln),
                'estimated_effort': self._estimate_effort(vuln),
                'risk_reduction': round(vuln.get('cvss_score', 0) * 10, 1)
            }
            remediation_plan.append(action)
        
        return remediation_plan
    
    def _get_recommended_action(self, vuln: Dict[str, Any]) -> str:
        """Get recommended remediation action"""
        product = vuln.get('affected_product', 'service')
        
        actions = {
            'CRITICAL': f"Immediately patch or upgrade {product}. Consider taking offline until patched.",
            'HIGH': f"Patch {product} as soon as possible. Implement compensating controls.",
            'MEDIUM': f"Schedule patch for {product} in next maintenance window.",
            'LOW': f"Update {product} during regular patch cycle."
        }
        
        return actions.get(vuln.get('severity'), "Review and update as needed.")
    
    def _estimate_effort(self, vuln: Dict[str, Any]) -> str:
        """Estimate remediation effort"""
        severity = vuln.get('severity', 'LOW')
        
        if severity in ['CRITICAL', 'HIGH']:
            return 'Medium'  # Usually just patching
        else:
            return 'Low'
