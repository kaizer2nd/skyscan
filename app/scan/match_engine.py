import logging
import json
from typing import List, Dict, Any
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class CVEMatcher:
    """CVE matching engine for vulnerability detection"""
    
    def __init__(self):
        self.cve_database = self._load_cve_database()
    
    def _load_cve_database(self) -> List[Dict[str, Any]]:
        """Load CVE database from JSON file"""
        try:
            cve_file = Path(__file__).parent / "cve_database.json"
            with open(cve_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            return []
    
    def match_vulnerabilities(self, fingerprinted_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Match fingerprinted services against CVE database
        
        Args:
            fingerprinted_assets: List of assets with fingerprinting results
        
        Returns:
            Dictionary with matched vulnerabilities
        """
        vulnerabilities = []
        
        for asset in fingerprinted_assets:
            asset_vulns = []
            
            # Check fingerprinted services
            for service in asset.get('fingerprinted_services', []):
                fp = service.get('fingerprint', {})
                if fp.get('identified'):
                    matches = self._find_cve_matches(
                        product=fp.get('product', ''),
                        version=fp.get('version', '')
                    )
                    
                    for match in matches:
                        vuln = {
                            'cve_id': match['cve_id'],
                            'description': match['description'],
                            'severity': match['severity'],
                            'cvss_score': match['cvss_score'],
                            'affected_product': fp.get('product'),
                            'detected_version': fp.get('version'),
                            'affected_versions': match['affected_versions'],
                            'service': service.get('name'),
                            'port': service.get('port'),
                            'asset_ip': asset.get('ip')
                        }
                        asset_vulns.append(vuln)
                        vulnerabilities.append(vuln)
            
            asset['vulnerabilities'] = asset_vulns
        
        result = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'severity_counts': self._count_by_severity(vulnerabilities),
            'assets_with_vulns': [a for a in fingerprinted_assets if a.get('vulnerabilities')]
        }
        
        logger.info(f"Matched {len(vulnerabilities)} vulnerabilities across {len(result['assets_with_vulns'])} assets")
        return result
    
    def _find_cve_matches(self, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Find CVE matches for a specific product and version
        
        Args:
            product: Product name
            version: Product version
        
        Returns:
            List of matching CVEs
        """
        matches = []
        
        if not product:
            return matches
        
        product_lower = product.lower()
        
        for cve in self.cve_database:
            # Check if product matches
            affected_products = [p.lower() for p in cve.get('affected_products', [])]
            
            if any(product_lower in ap or ap in product_lower for ap in affected_products):
                # If we have version info, check version ranges
                if version and self._is_version_affected(version, cve.get('affected_versions', [])):
                    matches.append(cve)
                elif not version:
                    # Without version info, include potential match
                    matches.append(cve)
        
        return matches
    
    def _is_version_affected(self, version: str, affected_versions: List[str]) -> bool:
        """
        Check if a version is in the affected version range
        
        Args:
            version: Version to check
            affected_versions: List of affected version ranges
        
        Returns:
            True if version is affected
        """
        if not version or not affected_versions:
            return False
        
        # Simple version comparison (can be enhanced with proper version parsing)
        for affected in affected_versions:
            # Handle "to" ranges like "2.0 to 2.15.0"
            if ' to ' in affected.lower():
                parts = affected.lower().split(' to ')
                if len(parts) == 2:
                    # Simplified range check
                    if version in affected or affected.lower() in version.lower():
                        return True
            else:
                # Direct match or contains
                if version in affected or affected in version:
                    return True
        
        return False
    
    def _count_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get details for a specific CVE
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            CVE details dictionary
        """
        for cve in self.cve_database:
            if cve['cve_id'] == cve_id:
                return cve
        
        return None
