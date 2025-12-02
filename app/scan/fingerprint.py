import logging
from typing import List, Dict, Any
import re

logger = logging.getLogger(__name__)


class Fingerprinting:
    """Service and application fingerprinting"""
    
    def __init__(self):
        self.service_signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict[str, Any]:
        """Load service fingerprinting signatures"""
        return {
            'web_servers': {
                'apache': {
                    'patterns': [r'Apache/(\d+\.\d+\.\d+)', r'Apache HTTP Server'],
                    'ports': [80, 443, 8080],
                    'headers': ['Server: Apache']
                },
                'nginx': {
                    'patterns': [r'nginx/(\d+\.\d+\.\d+)', r'nginx'],
                    'ports': [80, 443, 8080],
                    'headers': ['Server: nginx']
                },
                'iis': {
                    'patterns': [r'Microsoft-IIS/(\d+\.\d+)', r'IIS'],
                    'ports': [80, 443],
                    'headers': ['Server: Microsoft-IIS']
                }
            },
            'databases': {
                'mysql': {
                    'patterns': [r'MySQL (\d+\.\d+\.\d+)', r'mysql'],
                    'ports': [3306]
                },
                'postgresql': {
                    'patterns': [r'PostgreSQL (\d+\.\d+)', r'postgres'],
                    'ports': [5432]
                },
                'mongodb': {
                    'patterns': [r'MongoDB (\d+\.\d+\.\d+)', r'mongodb'],
                    'ports': [27017]
                }
            },
            'ssh': {
                'openssh': {
                    'patterns': [r'OpenSSH[_\s](\d+\.\d+)'],
                    'ports': [22]
                }
            }
        }
    
    def fingerprint_service(self, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fingerprint a service based on available information
        
        Args:
            service_info: Dictionary with service details (name, version, product, etc.)
        
        Returns:
            Fingerprinting result with identified software and versions
        """
        result = {
            'service': service_info.get('name', 'unknown'),
            'identified': False,
            'product': None,
            'version': None,
            'confidence': 0.0,
            'cpe': None
        }
        
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        port = service_info.get('port', 0)
        
        # Direct match from service info
        if product and version:
            result['identified'] = True
            result['product'] = product
            result['version'] = version
            result['confidence'] = 0.9
            result['cpe'] = self._generate_cpe(product, version)
            return result
        
        # Pattern matching
        service_name = service_info.get('name', '').lower()
        banner = service_info.get('banner', '')
        
        for category, services in self.service_signatures.items():
            for service, signature in services.items():
                # Check port match
                if port in signature.get('ports', []):
                    result['confidence'] += 0.3
                
                # Check pattern match
                for pattern in signature.get('patterns', []):
                    match = re.search(pattern, banner or product or '', re.IGNORECASE)
                    if match:
                        result['identified'] = True
                        result['product'] = service
                        result['confidence'] = min(result['confidence'] + 0.5, 1.0)
                        
                        # Extract version if available
                        if match.groups():
                            result['version'] = match.group(1)
                        elif version:
                            result['version'] = version
                        
                        result['cpe'] = self._generate_cpe(service, result['version'])
                        return result
        
        return result
    
    def fingerprint_os(self, nmap_os_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fingerprint operating system
        
        Args:
            nmap_os_info: OS information from nmap scan
        
        Returns:
            OS fingerprinting result
        """
        result = {
            'os_family': 'Unknown',
            'os_version': None,
            'accuracy': 0,
            'cpe': None
        }
        
        if not nmap_os_info:
            return result
        
        # Parse nmap OS detection results
        os_matches = nmap_os_info.get('osmatch', [])
        if os_matches:
            best_match = os_matches[0]
            result['os_family'] = best_match.get('name', 'Unknown')
            result['accuracy'] = int(best_match.get('accuracy', 0))
            
            # Try to extract version
            name = result['os_family']
            version_match = re.search(r'(\d+\.?\d*)', name)
            if version_match:
                result['os_version'] = version_match.group(1)
            
            # Get CPE if available
            os_classes = best_match.get('osclass', [])
            if os_classes:
                result['cpe'] = os_classes[0].get('cpe', [None])[0]
        
        return result
    
    def _generate_cpe(self, product: str, version: str = None) -> str:
        """
        Generate CPE string for product
        
        Args:
            product: Product name
            version: Product version
        
        Returns:
            CPE string
        """
        # Simplified CPE generation
        vendor = product.lower().replace(' ', '_')
        product_name = product.lower().replace(' ', '_')
        ver = version if version else '*'
        
        return f"cpe:2.3:a:{vendor}:{product_name}:{ver}:*:*:*:*:*:*:*"
    
    def batch_fingerprint(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fingerprint multiple assets
        
        Args:
            assets: List of asset dictionaries
        
        Returns:
            List of assets with fingerprinting results
        """
        fingerprinted_assets = []
        
        for asset in assets:
            fingerprinted_services = []
            
            for service in asset.get('services', []):
                fp_result = self.fingerprint_service(service)
                fingerprinted_services.append({
                    **service,
                    'fingerprint': fp_result
                })
            
            fingerprinted_assets.append({
                **asset,
                'fingerprinted_services': fingerprinted_services
            })
        
        logger.info(f"Fingerprinted {len(fingerprinted_assets)} assets")
        return fingerprinted_assets
