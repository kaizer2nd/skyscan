import logging
from typing import Dict, Any, List
import json
import asyncio

logger = logging.getLogger(__name__)


class CloudScanner:
    """Cloud infrastructure vulnerability scanner"""
    
    def __init__(self):
        self.metadata_endpoints = {
            'aws': 'http://169.254.169.254/latest/meta-data/',
            'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'gcp': 'http://metadata.google.internal/computeMetadata/v1/'
        }
    
    async def scan_cloud_config(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan cloud configuration for vulnerabilities
        
        Args:
            config: Cloud configuration dictionary (simulated for demo)
        
        Returns:
            Scan results with findings
        """
        findings = []
        
        # Simulated cloud configuration if none provided
        if not config:
            config = self._get_demo_config()
        
        # Check for common misconfigurations
        findings.extend(self._check_storage_permissions(config.get('storage', {})))
        findings.extend(self._check_network_exposure(config.get('network', {})))
        findings.extend(self._check_iam_policies(config.get('iam', {})))
        findings.extend(self._check_encryption(config.get('encryption', {})))
        
        result = {
            'scan_type': 'cloud',
            'total_findings': len(findings),
            'findings': findings,
            'severity_breakdown': self._calculate_severity_breakdown(findings),
            'status': 'completed'
        }
        
        logger.info(f"Cloud scan completed with {len(findings)} findings")
        return result
    
    def _get_demo_config(self) -> Dict[str, Any]:
        """Get demo cloud configuration for testing"""
        return {
            'storage': {
                'buckets': [
                    {'name': 'public-data', 'public_access': True, 'encryption': False},
                    {'name': 'private-data', 'public_access': False, 'encryption': True}
                ]
            },
            'network': {
                'security_groups': [
                    {
                        'name': 'web-sg',
                        'inbound_rules': [
                            {'port': 22, 'source': '0.0.0.0/0'},
                            {'port': 80, 'source': '0.0.0.0/0'},
                            {'port': 443, 'source': '0.0.0.0/0'}
                        ]
                    }
                ]
            },
            'iam': {
                'users': [
                    {'name': 'admin', 'mfa_enabled': False, 'permissions': ['*:*:*']},
                    {'name': 'developer', 'mfa_enabled': True, 'permissions': ['s3:*']}
                ]
            },
            'encryption': {
                'ebs_volumes': [
                    {'id': 'vol-001', 'encrypted': False},
                    {'id': 'vol-002', 'encrypted': True}
                ]
            }
        }
    
    def _check_storage_permissions(self, storage: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check storage bucket permissions"""
        findings = []
        
        for bucket in storage.get('buckets', []):
            if bucket.get('public_access'):
                findings.append({
                    'type': 'Storage Misconfiguration',
                    'severity': 'HIGH',
                    'resource': bucket['name'],
                    'description': f"Bucket '{bucket['name']}' allows public access",
                    'recommendation': 'Restrict public access unless explicitly required'
                })
            
            if not bucket.get('encryption'):
                findings.append({
                    'type': 'Missing Encryption',
                    'severity': 'MEDIUM',
                    'resource': bucket['name'],
                    'description': f"Bucket '{bucket['name']}' is not encrypted",
                    'recommendation': 'Enable server-side encryption'
                })
        
        return findings
    
    def _check_network_exposure(self, network: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check network security group configurations"""
        findings = []
        
        for sg in network.get('security_groups', []):
            for rule in sg.get('inbound_rules', []):
                if rule.get('source') == '0.0.0.0/0' and rule.get('port') == 22:
                    findings.append({
                        'type': 'Network Exposure',
                        'severity': 'CRITICAL',
                        'resource': sg['name'],
                        'description': f"SSH (port 22) is exposed to the internet in '{sg['name']}'",
                        'recommendation': 'Restrict SSH access to specific IP ranges'
                    })
        
        return findings
    
    def _check_iam_policies(self, iam: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check IAM user configurations"""
        findings = []
        
        for user in iam.get('users', []):
            if not user.get('mfa_enabled'):
                findings.append({
                    'type': 'IAM Security',
                    'severity': 'HIGH',
                    'resource': user['name'],
                    'description': f"User '{user['name']}' does not have MFA enabled",
                    'recommendation': 'Enable multi-factor authentication'
                })
            
            # Check for overly permissive policies
            if '*:*:*' in user.get('permissions', []):
                findings.append({
                    'type': 'IAM Security',
                    'severity': 'CRITICAL',
                    'resource': user['name'],
                    'description': f"User '{user['name']}' has overly permissive wildcard permissions",
                    'recommendation': 'Apply principle of least privilege'
                })
        
        return findings
    
    def _check_encryption(self, encryption: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check encryption settings"""
        findings = []
        
        for volume in encryption.get('ebs_volumes', []):
            if not volume.get('encrypted'):
                findings.append({
                    'type': 'Missing Encryption',
                    'severity': 'HIGH',
                    'resource': volume['id'],
                    'description': f"EBS volume '{volume['id']}' is not encrypted",
                    'recommendation': 'Enable encryption for data at rest'
                })
        
        return findings
    
    def _calculate_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return breakdown
